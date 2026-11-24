// Package keycheck tests credentials with one authenticated request to the source's host
// through egress. It has no scope and cannot contact targets.
package keycheck

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/cve"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// Status classifies the source's response to a credential test.
type Status int

// The answers a key test can give.
const (
	// Accepted: the source accepted the key.
	Accepted Status = iota
	// Rejected: the source said the key is invalid.
	Rejected
	// Unknown: the test could not tell; Result.Reason says why.
	Unknown
)

// Result is the outcome of one key test.
type Result struct {
	Status Status
	// Reason explains Unknown results in one sanitised, key-redacted line. Other statuses
	// leave it empty.
	Reason string
}

// requestTimeout exceeds caller deadlines so their context normally controls test duration.
const requestTimeout = 20 * time.Second

// maxReason is the most runes a Reason holds.
const maxReason = 200

// minEcho sets the shortest key fragment masked in reasons because sources may echo only part
// of a key.
const minEcho = 5

const mask = "****"

// source is how one source's key is tested.
type source struct {
	name, host   string
	method, path string // path with its query, without the key
	body         string // a JSON object, or ""
	// keyHeader, keyPrefix and keyParam are where egress puts the key.
	keyHeader, keyPrefix, keyParam string
	// rejects reports whether the answer says the key is invalid.
	rejects func(status int, body []byte) bool
	// ambiguous sources need response explanations because 401/403 alone does not prove an
	// invalid key.
	ambiguous bool
}

func unauthorised(status int, _ []byte) bool { return status == 401 }

// sources are the tested sources, in the order they are listed.
var sources = []source{
	{name: "securitytrails", host: "api.securitytrails.com", method: "GET", path: "/v1/ping",
		keyHeader: "APIKEY", rejects: unauthorised},
	{name: "shodan", host: "api.shodan.io", method: "GET", path: "/api-info",
		keyParam: "key", rejects: unauthorised},
	{name: "virustotal", host: "www.virustotal.com", method: "GET", path: "/api/v3/domains/example.com",
		keyHeader: "x-apikey", rejects: unauthorised},
	{name: "whoisxml", host: "user.whoisxmlapi.com", method: "GET", path: "/user-service/account-balance",
		keyParam: "apiKey", ambiguous: true},
	{name: "censys", host: "api.platform.censys.io", method: "POST", path: "/v3/global/search/query",
		body:      `{"query":"cert.names: \"example.com\"","page_size":1}`,
		keyHeader: "Authorization", keyPrefix: "Bearer ", rejects: unauthorised},
	{name: "chaos", host: "dns.projectdiscovery.io", method: "GET", path: "/dns/example.com",
		keyHeader: "Authorization", rejects: chaosRejects},
	{name: "github", host: "api.github.com", method: "GET", path: "/rate_limit",
		keyHeader: "Authorization", keyPrefix: "Bearer ", rejects: unauthorised},
	{name: "certspotter", host: "api.certspotter.com", method: "GET", path: "/v1/issuances?domain=example.com",
		keyHeader: "Authorization", keyPrefix: "Bearer ", rejects: unauthorised},
	{name: "nvd", host: cve.Host, method: "GET", path: "/rest/json/cves/2.0?cveId=CVE-2021-44228",
		keyHeader: "apiKey"}, // classified by the rules nyx cve uses
}

// chaosRejects recognises both 401 and Chaos's invalid-key 400 body.
func chaosRejects(status int, body []byte) bool {
	if status == 401 {
		return true
	}
	var b struct {
		Valid *bool `json:"valid"`
	}
	return status == 400 && json.Unmarshal(body, &b) == nil && b.Valid != nil && !*b.Valid
}

func lookup(name string) (source, bool) {
	for _, s := range sources {
		if s.name == name {
			return s, true
		}
	}
	return source{}, false
}

// Sources lists the key sources that can be tested, in the order they are listed.
func Sources() []string {
	out := make([]string, len(sources))
	for i, s := range sources {
		out[i] = s.name
	}
	return out
}

// Run builds a third-party egress client allowing only the selected source host. opts supplies
// keys, redaction and test routing; no target Policy is used.
func Run(ctx context.Context, opts egress.Options, name string, key config.Secret) Result {
	s, ok := lookup(name)
	if !ok {
		return unknown("no test for the source " + strconv.Quote(sanitize.Line(name)))
	}
	opts.Keys = map[string]config.Secret{s.name: key}
	opts.Redactor = config.NewRedactor(key.Reveal())
	return check(ctx, egress.New(opts).Clients(false, []string{s.host}).ThirdParty, s, key)
}

// check sends one source request and classifies its response. c supplies the credential and
// permits only that host. key is used only to mask echoed response text.
func check(ctx context.Context, c egress.ThirdPartyHTTP, s source, key config.Secret) Result {
	req := egress.ThirdPartyRequest{
		Method: s.method, URL: "https://" + s.host + s.path, Accept: "application/json",
		KeySource: s.name, KeyHeader: s.keyHeader, KeyParam: s.keyParam, KeyPrefix: s.keyPrefix,
		Timeout: requestTimeout,
	}
	if s.body != "" {
		req.Body, req.ContentType = []byte(s.body), "application/json"
	}
	resp, err := c.Do(ctx, req)
	if err != nil {
		if timedOut(ctx, err) {
			return unknown("timed out")
		}
		if ctx.Err() != nil {
			return unknown("cancelled")
		}
		return unknown(clean(err.Error(), key))
	}
	return classify(s, resp, key)
}

// timedOut recognises context and request deadlines, including errors egress has converted to
// text.
func timedOut(ctx context.Context, err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) ||
		strings.Contains(err.Error(), context.DeadlineExceeded.Error())
}

func unknown(reason string) Result { return Result{Status: Unknown, Reason: reason} }

// classify turns a source's answer into a result.
func classify(s source, resp egress.ThirdPartyResponse, key config.Secret) Result {
	status := resp.Status
	if status == 200 {
		return Result{Status: Accepted}
	}
	msg := message(s, resp)
	rateLimited := status == 429
	switch {
	case s.name == "nvd":
		switch cve.Meaning(status, resp.HeaderValue("message"), resp.Body) {
		case cve.KeyRefused:
			return Result{Status: Rejected}
		case cve.RateLimited:
			rateLimited = true
		case cve.Other:
		}
	case s.rejects != nil && s.rejects(status, resp.Body):
		return Result{Status: Rejected}
	case s.ambiguous && (status == 401 || status == 403):
		return unknown(describe(status, clean(msg, key), false))
	}
	switch {
	case rateLimited:
		return unknown("rate limited")
	case status == 402:
		return unknown("out of credits")
	}
	return unknown(describe(status, clean(msg, key), true))
}

// describe combines status and source message into an explanation.
func describe(status int, msg string, withStatus bool) string {
	switch {
	case msg == "":
		return "HTTP " + strconv.Itoa(status)
	case withStatus:
		return "HTTP " + strconv.Itoa(status) + ": " + msg
	}
	return msg
}

// message extracts NVD's message header or common JSON error fields. Returned text is raw and
// may be empty.
func message(s source, resp egress.ThirdPartyResponse) string {
	if s.name == "nvd" {
		if m := resp.HeaderValue("message"); m != "" {
			return m
		}
	}
	var b struct {
		Message  any `json:"message"`
		Messages any `json:"messages"`
		Error    any `json:"error"`
	}
	if json.Unmarshal(resp.Body, &b) != nil {
		return ""
	}
	if e, ok := b.Error.(map[string]any); ok {
		b.Error = e["message"]
	}
	for _, v := range []any{b.Message, b.Messages, b.Error} {
		if m := text(v); m != "" {
			return m
		}
	}
	return ""
}

// text extracts a JSON string or the first string in an array.
func text(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		for _, e := range x {
			if m := text(e); m != "" {
				return m
			}
		}
	}
	return ""
}

// clean removes terminal controls, masks full or partial key echoes and limits the reason to
// one short line.
func clean(msg string, key config.Secret) string {
	redactor := config.NewRedactor(key.Reveal())
	msg = maskEcho(redactor.Redact(msg), key.Reveal())
	line := ""
	for l := range strings.FieldsFuncSeq(msg, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if line = strings.TrimSpace(sanitize.Line(l)); line != "" {
			break
		}
	}
	// Removing control characters may have joined the parts of a key.
	line = maskEcho(redactor.Redact(line), key.Reveal())
	if r := []rune(line); len(r) > maxReason {
		line = string(r[:maxReason]) + "…"
	}
	return line
}

// maskEcho hides key fragments of at least minEcho characters wherever echoed.
func maskEcho(s, key string) string {
	if len([]rune(key)) < minEcho {
		return s
	}
	r := []rune(s)
	var b strings.Builder
	for i := 0; i < len(r); {
		n := 0
		if i+minEcho <= len(r) && strings.Contains(key, string(r[i:i+minEcho])) {
			n = minEcho
			for i+n < len(r) && strings.Contains(key, string(r[i:i+n+1])) {
				n++
			}
		}
		if n == 0 {
			b.WriteRune(r[i])
			i++
			continue
		}
		b.WriteString(mask)
		i += n
	}
	return b.String()
}

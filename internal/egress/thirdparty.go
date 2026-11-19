package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/scope"
)

const (
	maxThirdPartyBody = 10 << 20
	maxThirdPartyWait = 120 * time.Second
)

// ThirdPartyRequest is a request to a third-party source.
type ThirdPartyRequest struct {
	Method      string // GET, HEAD or POST
	URL         string // https URL whose host matches the calling stage's Sources()
	Body        []byte
	ContentType string
	// Accept sets the Accept header when it is not empty.
	Accept string
	// KeySource names a configured key to attach, as header KeyHeader and/or
	// query parameter KeyParam. The client attaches it; stages never handle it.
	KeySource, KeyHeader, KeyParam string
	// KeyPrefix is put before the key in the KeyHeader value ("Bearer ").
	KeyPrefix string
	// KeyBodyField, with KeySource, sets this field of the JSON object in Body
	// to the key, so a source that wants the key in the body never exposes it to the stage.
	KeyBodyField string
	// Timeout overrides the default HTTP timeout for this request (at most 120 s).
	Timeout time.Duration
}

// ThirdPartyResponse is a response from a third-party source (body capped at 10 MiB).
type ThirdPartyResponse struct {
	Status int
	Header map[string][]string
	Body   []byte
	// Truncated is set when the 10 MiB cap cut the body. A stage that needs the
	// whole body must treat it as an error.
	Truncated bool
}

// HeaderValue is the first value of the named header, matched case-insensitively,
// or "" if there is none.
func (r ThirdPartyResponse) HeaderValue(name string) string { return http.Header(r.Header).Get(name) }

// ThirdPartyHTTP talks to the hosts a stage declared in Sources().
type ThirdPartyHTTP interface {
	Do(ctx context.Context, r ThirdPartyRequest) (ThirdPartyResponse, error)
}

type thirdParty struct {
	e       *Egress
	sources []string
	// exempt are the source patterns whose hosts skip the candidate refusal.
	exempt []string
}

// matchSource reports whether host is the source pattern: an exact host, "*.x"
// (any name under x), or a pattern with one "*" label in the middle
// ("s3.*.amazonaws.com"), which matches exactly one label of [a-z0-9-]+.
func matchSource(pattern, host string) bool {
	if rest, ok := strings.CutPrefix(pattern, "*."); ok && !strings.Contains(rest, "*") {
		return strings.HasSuffix(host, "."+rest)
	}
	if !strings.Contains(pattern, "*") {
		return host == pattern
	}
	pl, hl := strings.Split(pattern, "."), strings.Split(host, ".")
	if len(pl) != len(hl) {
		return false
	}
	for i, p := range pl {
		if p == "*" {
			if hl[i] == "" || strings.Trim(hl[i], "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
				return false
			}
		} else if p != hl[i] {
			return false
		}
	}
	return true
}

func (t *thirdParty) Do(ctx context.Context, r ThirdPartyRequest) (ThirdPartyResponse, error) {
	e := t.e
	u, pattern, err := t.sourceURL(r)
	if err != nil {
		return ThirdPartyResponse{}, err
	}
	key, err := e.attachKey(&r, u)
	if err != nil {
		return ThirdPartyResponse{}, err
	}
	if err := e.sourceLimiter(pattern).Wait(ctx); err != nil {
		return ThirdPartyResponse{}, err
	}
	timeout := e.opts.HTTPTimeout
	if r.Timeout > 0 {
		timeout = min(r.Timeout, maxThirdPartyWait)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	hreq, err := t.newRequest(ctx, r, u, key)
	if err != nil {
		return ThirdPartyResponse{}, t.scrub(err)
	}
	resp, err := e.thirdParty.Do(hreq)
	if err != nil {
		return ThirdPartyResponse{}, t.scrub(err)
	}
	defer resp.Body.Close()
	data, truncated, err := readCapped(resp.Body, maxThirdPartyBody)
	if err != nil {
		return ThirdPartyResponse{}, t.scrub(err)
	}
	return ThirdPartyResponse{Status: resp.StatusCode, Header: resp.Header, Body: data, Truncated: truncated}, nil
}

// sourceURL checks a request's method and URL against the stage's sources and the policy, and
// returns the URL to send it to (rebased by Options.SourceBaseURLs) and the source pattern it matched.
func (t *thirdParty) sourceURL(r ThirdPartyRequest) (*url.URL, string, error) {
	e := t.e
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodHead {
		return nil, "", fmt.Errorf("method %q is not permitted for third-party requests", r.Method)
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Host == "" {
		return nil, "", fmt.Errorf("invalid third-party URL %q", e.opts.Redactor.Redact(r.URL))
	}
	if u.Scheme != "https" || u.User != nil {
		return nil, "", errors.New("third-party requests must be https without userinfo")
	}
	host := dnsname.Normalise(u.Hostname())
	i := slices.IndexFunc(t.sources, func(s string) bool { return matchSource(s, host) })
	if i < 0 {
		return nil, "", fmt.Errorf("host %s is not one of this stage's sources", host)
	}
	pattern := t.sources[i]
	if err := t.policyRefusal(host); err != nil {
		return nil, "", err
	}
	if err := e.rebase(u, host, pattern); err != nil {
		return nil, "", err
	}
	return u, pattern, nil
}

// policyRefusal refuses a source host that the current scope classifies as in scope or
// excluded, or that is a candidate the stage has not declared exempt.
func (t *thirdParty) policyRefusal(host string) error {
	p := t.e.policy()
	if p == nil {
		return nil
	}
	if p.Scope != nil {
		if c := p.Scope.ClassifyHost(host); c.Class == scope.InScope || c.Class == scope.Excluded {
			return fmt.Errorf("host %s is %s; third-party clients never contact it", host, c.Class)
		}
	}
	if p.Candidates[host] && !t.candidateExempt(host) {
		return fmt.Errorf("host %s is a candidate; it is never contacted", host)
	}
	return nil
}

// rebase points u at the base URL Options.SourceBaseURLs gives for host or, failing that, for
// pattern. Without either it leaves u alone.
func (e *Egress) rebase(u *url.URL, host, pattern string) error {
	base, ok := e.opts.SourceBaseURLs[host]
	if !ok {
		base, ok = e.opts.SourceBaseURLs[pattern]
	}
	if !ok {
		return nil
	}
	b, err := url.Parse(base)
	if err != nil {
		return err
	}
	u.Scheme, u.Host = b.Scheme, b.Host
	return nil
}

// attachKey looks up the key r.KeySource names, if any, and puts it in the query parameter
// and JSON body field the request asks for. The header is set by newRequest.
func (e *Egress) attachKey(r *ThirdPartyRequest, u *url.URL) (config.Secret, error) {
	var key config.Secret
	if r.KeySource == "" {
		return key, nil
	}
	key, ok := e.opts.Keys[strings.ToLower(r.KeySource)]
	if !ok {
		return key, fmt.Errorf("no key configured for %s", r.KeySource)
	}
	if r.KeyParam != "" {
		q := u.Query()
		q.Set(r.KeyParam, key.Reveal())
		u.RawQuery = q.Encode()
	}
	if r.KeyBodyField != "" {
		var obj map[string]any
		if err := json.Unmarshal(r.Body, &obj); err != nil || obj == nil {
			return key, errors.New("a key body field needs a JSON object body")
		}
		obj[r.KeyBodyField] = key.Reveal()
		r.Body, _ = json.Marshal(obj)
	}
	return key, nil
}

// newRequest builds the HTTP request for r to u, with the User-Agent, the content type and
// Accept it asks for, and the key in KeyHeader when it names one.
func (t *thirdParty) newRequest(ctx context.Context, r ThirdPartyRequest, u *url.URL, key config.Secret) (*http.Request, error) {
	var body io.Reader
	if len(r.Body) > 0 {
		body = bytes.NewReader(r.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, r.Method, u.String(), body)
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("User-Agent", t.e.opts.UserAgent)
	if r.ContentType != "" {
		hreq.Header.Set("Content-Type", r.ContentType)
	}
	if r.Accept != "" {
		hreq.Header.Set("Accept", r.Accept)
	}
	if r.KeySource != "" && r.KeyHeader != "" {
		hreq.Header.Set(r.KeyHeader, r.KeyPrefix+key.Reveal())
	}
	return hreq, nil
}

// candidateExempt reports whether host matches a pattern the stage declared as
// a provider endpoint rather than a target system.
func (t *thirdParty) candidateExempt(host string) bool {
	return slices.ContainsFunc(t.exempt, func(p string) bool { return matchSource(p, host) })
}

// scrub removes key values from an error, including the URL net/http embeds.
func (t *thirdParty) scrub(err error) error {
	return errors.New(t.e.opts.Redactor.Redact(err.Error()))
}

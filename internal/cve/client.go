package cve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rafaelh/nyx/internal/batch"
	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/egress"
)

// Host is the NVD's API host, the one host nyx cve contacts.
const Host = "services.nvd.nist.gov"

// The NVD's published rate limits: requests per rolling window, without and
// with an API key.
const (
	rateWindow     = 30 * time.Second
	rateWithoutKey = 5
	rateWithKey    = 50
)

const (
	maxAttempts    = 3 // the first and two retries
	maxRequestWait = 120 * time.Second
)

// The hints of the failures whose hint does not depend on the call.
const (
	hintNotFound   = "check the ID; the NVD lists only published CVEs"
	hintRetryLater = "retry later"
	hintNoKey      = "; or set NVD_API_KEY for 50 requests per 30s"
)

// Config is what a Client needs.
type Config struct {
	HTTP egress.ThirdPartyHTTP
	// Keyed is whether the requests carry an API key, which egress attaches as
	// the key of the "nvd" source.
	Keyed bool
	// AuthHint is the hint of a refused key: where the key came from.
	AuthHint string
	// Debug, when set, receives one line per attempt.
	Debug func(msg string)
}

// Client looks up one CVE ID at a time. One Client serves a whole batch, so
// every request shares its window.
type Client struct {
	cfg     Config
	win     *window
	backoff time.Duration // the wait before the first retry; it doubles for each one after
	stop    atomic.Bool   // set by the first refused key
}

// NewClient returns a Client paced to the NVD's limit for cfg.Keyed.
func NewClient(cfg Config) *Client {
	n := rateWithoutKey
	if cfg.Keyed {
		n = rateWithKey
	}
	return &Client{cfg: cfg, win: newWindow(n, rateWindow, time.Now), backoff: time.Second}
}

// Failure is why the lookup of one ID failed: its error (without an input),
// and how long to wait before a retry may succeed, 0 when that is not known.
type Failure struct {
	Err  *clierr.Error
	Wait time.Duration
}

func (f *Failure) Error() string { return f.Err.Message }

// Get looks up one CVE ID, retrying transient failures within ctx's deadline.
// Its error is a *Failure, or ctx's error when ctx was cancelled by anything
// but its deadline.
func (c *Client) Get(ctx context.Context, id string) (Record, error) {
	for attempt := 1; ; attempt++ {
		if c.stop.Load() {
			return Record{}, c.refused()
		}
		// Past the deadline, the window is not why the ID goes unsent.
		if deadline, has := ctx.Deadline(); ctx.Err() != nil || has && !time.Now().Before(deadline) {
			c.debugf("nvd %s attempt %d: not sent, the call has ended", id, attempt)
			return Record{}, ended(ctx)
		}
		wait, ok := c.win.reserve(ctx)
		if !ok {
			msg := fmt.Sprintf("the NVD allows %d requests per %s, and the next is due after the deadline", c.win.n, c.win.size)
			c.debugf("nvd %s attempt %d: not sent, %s", id, attempt, msg)
			return Record{}, c.rateLimited(msg, wait)
		}
		if err := sleep(ctx, wait); err != nil {
			return Record{}, ended(ctx)
		}
		if c.stop.Load() {
			return Record{}, c.refused()
		}
		a := c.attempt(ctx, id)
		at := fmt.Sprintf("nvd %s attempt %d", id, attempt)
		if wait > 0 {
			at += fmt.Sprintf(" (after a wait of %s for the rate limit)", wait.Round(time.Millisecond))
		}
		switch {
		case a.ended:
			c.debugf("%s: cut off", at)
			return Record{}, ended(ctx)
		case a.fail == nil:
			c.debugf("%s: %s", at, a.status)
			return a.rec, nil
		case !a.retry:
			c.debugf("%s: %s", at, a.status)
			return Record{}, &Failure{Err: a.fail}
		}
		d := c.retryDelay(a.retryAfter, attempt)
		if attempt == maxAttempts {
			c.debugf("%s: %s, not retried again", at, a.status)
			return Record{}, c.exhausted(a, d)
		}
		if deadline, ok := ctx.Deadline(); ok && time.Now().Add(d).After(deadline) {
			c.debugf("%s: %s, its retry in %s is after the deadline", at, a.status, d.Round(time.Millisecond))
			return Record{}, c.retryPastDeadline(a, d)
		}
		c.debugf("%s: %s, retry in %s", at, a.status, d.Round(time.Millisecond))
		if err := sleep(ctx, d); err != nil {
			return Record{}, ended(ctx)
		}
	}
}

// attempted is how one request ended: a record, a failure (and whether the
// client retries it), or a context that ended while it was in flight.
type attempted struct {
	rec        Record
	fail       *clierr.Error
	status     string // what the NVD answered, for --debug
	retry      bool
	rateLimit  bool   // a rate-limit answer: its retry, past the deadline, is RATE_LIMITED
	retryAfter string // the answer's Retry-After header
	ended      bool
}

// attempt sends one request for id and classifies the answer.
func (c *Client) attempt(ctx context.Context, id string) attempted {
	req := egress.ThirdPartyRequest{Method: "GET", URL: "https://" + Host + "/rest/json/cves/2.0?cveId=" + id, Accept: "application/json"}
	if c.cfg.Keyed {
		req.KeySource, req.KeyHeader = "nvd", "apiKey"
	}
	if deadline, ok := ctx.Deadline(); ok {
		// The invocation's deadline governs the request, not egress's default timeout.
		req.Timeout = max(min(time.Until(deadline), maxRequestWait), time.Millisecond)
	}
	resp, err := c.cfg.HTTP.Do(ctx, req)
	if err != nil {
		if ctx.Err() != nil {
			return attempted{ended: true}
		}
		return attempted{status: "network error: " + err.Error(), retry: true,
			fail: &clierr.Error{Code: clierr.NetworkError, Message: "cannot reach the NVD: " + err.Error(), Hint: hintRetryLater, Transient: true}}
	}
	a := attempted{status: fmt.Sprintf("HTTP %d", resp.Status), retryAfter: resp.HeaderValue("Retry-After")}
	if resp.Status == 200 {
		a.rec, a.fail = decode(resp)
		return a
	}
	message := resp.HeaderValue("message")
	upstream := func(transient bool, retry bool) attempted {
		a.fail = &clierr.Error{Code: clierr.UpstreamError, Message: fmt.Sprintf("the NVD answered HTTP %d", resp.Status), Transient: transient}
		if message != "" {
			a.fail.Message += ": " + message
		}
		if transient {
			a.fail.Hint = hintRetryLater
		}
		a.retry = retry
		return a
	}
	switch s := resp.Status; {
	case s == 401, (s == 403 || s == 404) && strings.Contains(strings.ToLower(message+" "+string(resp.Body)), "apikey"):
		c.stop.Store(true) // the first refused key stops the batch
		a.fail = c.refused().Err
	case s == 403, s == 429:
		a.retry, a.rateLimit = true, true
		a.fail = &clierr.Error{Code: clierr.RateLimited, Message: fmt.Sprintf("the NVD refused the request for its rate limit (HTTP %d)", s), Transient: true}
	case s == 502, s == 503, s == 504:
		return upstream(true, true)
	case s >= 500:
		return upstream(true, false)
	default: // a 404 that does not name the key is a refused parameter, never "not found"
		return upstream(false, false)
	}
	return a
}

// decode reads a 200's body: the record, or not found when the NVD holds no
// entry for the ID.
func decode(resp egress.ThirdPartyResponse) (Record, *clierr.Error) {
	if resp.Truncated {
		return Record{}, &clierr.Error{Code: clierr.UpstreamError, Message: "the NVD's answer was cut off at 10 MiB"}
	}
	var body response
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return Record{}, &clierr.Error{Code: clierr.UpstreamError, Message: "the NVD sent an answer that does not decode: " + err.Error()}
	}
	if len(body.Vulnerabilities) == 0 {
		return Record{}, &clierr.Error{Code: clierr.NotFound, Message: "not in the NVD", Hint: hintNotFound}
	}
	return FromNVD(&body.Vulnerabilities[0].CVE), nil
}

// refused is the failure of a refused key, the same for the ID whose request
// the NVD refused and for every ID not yet sent.
func (c *Client) refused() *Failure {
	return &Failure{Err: &clierr.Error{Code: clierr.AuthFailed, Message: "the NVD refused the API key", Hint: c.cfg.AuthHint}}
}

// rateLimited is a transient rate limit that may succeed after wait.
func (c *Client) rateLimited(msg string, wait time.Duration) *Failure {
	hint := "retry after " + batch.Seconds(wait)
	if !c.cfg.Keyed {
		hint += hintNoKey
	}
	return &Failure{Err: &clierr.Error{Code: clierr.RateLimited, Message: msg, Hint: hint, Transient: true}, Wait: wait}
}

// exhausted is the failure of a retried answer once its attempts are spent.
// Only a rate limit's wait is known.
func (c *Client) exhausted(a attempted, d time.Duration) *Failure {
	if a.rateLimit {
		return c.rateLimited(a.fail.Message, d)
	}
	return &Failure{Err: a.fail}
}

// retryPastDeadline is the failure of an answer whose retry, after d, would
// be after the deadline: a rate limit for a rate-limit answer, else a timeout.
func (c *Client) retryPastDeadline(a attempted, d time.Duration) *Failure {
	if a.rateLimit {
		return c.rateLimited(a.fail.Message+", and its retry is due after the deadline", d)
	}
	return &Failure{Err: &clierr.Error{Code: clierr.Timeout, Message: a.fail.Message + ", and its retry is due after the deadline",
		Hint: "retry after " + batch.Seconds(d) + ", or " + batch.HintTimeout, Transient: true}, Wait: d}
}

// ended is the error of a context that ended: a cancel (a signal) as itself,
// and its deadline, passed even before its timer fires, as a timeout.
func ended(ctx context.Context) error {
	if err := ctx.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &Failure{Err: &clierr.Error{Code: clierr.Timeout, Message: "no answer from the NVD before the deadline", Hint: batch.HintTimeout, Transient: true}}
}

// retryDelay is the wait before a retry: Retry-After when it is a whole
// number of seconds, else the backoff, doubling for each attempt, uniform in
// [d/2, 3d/2) so concurrent retries do not arrive together.
func (c *Client) retryDelay(retryAfter string, attempt int) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	d := c.backoff << (attempt - 1)
	return d/2 + rand.N(d)
}

func (c *Client) debugf(format string, args ...any) {
	if c.cfg.Debug != nil {
		c.cfg.Debug(fmt.Sprintf(format, args...))
	}
}

// These types decode the NVD CVE API 2.0. They are never shown to callers:
// what callers see is the Record.

// response is the NVD's envelope around the entries that match a query.
type response struct {
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

type vulnerability struct {
	CVE Entry `json:"cve"`
}

// Entry is an NVD entry: the NVD's own JSON object for one CVE.
type Entry struct {
	ID               string          `json:"id"`
	SourceIdentifier string          `json:"sourceIdentifier"`
	Published        string          `json:"published"` // zoneless, and UTC
	LastModified     string          `json:"lastModified"`
	VulnStatus       string          `json:"vulnStatus"`
	Descriptions     []LangString    `json:"descriptions"`
	Metrics          *Metrics        `json:"metrics"`
	Weaknesses       []Weakness      `json:"weaknesses"`
	Configurations   []Configuration `json:"configurations"`
	References       []NVDReference  `json:"references"`
}

// LangString is a text in one language.
type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Metrics holds every CVSS score in the entry, by CVSS version.
type Metrics struct {
	CVSSMetricV40 []CVSSMetric `json:"cvssMetricV40"`
	CVSSMetricV31 []CVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []CVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []CVSSMetric `json:"cvssMetricV2"`
}

// CVSSMetric is one CVSS score. Type is Primary, published by the NVD itself,
// or Secondary. Version 2 keeps its severity here as BaseSeverity; later
// versions keep it in CVSSData.
type CVSSMetric struct {
	Source       string    `json:"source"`
	Type         string    `json:"type"`
	BaseSeverity string    `json:"baseSeverity"`
	CVSSData     *CVSSData `json:"cvssData"`
}

// CVSSData is a score's data. Version 2 has no BaseSeverity here.
type CVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// Weakness is one weakness source's CWE values.
type Weakness struct {
	Source      string       `json:"source"`
	Type        string       `json:"type"`
	Description []LangString `json:"description"`
}

// Configuration is one tree of configuration nodes.
type Configuration struct {
	Nodes []Node `json:"nodes"`
}

// Node is a configuration node; its CPE matches and child nodes combine by
// Operator.
type Node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []CPEMatch `json:"cpeMatch"`
	Nodes    []Node     `json:"nodes"`
}

// CPEMatch is one CPE match of a node, with its version bounds.
type CPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"` // a CPE 2.3 formatted string
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// NVDReference is one of the entry's references.
type NVDReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

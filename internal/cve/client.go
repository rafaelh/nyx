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

// Host restricts CVE lookups to NVD's API endpoint.
const Host = "services.nvd.nist.gov"

// NVD rolling-window request limits for unkeyed and keyed calls.
const (
	rateWindow     = 30 * time.Second
	rateWithoutKey = 5
	rateWithKey    = 50
)

const (
	maxAttempts    = 3 // the first and two retries
	maxRequestWait = 120 * time.Second
)

// Shared failure hints independent of invocation arguments.
const (
	hintNotFound   = "check the ID; the NVD lists only published CVEs"
	hintRetryLater = "retry later"
	hintNoKey      = "; or set keys.nvd in the config file for 50 requests per 30s"
)

// Config supplies NVD client dependencies.
type Config struct {
	HTTP egress.ThirdPartyHTTP
	// Keyed selects authenticated rate limits; egress attaches the NVD key.
	Keyed bool
	// AuthHint explains where rejected credentials were configured.
	AuthHint string
	// Debug, when set, receives one line per attempt.
	Debug func(msg string)
}

// Client shares one rate window across all requests and retries in a batch.
type Client struct {
	cfg     Config
	win     *window
	backoff time.Duration // initial retry delay, doubled on each retry
	stop    atomic.Bool   // set by the first refused key
}

// NewClient selects NVD pacing from keyed status.
func NewClient(cfg Config) *Client {
	n := rateWithoutKey
	if cfg.Keyed {
		n = rateWithKey
	}
	return &Client{cfg: cfg, win: newWindow(n, rateWindow, time.Now), backoff: time.Second}
}

// Failure describes one failed lookup and any known retry delay. Its error omits the input so
// callers can attach the original argument.
type Failure struct {
	Err  *clierr.Error
	Wait time.Duration
}

func (f *Failure) Error() string { return f.Err.Message }

// Get retries transient CVE lookup failures within ctx's deadline. It returns *Failure, except
// external cancellation returns the context error directly.
func (c *Client) Get(ctx context.Context, id string) (Record, error) {
	for attempt := 1; ; attempt++ {
		if c.stop.Load() {
			return Record{}, c.refused()
		}
		// After expiry, report timeout rather than an unavailable window slot.
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

// attempted captures a request's record, retryable failure or interrupted context.
type attempted struct {
	rec        Record
	fail       *clierr.Error
	status     string // what the NVD answered, for --debug
	retry      bool
	rateLimit  bool   // an unfittable rate-limit retry remains RATE_LIMITED
	retryAfter string // the answer's Retry-After header
	ended      bool
}

// attempt makes and classifies one request.
func (c *Client) attempt(ctx context.Context, id string) attempted {
	req := egress.ThirdPartyRequest{Method: "GET", URL: "https://" + Host + "/rest/json/cves/2.0?cveId=" + id, Accept: "application/json"}
	if c.cfg.Keyed {
		req.KeySource, req.KeyHeader = "nvd", "apiKey"
	}
	if deadline, ok := ctx.Deadline(); ok {
		// Use the invocation deadline rather than the default egress timeout.
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
	switch s, meaning := resp.Status, Meaning(resp.Status, message, resp.Body); {
	case meaning == KeyRefused:
		c.stop.Store(true) // the first refused key stops the batch
		a.fail = c.refused().Err
	case meaning == RateLimited:
		a.retry, a.rateLimit = true, true
		a.fail = &clierr.Error{Code: clierr.RateLimited, Message: fmt.Sprintf("the NVD refused the request for its rate limit (HTTP %d)", s), Transient: true}
	case s == 502, s == 503, s == 504:
		return upstream(true, true)
	case s >= 500:
		return upstream(true, false)
	default: // NVD also uses 404 for rejected parameters, so it cannot establish missing IDs
		return upstream(false, false)
	}
	return a
}

// Answer classifies non-200 NVD responses.
type Answer int

const (
	// Other covers responses unrelated to credentials or rate limits.
	Other Answer = iota
	// KeyRefused covers 401 and key-specific 403/404 responses.
	KeyRefused
	// RateLimited covers 429 and non-key 403 responses.
	RateLimited
)

// Meaning classifies an NVD response using its status, message header and body. Either text can
// mention a rejected key. A key-unrelated 404 is Other, since NVD also uses 404 for rejected
// parameters.
func Meaning(status int, message string, body []byte) Answer {
	named := func() bool { return strings.Contains(strings.ToLower(message+" "+string(body)), "apikey") }
	switch {
	case status == 401, (status == 403 || status == 404) && named():
		return KeyRefused
	case status == 403, status == 429:
		return RateLimited
	}
	return Other
}

// decode handles successful bodies, including a valid response with no matching ID.
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

// refused shares the key-rejection failure across the refused request and unsent IDs.
func (c *Client) refused() *Failure {
	return &Failure{Err: &clierr.Error{Code: clierr.AuthFailed, Message: "the NVD refused the API key", Hint: c.cfg.AuthHint}}
}

// rateLimited supplies a retryable error with wait guidance.
func (c *Client) rateLimited(msg string, wait time.Duration) *Failure {
	hint := "retry after " + batch.Seconds(wait)
	if !c.cfg.Keyed {
		hint += hintNoKey
	}
	return &Failure{Err: &clierr.Error{Code: clierr.RateLimited, Message: msg, Hint: hint, Transient: true}, Wait: wait}
}

// exhausted reports the final failed attempt, preserving known rate-limit wait time.
func (c *Client) exhausted(a attempted, d time.Duration) *Failure {
	if a.rateLimit {
		return c.rateLimited(a.fail.Message, d)
	}
	return &Failure{Err: a.fail}
}

// retryPastDeadline reports rate limiting or timeout when the next retry cannot fit before the
// deadline.
func (c *Client) retryPastDeadline(a attempted, d time.Duration) *Failure {
	if a.rateLimit {
		return c.rateLimited(a.fail.Message+", and its retry is due after the deadline", d)
	}
	return &Failure{Err: &clierr.Error{Code: clierr.Timeout, Message: a.fail.Message + ", and its retry is due after the deadline",
		Hint: "retry after " + batch.Seconds(d) + ", or " + batch.HintTimeout, Transient: true}, Wait: d}
}

// ended preserves cancellation errors and maps expired deadlines to timeout, even before their
// timers fire.
func ended(ctx context.Context) error {
	if err := ctx.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &Failure{Err: &clierr.Error{Code: clierr.Timeout, Message: "no answer from the NVD before the deadline", Hint: batch.HintTimeout, Transient: true}}
}

// retryDelay uses an integer Retry-After value when present. Otherwise it doubles the backoff
// per attempt and adds jitter in [d/2, 3d/2) to spread concurrent retries.
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

// These private types decode NVD CVE API 2.0; callers receive Record instead.

// response models NVD's query-result envelope.
type response struct {
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

type vulnerability struct {
	CVE Entry `json:"cve"`
}

// Entry models the original NVD object for one CVE.
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

// Metrics groups available scores by CVSS version.
type Metrics struct {
	CVSSMetricV40 []CVSSMetric `json:"cvssMetricV40"`
	CVSSMetricV31 []CVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []CVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []CVSSMetric `json:"cvssMetricV2"`
}

// CVSSMetric holds a score and its Primary/Secondary source type. CVSS v2 stores severity in
// BaseSeverity; later versions use CVSSData.
type CVSSMetric struct {
	Source       string    `json:"source"`
	Type         string    `json:"type"`
	BaseSeverity string    `json:"baseSeverity"`
	CVSSData     *CVSSData `json:"cvssData"`
}

// CVSSData holds version-specific score fields; v2 stores severity outside it.
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

// Node combines child nodes and CPE matches using its Operator.
type Node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []CPEMatch `json:"cpeMatch"`
	Nodes    []Node     `json:"nodes"`
}

// CPEMatch retains affected-version boundaries for one configuration match.
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

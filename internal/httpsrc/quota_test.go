package httpsrc_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/rafaelh/nyx/internal/httpsrc"
	"github.com/rafaelh/nyx/internal/ipsource"
	"github.com/rafaelh/nyx/internal/run"
)

func TestQuotaError_WrapsRunQuotaAndKeepsTheText(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("bootstrap ipv4.json: %w", &ipsource.RateLimitedError{Host: "data.iana.org"})
	got := httpsrc.QuotaError(err)
	if !errors.Is(got, run.ErrQuota) || !errors.Is(got, run.ErrAbortProcedure) || !errors.Is(got, ipsource.ErrQuota) {
		t.Errorf("%v should be a spent quota of both kinds", got)
	}
	var rl *ipsource.RateLimitedError
	if !errors.As(got, &rl) || rl.Host != "data.iana.org" {
		t.Errorf("the rate-limited host is lost: %v", got)
	}
	if want := "bootstrap ipv4.json: HTTP 429: " + run.ErrQuota.Error(); got.Error() != want {
		t.Errorf("text = %q, want %q", got, want)
	}
}

func TestQuotaError_LeavesOtherErrorsAlone(t *testing.T) {
	t.Parallel()
	plain := errors.New("HTTP 500")
	if httpsrc.QuotaError(plain) != plain || httpsrc.QuotaError(nil) != nil { //nolint:errorlint // identity is what is checked
		t.Error("an error that is not a spent quota must be returned as it is")
	}
	already := fmt.Errorf("HTTP 429: %w", run.ErrQuota)
	if httpsrc.QuotaError(already) != already { //nolint:errorlint // identity is what is checked
		t.Error("an error that already wraps run.ErrQuota must be returned as it is")
	}
}

func TestHackerTargetLines_QuotaIsRunErrQuota(t *testing.T) {
	t.Parallel()
	lines, err := httpsrc.HackerTargetLines([]byte("API count exceeded - Increase Quota"))
	if lines != nil || !errors.Is(err, run.ErrQuota) || err.Error() != "HackerTarget API count exceeded: "+run.ErrQuota.Error() {
		t.Errorf("lines = %q, err = %v", lines, err)
	}
	lines, err = httpsrc.HackerTargetLines([]byte("a.example.com\nb.example.com\n"))
	if err != nil || len(lines) != 2 {
		t.Errorf("lines = %q, err = %v", lines, err)
	}
}

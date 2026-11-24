//go:build perf

package cli_test

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// perfOut optionally saves each run's output for comparisons between builds.
var perfOut = flag.String("perf-out", "", "copy the perf engagement's output files to this directory")

// keepOutputs copies the engagement's output files to perfOut/sub.
func keepOutputs(t *testing.T, w *world, eng, sub string) {
	t.Helper()
	if *perfOut == "" {
		return
	}
	dst := filepath.Join(*perfOut, sub)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(w.h.out, eng))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		copyFile(t, filepath.Join(w.h.out, eng, e.Name()), filepath.Join(dst, e.Name()))
	}
	// The state database too, with its log, to compare the records and the baseline.
	for _, name := range []string{"state.db", "state.db-wal"} {
		if _, err := os.Stat(filepath.Join(w.h.out, eng, ".nyx", name)); err == nil {
			copyFile(t, filepath.Join(w.h.out, eng, ".nyx", name), filepath.Join(dst, ".nyx", name))
		}
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestPerfLargeEngagement profiles local processing with real passive stages and fake sources.
// Enable the perf tag and use -cpuprofile to capture a profile.
func TestPerfLargeEngagement(t *testing.T) {
	t.Parallel()
	const hosts, urls = 20000, 5000
	w := newWorld(t)
	var names []string
	for i := range hosts {
		name := fmt.Sprintf("h%d.example.com", i)
		names = append(names, name)
		addr := fmt.Sprintf("45.%d.%d.%d", 10+i/62500, i/250%250, i%250+1)
		if i%10 == 5 { // a tenth of the names are fronted by a CDN
			edge := fmt.Sprintf("d%d.cloudfront.net", i)
			w.dns.CNAME(name, edge)
			name = edge
		}
		w.dns.A(name, addr)
		if i%10 == 0 {
			w.owner(addr, 64500+i%50, "ACME-NET")
		}
	}
	w.crtsh(map[string][]string{"example.com": names}, nil)
	var archived []string
	for i := range urls {
		archived = append(archived, fmt.Sprintf("https://h%d.example.com/page/%d?id=%d", i%hosts, i, i))
	}
	w.commonCrawl("CC-MAIN-2026-01", archived...)
	const eng = "example.com"
	args := []string{"--passive", "--no-permutations", "--concurrency", "64", "example.com"}

	start := time.Now()
	if code := w.run(args...); code != 0 && code != 7 {
		t.Fatalf("first run exit %d\n%s", code, w.h.stderr.String())
	}
	t.Logf("first run: %v, %d subdomains, %d urls", time.Since(start), len(w.lines(eng, "subdomains.txt")), len(w.table(eng, "urls.csv")))
	keepOutputs(t, w, eng, "first")

	start = time.Now()
	if code := w.run(args...); code != 0 && code != 7 {
		t.Fatalf("second run exit %d", code)
	}
	t.Logf("second run (nothing to do): %v", time.Since(start))
	keepOutputs(t, w, eng, "second")
}

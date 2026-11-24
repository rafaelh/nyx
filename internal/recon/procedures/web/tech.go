package web

import (
	"maps"
	"slices"
	"strings"
	"sync"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// fingerprints caches Wappalyzer loading per process; failures leave technologies empty and
// httpprobe warns.
var fingerprints = sync.OnceValues(wappalyzer.New)

// technologies combines header/body detection as sorted semicolon-separated names, adding
// detected versions after a colon.
func technologies(header map[string][]string, body []byte) string {
	w, err := fingerprints()
	if err != nil {
		return ""
	}
	return strings.Join(slices.Sorted(maps.Keys(w.Fingerprint(header, body))), ";")
}

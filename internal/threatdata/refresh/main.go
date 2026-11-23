// Command refresh rebuilds the built-in copies of the five threat-data lists from the files
// `make threat-data` fetched: Spamhaus's DROP, DROPv6 and ASN-DROP (internal/spamhaus/builtin.jsonl,
// a bundle) and ipapi.is's most abusive networks and ASNs (internal/abusive/snapshot.json). It makes
// no request itself: curl fetches, and this program checks each list with the rules an update
// applies, prints what was added, removed and changed, and replaces each source's file as a whole,
// or not at all. It is a maintainer's tool, not part of the nyx binary.
//
// It reads, from the -dir directory, drop_v4.json, drop_v6.json and asndrop.json (as Spamhaus
// serves them) and networks.html and asns.html (ipapi.is's pages). A list dated no later than the
// built-in copy is left as it is. -allow-shrink lets through a list that holds fewer than half the
// entries of the built-in copy, for a maintainer who has reviewed it, and lifts no other rule.
package main

import (
	"os"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now().UTC()))
}

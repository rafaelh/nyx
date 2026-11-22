// Command refresh rebuilds the embedded snapshot of ipapi.is's most abusive networks and ASNs
// (internal/abusive/snapshot.json) from the two pages `make abusive-data` fetched. It makes no
// request itself: curl fetches, and this program parses, checks, prints what changed and writes the
// file. It is a maintainer's tool, not part of the nyx binary.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	var o options
	flag.StringVar(&o.networks, "networks", "", "the fetched most-abusive-networks page")
	flag.StringVar(&o.asns, "asns", "", "the fetched most-abusive-asn page")
	flag.StringVar(&o.snapshot, "snapshot", "", "the snapshot file to replace")
	flag.Parse()
	if o.networks == "" || o.asns == "" || o.snapshot == "" {
		fmt.Fprintln(os.Stderr, "usage: refresh -networks <file> -asns <file> -snapshot <file>")
		os.Exit(2)
	}
	o.now = time.Now().UTC()
	if err := refresh(o, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "refresh failed, and the snapshot is unchanged:", err)
		os.Exit(1)
	}
}

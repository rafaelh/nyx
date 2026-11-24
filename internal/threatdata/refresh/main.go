// Command refresh rebuilds embedded Spamhaus and ipapi.is data from files fetched by make
// threat-data. It performs no network requests. Lists are validated with runtime update rules,
// changes are printed and each source file is replaced atomically.
//
// -dir supplies drop_v4.json, drop_v6.json, asndrop.json, networks.html and asns.html. Lists no
// newer than the embedded copy stay unchanged. -allow-shrink bypasses only the half-size
// rejection for maintainer-reviewed data.
package main

import (
	"os"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now().UTC()))
}

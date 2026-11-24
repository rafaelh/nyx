// Command nyx discovers target domains, organisations and networks using passive sources first.
package main

import (
	"context"
	"os"

	"github.com/rafaelh/nyx/internal/cli"
)

func main() {
	d := cli.DefaultDeps()
	d.Signals = cli.NotifySignals()
	os.Exit(cli.Execute(context.Background(), os.Args[1:], d))
}

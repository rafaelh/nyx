package cli_test

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/cli"
)

// setupChildMain uses real signal handling on the supplied terminal. NYX_TEST_PANIC_FILE
// injects an editor panic through working-directory lookup.
func setupChildMain() int {
	d := cli.DefaultDeps()
	d.Signals = cli.NotifySignals()
	d.NoFsync = true
	if marker := os.Getenv("NYX_TEST_PANIC_FILE"); marker != "" {
		d.Getwd = func() (string, error) {
			if _, err := os.Stat(marker); err == nil {
				panic("forced panic in Getwd")
			}
			return os.Getwd()
		}
	}
	d.Clock = time.Now
	return cli.Execute(context.Background(), strings.Split(os.Getenv("NYX_TEST_ARGS"), "\x1f"), d)
}

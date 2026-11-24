//go:build !linux

package cli_test

import "testing"

// macOS uses different pseudo-terminal ioctls; the real-terminal tests run on Linux only.
func testSetupOnAPty(t *testing.T) { t.Skip("the pty test runs on Linux only") }

//go:build !linux

package cli_test

import "testing"

// The pty test is Linux-only: macOS opens and configures a pty with different ioctls.
func testSetupOnAPty(t *testing.T) { t.Skip("the pty test runs on Linux only") }

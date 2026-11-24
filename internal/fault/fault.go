// Package fault exposes deterministic crash-test checkpoints. The first goroutine reaching
// NYX_FAULT writes optional detail to NYX_FAULT_FILE and blocks for the test to kill it. Unset
// NYX_FAULT disables the hook.
package fault

import (
	"os"
	"sync/atomic"
)

var (
	target  = os.Getenv("NYX_FAULT")      //nolint:forbidigo // set only by crash tests, in a child process
	file    = os.Getenv("NYX_FAULT_FILE") //nolint:forbidigo // as above
	tripped atomic.Bool
)

// Point pauses at the named point if it is the configured fault.
func Point(name string) { PointDetail(name, "") }

// PointDetail is Point with a detail string recorded in the fault file.
func PointDetail(name, detail string) {
	if target == "" || target != name || !tripped.CompareAndSwap(false, true) {
		return
	}
	if file != "" {
		tmp := file + ".tmp"
		if err := os.WriteFile(tmp, []byte(name+" "+detail+"\n"), 0o600); err == nil {
			_ = os.Rename(tmp, file) // best effort: the process hangs next regardless
		}
	}
	select {}
}

// Package fault provides deterministic crash points for subprocess tests.
//
// When NYX_FAULT names a point, the first goroutine to reach it writes the
// point (and optional detail) to NYX_FAULT_FILE and then blocks forever so a
// test can kill the process at a known moment. With NYX_FAULT unset, Point
// does nothing.
//
// A point reached through Err can also fail instead of pausing: an in-process
// test attaches an error to the point with Inject, so it needs no child
// process and no environment.
package fault

import (
	"context"
	"maps"
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

// injected is the context key under which Inject keeps its points.
type injected struct{}

// Inject returns a copy of ctx under which Err for the named point returns err. Injections add to
// each other and a context derived from the result keeps them.
func Inject(ctx context.Context, name string, err error) context.Context {
	points, _ := ctx.Value(injected{}).(map[string]error)
	next := make(map[string]error, len(points)+1)
	maps.Copy(next, points)
	next[name] = err
	return context.WithValue(ctx, injected{}, next)
}

// Err is Point, and then the error Inject attached to ctx for the named point, or nil.
func Err(ctx context.Context, name string) error {
	Point(name)
	points, _ := ctx.Value(injected{}).(map[string]error)
	return points[name]
}

package fault_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rafaelh/nyx/internal/fault"
)

// An error injected at a point is returned there, and only there.
func TestInject_FailsOnlyItsPoint(t *testing.T) {
	t.Parallel()
	injected := errors.New("injected rename failure")
	ctx := fault.Inject(context.Background(), "threat-before-rename", injected)
	if err := fault.Err(ctx, "threat-before-rename"); !errors.Is(err, injected) {
		t.Errorf("Err at the injected point = %v, want %v", err, injected)
	}
	if err := fault.Err(ctx, "threat-after-response"); err != nil {
		t.Errorf("Err at another point = %v, want nil", err)
	}
	if err := fault.Err(context.Background(), "threat-before-rename"); err != nil {
		t.Errorf("Err with nothing injected = %v, want nil", err)
	}
}

// A context derived from an injected one keeps the injection, and a second injection adds to it.
func TestInject_SurvivesDerivedContexts(t *testing.T) {
	t.Parallel()
	first, second := errors.New("first"), errors.New("second")
	ctx := fault.Inject(context.Background(), "threat-before-rename", first)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx = fault.Inject(ctx, "threat-after-response", second)
	if err := fault.Err(ctx, "threat-before-rename"); !errors.Is(err, first) {
		t.Errorf("Err at the first point = %v, want %v", err, first)
	}
	if err := fault.Err(ctx, "threat-after-response"); !errors.Is(err, second) {
		t.Errorf("Err at the second point = %v, want %v", err, second)
	}
}

package cli_test

import (
	"net/netip"

	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/stages/asn"
)

func newASN() run.Stage { return asn.New() }

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

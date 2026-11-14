package egress_test

import "github.com/rafaelh/nyx/internal/config"

func newRedactor(v ...string) *config.Redactor { return config.NewRedactor(v...) }

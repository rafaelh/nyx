package palette

import "testing"

// 256-colour styles use nearest fixed xterm entries; 16-colour choices are explicit.
func TestDepthTables(t *testing.T) {
	t.Parallel()
	want256 := map[string][2]int{
		"DEBUG": {146, 236}, "INFO": {111, 236}, "WARN": {222, 236}, "ERROR": {210, 236},
		"CRIT": {255, 131}, "PASS": {150, 235}, "DRY RUN": {116, 236}, "MEDIUM": {216, 236},
	}
	want16 := map[string][2]int{
		"DEBUG": {37, 40}, "INFO": {94, 40}, "WARN": {93, 40}, "ERROR": {91, 40},
		"CRIT": {97, 41}, "PASS": {92, 40}, "DRY RUN": {96, 40}, "MEDIUM": {33, 40},
	}
	if len(styles) != len(want256) {
		t.Fatalf("%d base styles, want %d", len(styles), len(want256))
	}
	for _, s := range styles {
		if got := [2]int{s.FG256, s.BG256}; got != want256[s.Name] {
			t.Errorf("%s: 256-colour %v, want %v", s.Name, got, want256[s.Name])
		}
		if got := [2]int{s.FG16, s.BG16}; got != want16[s.Name] {
			t.Errorf("%s: 16-colour %v, want %v", s.Name, got, want16[s.Name])
		}
		if s.Bold != (s.Name == "CRIT") {
			t.Errorf("%s: bold = %v", s.Name, s.Bold)
		}
		// Keep text distinguishable from its background at every depth.
		if s.FG == s.BG || s.FG16 == s.BG16 || s.FG256 == s.BG256 {
			t.Errorf("%s: foreground equals background at some depth: %+v", s.Name, s)
		}
	}
}

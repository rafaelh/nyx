package setup

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/layout"
)

// testPath is the config path the fake backend reports.
const testPath = "/home/tester/.config/nyx/config.yaml"

type testCall struct {
	source string
	key    string
}

// fakeBackend is a Backend that records what the model asks of it.
type fakeBackend struct {
	mu      sync.Mutex
	info    Info
	snap    Snapshot
	openErr error
	token   int

	checkFn func(key, value string) (string, error)
	saveFn  func(snap Snapshot, e Edits) (Snapshot, error)
	overFn  func(e Edits) (Snapshot, error)
	testFn  func(ctx context.Context, source string, key config.Secret) TestResult

	// threat is what ThreatData gives; an update's result replaces it, as the real data would be.
	threat   []ThreatList
	updateFn func(ctx context.Context) ThreatResult

	opens     int
	updates   int
	saves     []Edits
	saveSnaps []Snapshot
	overs     []Edits
	tests     []testCall
	checks    []string
}

func testInfo() Info {
	return Info{
		Path: testPath,
		Sources: []Source{
			{Name: "securitytrails", Turns: "subdomains and DNS history"},
			{Name: "shodan", Turns: "open ports and banners"},
			{Name: "virustotal", Turns: "passive DNS and subdomains"},
			{Name: "whoisxml", Turns: "reverse WHOIS and registrant lookups"},
			{Name: "censys", Turns: "certificate and host search"},
			{Name: "chaos", Turns: "subdomain lists"},
			{Name: "github", Turns: "code search for leaked hostnames"},
			{Name: "certspotter", Turns: "certificate transparency (also works without a key)"},
			{Name: "nvd", Turns: "nyx cve: 50 requests per 30 s instead of 5"},
		},
		Stages: []Stage{
			{Name: "dns", Does: "resolves hostnames"},
			{Name: "ports", Does: "checks open TCP ports"},
			{Name: "web", Does: "fetches home pages"},
			{Name: "risk", Does: "derives findings"},
		},
	}
}

func testSnapshot() Snapshot {
	s := Snapshot{
		Token: 1,
		Keys:  map[string]KeyState{},
		Settings: map[string]Value{
			"output_dir":      {Default: ".", Relative: "Relative: resolves against the directory nyx runs from, e.g. /work/out"},
			"concurrency":     {Default: "8"},
			"rate.per_host":   {Default: "2"},
			"rate.per_source": {Default: "5"},
			"rate.dns":        {Default: "50"},
			"wordlist":        {Default: "built-in (1000 words)"},
			"sensitive_paths": {Default: "built-in (40 paths)"},
		},
	}
	for _, src := range testInfo().Sources {
		s.Keys[src.Name] = KeyState{}
	}
	return s
}

func newFake() *fakeBackend {
	return &fakeBackend{info: testInfo(), snap: testSnapshot(), token: 1}
}

func (f *fakeBackend) Info() Info { return f.info }

func (f *fakeBackend) Open() (Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens++
	if f.openErr != nil {
		return Snapshot{}, f.openErr
	}
	return f.snap, nil
}

func (f *fakeBackend) Check(key, value string) (string, error) {
	f.mu.Lock()
	f.checks = append(f.checks, key+"="+value)
	fn := f.checkFn
	f.mu.Unlock()
	if fn != nil {
		return fn(key, value)
	}
	return value, nil
}

// applied is the snapshot the file would give after e.
func (f *fakeBackend) applied(base Snapshot, e Edits) Snapshot {
	f.token++
	out := Snapshot{Token: f.token, Keys: map[string]KeyState{}, Settings: map[string]Value{}, Skip: base.Skip}
	maps.Copy(out.Keys, base.Keys)
	maps.Copy(out.Settings, base.Settings)
	for k, v := range e.Set {
		if name, ok := strings.CutPrefix(k, KeyPrefix); ok {
			out.Keys[name] = KeyState{Value: config.Secret(v)}
			continue
		}
		cur := out.Settings[k]
		cur.Text, cur.Set, cur.Problem = v, true, ""
		out.Settings[k] = cur
	}
	for _, k := range e.Clear {
		if name, ok := strings.CutPrefix(k, KeyPrefix); ok {
			out.Keys[name] = KeyState{}
			continue
		}
		cur := out.Settings[k]
		cur.Text, cur.Set, cur.Problem = "", false, ""
		out.Settings[k] = cur
	}
	for name, rec := range e.Records {
		if ks := out.Keys[name]; ks.Value != "" {
			ks.Record = &rec
			out.Keys[name] = ks
		}
	}
	if e.Skip != nil {
		out.Skip = e.Skip
	} else {
		out.SkipProblems, out.SkipListProblem = base.SkipProblems, base.SkipListProblem
	}
	return out
}

func (f *fakeBackend) Save(snap Snapshot, e Edits) (Snapshot, error) {
	f.mu.Lock()
	f.saves = append(f.saves, e)
	f.saveSnaps = append(f.saveSnaps, snap)
	fn := f.saveFn
	f.mu.Unlock()
	if fn != nil {
		return fn(snap, e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied(snap, e), nil
}

func (f *fakeBackend) Overwrite(e Edits) (Snapshot, error) {
	f.mu.Lock()
	f.overs = append(f.overs, e)
	fn := f.overFn
	f.mu.Unlock()
	if fn != nil {
		return fn(e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied(f.snap, e), nil
}

func (f *fakeBackend) Test(ctx context.Context, source string, key config.Secret) TestResult {
	f.mu.Lock()
	f.tests = append(f.tests, testCall{source, key.Reveal()})
	fn := f.testFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, source, key)
	}
	return TestResult{Status: TestAccepted}
}

func (f *fakeBackend) ThreatData() []ThreatList {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.threat)
}

func (f *fakeBackend) UpdateThreatData(ctx context.Context) ThreatResult {
	f.mu.Lock()
	f.updates++
	fn := f.updateFn
	f.mu.Unlock()
	var res ThreatResult
	if fn != nil {
		res = fn(ctx)
	}
	if res.Lists != nil {
		f.mu.Lock()
		f.threat = f.threat[:0:0]
		for _, l := range res.Lists {
			f.threat = append(f.threat, l.ThreatList)
		}
		f.mu.Unlock()
	}
	return res
}

// updateCount is how many times UpdateThreatData was called.
func (f *fakeBackend) updateCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.updates
}

func (f *fakeBackend) counts() (saves, overs, opens int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.saves), len(f.overs), f.opens
}

// th drives a model the way the Program would, and keeps every frame.
type th struct {
	t       *testing.T
	b       *fakeBackend
	m       *model
	frames  []string
	mu      sync.Mutex
	secrets []string
	cancel  context.CancelFunc
}

type thOpt func(*Options)

func atSize(w, h int) thOpt { return func(o *Options) { o.Width, o.Height = w, h } }

func newTH(t *testing.T, b *fakeBackend, opts ...thOpt) *th {
	t.Helper()
	h := &th{t: t, b: b}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.cancel = cancel
	o := Options{Width: 80, Height: 24, OnSecret: func(v string) {
		h.mu.Lock()
		h.secrets = append(h.secrets, v)
		h.mu.Unlock()
	}}
	for _, opt := range opts {
		opt(&o)
	}
	m, err := newModel(ctx, b, o)
	if err != nil {
		t.Fatalf("newModel: %v", err)
	}
	h.m = m
	h.snap()
	return h
}

func (h *th) snap() string {
	f := h.m.view()
	h.frames = append(h.frames, f)
	return f
}

// kp turns a key name into the message Bubble Tea sends for it.
func kp(s string) tea.KeyPressMsg {
	switch s {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	case "shift+tab":
		return tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "left":
		return tea.KeyPressMsg{Code: tea.KeyLeft}
	case "right":
		return tea.KeyPressMsg{Code: tea.KeyRight}
	case "home":
		return tea.KeyPressMsg{Code: tea.KeyHome}
	case "end":
		return tea.KeyPressMsg{Code: tea.KeyEnd}
	case "delete":
		return tea.KeyPressMsg{Code: tea.KeyDelete}
	case "backspace":
		return tea.KeyPressMsg{Code: tea.KeyBackspace}
	case "space":
		return tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
	case "ctrl+s":
		return tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl}
	case "ctrl+c":
		return tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}
	case "ctrl+u":
		return tea.KeyPressMsg{Code: 'u', Mod: tea.ModCtrl}
	case "ctrl+a":
		return tea.KeyPressMsg{Code: 'a', Mod: tea.ModCtrl}
	case "ctrl+e":
		return tea.KeyPressMsg{Code: 'e', Mod: tea.ModCtrl}
	}
	r := []rune(s)
	if len(r) != 1 {
		panic("kp: unknown key " + s)
	}
	return tea.KeyPressMsg{Code: r[0], Text: s}
}

// press sends each key and returns the last command.
func (h *th) press(keys ...string) tea.Cmd {
	h.t.Helper()
	var cmd tea.Cmd
	for _, k := range keys {
		cmd = h.m.update(kp(k))
		h.snap()
	}
	return cmd
}

// typ types text one rune at a time.
func (h *th) typ(text string) {
	h.t.Helper()
	for _, r := range text {
		h.m.update(tea.KeyPressMsg{Code: r, Text: string(r)})
		h.snap()
	}
}

func (h *th) paste(text string) {
	h.t.Helper()
	h.m.update(tea.PasteMsg{Content: text})
	h.snap()
}

// send delivers a message and records the frame.
func (h *th) send(msg tea.Msg) tea.Cmd {
	h.t.Helper()
	cmd := h.m.update(msg)
	h.snap()
	return cmd
}

// run executes a command and delivers its message.
func (h *th) run(cmd tea.Cmd) {
	h.t.Helper()
	if cmd == nil {
		h.t.Fatal("no command to run")
	}
	h.send(cmd())
}

func (h *th) view() string { return h.m.view() }

// goTo puts the selection on row i of a tab (0 keys, 1 settings, 2 skip).
func (h *th) goTo(tab, row int) {
	h.t.Helper()
	for range 3 {
		if h.m.tab == tabID(tab) {
			break
		}
		h.press("tab")
	}
	for range 60 {
		h.press("up")
	}
	for range row {
		h.press("down")
	}
}

// lineFor is the first frame line whose first word, past the row marks, is name.
func lineFor(frame, name string) string {
	for l := range strings.SplitSeq(frame, "\n") {
		f := strings.Fields(strings.TrimLeft(l, ">* "))
		if len(f) > 0 && f[0] == name {
			return l
		}
	}
	return ""
}

func mustHave(t *testing.T, frame string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(frame, s) {
			t.Errorf("frame lacks %q:\n%s", s, frame)
		}
	}
}

func mustNotHave(t *testing.T, frame string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if s != "" && strings.Contains(frame, s) {
			t.Errorf("frame has %q:\n%s", s, frame)
		}
	}
}

// windows are the 5-rune pieces of key, every one of which is more than its last four characters.
func windows(key string) []string {
	r := []rune(key)
	var out []string
	for i := 0; i+5 <= len(r); i++ {
		out = append(out, string(r[i:i+5]))
	}
	return out
}

// noKeyIn fails when any piece of key longer than its last four characters is in text.
func noKeyIn(t *testing.T, what, text string, keys ...string) {
	t.Helper()
	for _, k := range keys {
		for _, w := range windows(k) {
			if strings.Contains(text, w) {
				t.Errorf("%s holds %q of a key", what, w)
				return
			}
		}
	}
}

func maxWidth(frame string) int {
	w := 0
	for l := range strings.SplitSeq(frame, "\n") {
		w = max(w, layout.Measure(l))
	}
	return w
}

func lineCount(frame string) int { return strings.Count(frame, "\n") + 1 }

type errTest string

func (e errTest) Error() string { return string(e) }

func sprintf(verb string, v any) string { return fmt.Sprintf(verb, v) }

// lineWith is the first frame line holding sub.
func lineWith(frame, sub string) string {
	for l := range strings.SplitSeq(frame, "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	return ""
}

func windowSize(w, h int) tea.WindowSizeMsg { return tea.WindowSizeMsg{Width: w, Height: h} }

// nth is element i of the calls f recorded to method, read under f's lock.
func nth[T any](t *testing.T, f *fakeBackend, calls *[]T, i int, method string) T {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if i >= len(*calls) {
		t.Fatalf("%s was called %d times, want at least %d", method, len(*calls), i+1)
	}
	return (*calls)[i]
}

func (f *fakeBackend) save(t *testing.T, i int) Edits {
	t.Helper()
	return nth(t, f, &f.saves, i, "Save")
}
func (f *fakeBackend) saveSnap(t *testing.T, i int) Snapshot {
	t.Helper()
	return nth(t, f, &f.saveSnaps, i, "Save")
}
func (f *fakeBackend) over(t *testing.T, i int) Edits {
	t.Helper()
	return nth(t, f, &f.overs, i, "Overwrite")
}
func (f *fakeBackend) check(t *testing.T, i int) string {
	t.Helper()
	return nth(t, f, &f.checks, i, "Check")
}
func (f *fakeBackend) testCall(t *testing.T, i int) testCall {
	t.Helper()
	return nth(t, f, &f.tests, i, "Test")
}

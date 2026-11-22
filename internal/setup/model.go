package setup

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"charm.land/bubbles/v2/help"
	tea "charm.land/bubbletea/v2"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// The smallest terminal the UI draws in.
const (
	minWidth  = 60
	minHeight = 16
)

// defaultTestTimeout is how long a key test may take.
const defaultTestTimeout = 15 * time.Second

type tabID int

// The tabs, in the order they are shown.
const (
	tabKeys tabID = iota
	tabSettings
	tabSkip
	tabCount
)

type mode int

// What the keyboard is doing.
const (
	modeBrowse mode = iota
	modeEdit
	modeQuit
	modeConflict
)

// keyRow is one key source on the Keys tab.
type keyRow struct {
	src         Source
	orig, cur   config.Secret
	origProblem string
	problem     string
	// gen is the edit generation: it changes whenever the key does, and a test result carries the
	// one it was started with.
	gen    int
	cancel context.CancelFunc // set while a test runs
	result *TestResult
}

func (r *keyRow) changed() bool {
	return r.cur != r.orig || (r.origProblem != "" && r.problem == "")
}

// testing reports whether a test of the key is running.
func (r *keyRow) testing() bool { return r.cancel != nil }

// settingRow is one setting on the Settings tab.
type settingRow struct {
	key     string
	orig    Value
	text    string
	set     bool
	problem string
}

func (r *settingRow) changed() bool {
	return r.set != r.orig.Set || r.text != r.orig.Text || (r.orig.Problem != "" && r.problem == "")
}

// relative is the line that says a path resolves against the directory nyx runs from. It belongs to
// the value the file holds, so an edited row has none.
func (r *settingRow) relative() string {
	if r.set == r.orig.Set && r.text == r.orig.Text {
		return r.orig.Relative
	}
	return ""
}

// skipState is the skip list being edited.
type skipState struct {
	on       []string // the skippable stages the list holds, in file order, then those toggled on
	problems []SkipProblem
	list     string // a problem with the list as a whole

	origOn       []string
	origProblems []SkipProblem
	origList     string
}

func (s *skipState) changed() bool {
	if len(s.on) != len(s.origOn) || len(s.problems) != len(s.origProblems) {
		return true
	}
	for _, name := range s.on {
		if !slices.Contains(s.origOn, name) {
			return true
		}
	}
	return s.origList != "" && s.list == ""
}

func (s *skipState) toggle(name string) {
	if i := slices.Index(s.on, name); i >= 0 {
		s.on = slices.Delete(s.on, i, i+1)
	} else {
		s.on = append(s.on, name)
	}
	s.list = ""
}

// entries is the whole list to write: the entries left in place in file order, those that are
// problems after the stages, then the stages toggled on.
func (s *skipState) entries() []string {
	out := []string{}
	for _, name := range s.on {
		if slices.Contains(s.origOn, name) {
			out = append(out, name)
		}
	}
	for _, p := range s.problems {
		out = append(out, p.Entry)
	}
	for _, name := range s.on {
		if !slices.Contains(s.origOn, name) {
			out = append(out, name)
		}
	}
	return out
}

// editState is a field being edited.
type editState struct {
	tab tabID
	row int
	f   *field
}

// dialogState is what the conflict dialog says beyond its fixed text.
type dialogState struct {
	thenQuit bool     // the save that met the conflict was asked for by the quit dialog
	path     string   // the file the problems are about
	problems []string // what a reload found
}

// model is the state of nyx setup. It holds keys as config.Secret, and formats without any state.
type model struct {
	b       Backend
	o       Options
	info    Info
	snap    Snapshot
	base    context.Context
	stop    context.CancelFunc
	timeout time.Duration
	genSeq  int

	keys []*keyRow
	sets []*settingRow
	skip skipState

	tab    tabID
	sel    [tabCount]int
	top    [tabCount]int
	mode   mode
	ed     *editState
	dlg    dialogState
	notice []string

	width, height int
	quitting      bool

	// seen holds every key the file held or the user typed, so no text of any kind can carry one.
	seen   []config.Secret
	typing config.Secret
	// red is the redactor scrub last built, for the first redSeen of seen and redTyping: seen only
	// grows, so the two say when it is stale.
	red       *config.Redactor
	redSeen   int
	redTyping config.Secret
	help      help.Model
}

// Format prints nothing of the state: the model holds keys.
func (m model) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "setup.model{}")
}

// newModel opens the file through b and builds the model from it. ctx ends any key test running.
func newModel(ctx context.Context, b Backend, o Options) (*model, error) {
	snap, err := b.Open()
	if err != nil {
		return nil, err
	}
	m := &model{b: b, o: o, width: o.Width, height: o.Height, timeout: cmp.Or(o.TestTimeout, defaultTestTimeout)}
	m.base, m.stop = context.WithCancel(ctx)
	m.info = b.Info()
	m.info.Path = sanitize.Line(m.info.Path)
	m.info.Sources = slices.Clone(m.info.Sources)
	for i, s := range m.info.Sources {
		m.info.Sources[i].Turns = sanitize.Line(s.Turns)
	}
	m.info.Stages = slices.Clone(m.info.Stages)
	for i, s := range m.info.Stages {
		m.info.Stages[i].Does = sanitize.Line(s.Does)
	}
	m.help = newHelp()
	m.load(snap, false)
	return m, nil
}

// secret registers a key with the caller and with the model's own scrubbing.
func (m *model) secret(v config.Secret) {
	if strings.TrimSpace(v.Reveal()) == "" {
		return
	}
	if !slices.Contains(m.seen, v) {
		m.seen = append(m.seen, v)
	}
	if m.o.OnSecret != nil {
		m.o.OnSecret(v.Reveal())
	}
}

// scrub removes every key the model has seen from s.
func (m *model) scrub(s string) string {
	if m.red == nil || m.redSeen != len(m.seen) || m.redTyping != m.typing {
		vals := make([]string, 0, len(m.seen)+1)
		for _, v := range m.seen {
			vals = append(vals, v.Reveal())
		}
		vals = append(vals, m.typing.Reveal())
		// The longest first, so a key is masked whole before a shorter one inside it can split it.
		slices.SortFunc(vals, func(a, b string) int { return len(b) - len(a) })
		m.red, m.redSeen, m.redTyping = config.NewRedactor(vals...), len(m.seen), m.typing
	}
	return m.red.Redact(s)
}

// text is s made safe to draw: no key in it and no terminal control, on one line.
func (m *model) text(s string) string { return sanitize.Line(m.scrub(s)) }

// load makes snap the baseline, discarding the edits. A key's test state is kept when keep is set
// and the key is the one the test was for.
func (m *model) load(snap Snapshot, keep bool) {
	old := m.keys
	m.snap = snap
	m.keys = make([]*keyRow, 0, len(m.info.Sources))
	for _, src := range m.info.Sources {
		ks := snap.Keys[src.Name]
		m.secret(ks.Value)
		row := &keyRow{src: src, orig: ks.Value, cur: ks.Value, origProblem: ks.Problem, problem: ks.Problem}
		m.genSeq++
		row.gen = m.genSeq
		if prev := findKey(old, src.Name); prev != nil {
			if keep && prev.cur == row.cur {
				row.gen, row.cancel, row.result = prev.gen, prev.cancel, prev.result
			} else {
				prev.abandon()
			}
		}
		m.keys = append(m.keys, row)
	}
	m.sets = make([]*settingRow, 0, len(SettingKeys))
	for _, k := range SettingKeys {
		v := snap.Settings[k]
		m.sets = append(m.sets, &settingRow{key: k, orig: v, text: v.Text, set: v.Set, problem: v.Problem})
	}
	m.skip = skipState{
		on: slices.Clone(snap.Skip), problems: slices.Clone(snap.SkipProblems), list: snap.SkipListProblem,
		origOn: slices.Clone(snap.Skip), origProblems: slices.Clone(snap.SkipProblems), origList: snap.SkipListProblem,
	}
	m.ed, m.mode = nil, modeBrowse
	m.typing = ""
	m.fixScroll()
}

func findKey(rows []*keyRow, name string) *keyRow {
	for _, r := range rows {
		if r.src.Name == name {
			return r
		}
	}
	return nil
}

// abandon ends a running test of the row.
func (r *keyRow) abandon() {
	if r.cancel != nil {
		r.cancel()
	}
	r.cancel, r.result = nil, nil
}

// changes is the number of fields with unsaved changes. The skip list is one field.
func (m *model) changes() int {
	n := 0
	for _, r := range m.keys {
		if r.changed() {
			n++
		}
	}
	for _, r := range m.sets {
		if r.changed() {
			n++
		}
	}
	if m.skip.changed() {
		n++
	}
	return n
}

// tabChanged reports whether a tab holds an unsaved change.
func (m *model) tabChanged(t tabID) bool {
	switch t {
	case tabKeys:
		return slices.ContainsFunc(m.keys, (*keyRow).changed)
	case tabSettings:
		return slices.ContainsFunc(m.sets, (*settingRow).changed)
	case tabCount:
	case tabSkip:
		return m.skip.changed()
	}
	return false
}

// invalid is the first message of an invalid value on a tab, and whether the tab has one.
func (m *model) invalid(t tabID) (string, bool) {
	named := func(name, msg string) string {
		if strings.HasPrefix(msg, name) {
			return msg
		}
		return name + ": " + msg
	}
	switch t {
	case tabKeys:
		for _, r := range m.keys {
			if r.problem != "" {
				return named(r.src.Name, r.problem), true
			}
		}
	case tabSettings:
		for _, r := range m.sets {
			if r.problem != "" {
				return named(r.key, r.problem), true
			}
		}
	case tabSkip:
		if len(m.skip.problems) > 0 {
			p := m.skip.problems[0]
			return "skip: " + p.Entry + ": " + p.Message, true
		}
		if m.skip.list != "" {
			return "skip: " + m.skip.list, true
		}
	case tabCount:
	}
	return "", false
}

// edits are the changes to write.
func (m *model) edits() Edits {
	var e Edits
	set := func(k, v string) {
		if e.Set == nil {
			e.Set = map[string]string{}
		}
		e.Set[k] = v
	}
	for _, r := range m.keys {
		switch {
		case !r.changed():
		case r.cur != "":
			set(KeyPrefix+r.src.Name, r.cur.Reveal())
		default:
			e.Clear = append(e.Clear, KeyPrefix+r.src.Name)
		}
	}
	for _, r := range m.sets {
		switch {
		case !r.changed():
		case r.set:
			set(r.key, r.text)
		default:
			e.Clear = append(e.Clear, r.key)
		}
	}
	if m.skip.changed() {
		e.Skip = m.skip.entries()
	}
	return e
}

// say sets the notice: at most two lines under the body.
func (m *model) say(lines ...string) {
	m.notice = nil
	for _, l := range lines {
		m.notice = append(m.notice, m.text(l))
	}
}

// quit ends the program, and any key test with it.
func (m *model) quit() tea.Cmd {
	m.quitting = true
	m.stop()
	return tea.Quit
}

// update handles one message.
func (m *model) update(msg tea.Msg) tea.Cmd {
	defer m.fixScroll()
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyPressMsg:
		return m.onKey(msg)
	case tea.PasteMsg:
		m.onPaste(msg.Content)
	case testDone:
		m.onTestDone(msg)
	}
	return nil
}

func (m *model) onKey(k tea.KeyPressMsg) tea.Cmd {
	m.notice = nil
	switch m.mode {
	case modeEdit:
		return m.editKey(k)
	case modeQuit:
		return m.quitKey(k)
	case modeConflict:
		return m.conflictKey(k)
	case modeBrowse:
	}
	return m.browseKey(k.String())
}

func (m *model) browseKey(s string) tea.Cmd {
	switch s {
	case "q", "esc", "ctrl+c":
		return m.askQuit()
	case "ctrl+s":
		return m.save(false)
	case "tab":
		m.tab = (m.tab + 1) % tabCount
	case "shift+tab":
		m.tab = (m.tab + tabCount - 1) % tabCount
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "pgup":
		m.move(-5)
	case "pgdown":
		m.move(5)
	case "enter":
		m.activate()
	case "space":
		if m.tab == tabSkip {
			m.activate()
		}
	case "t":
		if m.tab == tabKeys {
			return m.startTest()
		}
	case "x", "delete":
		m.clearRow()
	}
	return nil
}

// rows is the number of selectable rows on a tab.
func (m *model) rows(t tabID) int {
	switch t {
	case tabKeys:
		return len(m.keys)
	case tabSettings:
		return len(m.sets)
	case tabSkip:
		n := len(m.info.Stages) + len(m.skip.problems)
		if m.skip.list != "" {
			n++
		}
		return n
	case tabCount:
	}
	return 0
}

func (m *model) move(d int) {
	n := m.rows(m.tab)
	m.sel[m.tab] = max(0, min(m.sel[m.tab]+d, n-1))
}

// activate is enter on the selected row.
func (m *model) activate() {
	i := m.sel[m.tab]
	switch m.tab {
	case tabKeys:
		m.ed = &editState{tab: tabKeys, row: i, f: newField(true, "")}
		m.mode = modeEdit
	case tabSettings:
		m.ed = &editState{tab: tabSettings, row: i, f: newField(false, m.sets[i].text)}
		m.mode = modeEdit
	case tabSkip:
		if i < len(m.info.Stages) {
			m.skip.toggle(m.info.Stages[i].Name)
		} else {
			m.say("x removes this entry")
		}
	case tabCount:
	}
}

// clearRow is x or delete on the selected row.
func (m *model) clearRow() {
	i := m.sel[m.tab]
	switch m.tab {
	case tabKeys:
		m.setKey(m.keys[i], "")
	case tabSettings:
		r := m.sets[i]
		r.text, r.set, r.problem = "", false, ""
	case tabSkip:
		m.clearSkip(i)
	case tabCount:
	}
}

// clearSkip removes the problem entry at row i, clears the whole-list problem, or turns a stage off.
func (m *model) clearSkip(i int) {
	stages := len(m.info.Stages)
	switch {
	case i < stages:
		if name := m.info.Stages[i].Name; slices.Contains(m.skip.on, name) {
			m.skip.toggle(name)
		}
	case i < stages+len(m.skip.problems):
		m.skip.problems = slices.Delete(m.skip.problems, i-stages, i-stages+1)
	default:
		m.skip.list = ""
	}
	m.move(0)
}

// setKey makes v the row's key. A key that changes ends the test of the old one and drops its result.
func (m *model) setKey(r *keyRow, v config.Secret) {
	if v != r.cur {
		r.abandon()
		m.genSeq++
		r.gen = m.genSeq
	}
	r.cur, r.problem = v, ""
}

// typedText is the text a key press types, or "" when it is a command.
func typedText(k tea.KeyPressMsg) string {
	key := k.Key()
	if key.Mod&(tea.ModCtrl|tea.ModAlt) != 0 || key.Text == "" {
		return ""
	}
	if strings.ContainsFunc(key.Text, unicode.IsControl) {
		return ""
	}
	return key.Text
}

func (m *model) editKey(k tea.KeyPressMsg) tea.Cmd {
	f := m.ed.f
	if txt := typedText(k); txt != "" {
		f.insert(txt)
		m.typed()
		return nil
	}
	switch name := k.String(); name {
	case "enter":
		m.accept()
	case "esc":
		m.endEdit()
	case "ctrl+c":
		m.endEdit()
		return m.askQuit()
	default:
		if f.press(name) {
			m.typed()
		}
	}
	return nil
}

func (m *model) onPaste(content string) {
	if m.mode != modeEdit {
		return
	}
	if !utf8.ValidString(content) {
		m.say("the pasted text is not valid UTF-8")
		return
	}
	m.ed.f.insert(content)
	m.typed()
}

// typed notes what is in a key field after every change, so a panic cannot find a key unregistered.
func (m *model) typed() {
	if m.ed.tab != tabKeys {
		return
	}
	v := config.Secret(m.ed.f.text())
	m.typing = v
	if len([]rune(v.Reveal())) >= 4 && strings.TrimSpace(v.Reveal()) != "" && m.o.OnSecret != nil {
		m.o.OnSecret(v.Reveal())
	}
}

func (m *model) endEdit() {
	if m.typing != "" {
		m.secret(m.typing)
	}
	m.typing = ""
	m.ed, m.mode = nil, modeBrowse
}

// accept is enter in a field.
func (m *model) accept() {
	raw := strings.TrimSpace(m.ed.f.text())
	i := m.ed.row
	if m.ed.tab == tabKeys {
		v := config.Secret(raw)
		m.secret(v)
		m.setKey(m.keys[i], v)
		m.endEdit()
		return
	}
	r := m.sets[i]
	if raw == "" {
		r.text, r.set, r.problem = "", false, ""
		m.endEdit()
		return
	}
	val, err := m.b.Check(r.key, raw)
	if err != nil {
		m.say(err.Error())
		return
	}
	r.text, r.set, r.problem = val, true, ""
	m.endEdit()
}

// startTest starts a test of the selected key.
func (m *model) startTest() tea.Cmd {
	r := m.keys[m.sel[tabKeys]]
	switch {
	case r.testing():
		return nil
	case r.cur == "":
		m.say("there is no key to test: enter one first")
		return nil
	}
	ctx, cancel := context.WithTimeout(m.base, m.timeout)
	r.cancel, r.result = cancel, nil
	name, gen, key, b := r.src.Name, r.gen, r.cur, m.b
	return func() tea.Msg { // root.Update makes it safe
		defer cancel()
		res := b.Test(ctx, name, key)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			res = TestResult{Status: TestUnknown, Reason: "timed out"}
		}
		return testDone{source: name, gen: gen, res: res}
	}
}

// testDone is the end of a key test.
type testDone struct {
	source string
	gen    int
	res    TestResult
}

func (m *model) onTestDone(d testDone) {
	r := findKey(m.keys, d.source)
	if r == nil || r.gen != d.gen {
		return
	}
	res := d.res
	res.Reason = m.text(res.Reason)
	r.cancel, r.result = nil, &res
}

// askQuit is q, esc or ctrl+c.
func (m *model) askQuit() tea.Cmd {
	if m.changes() == 0 {
		return m.quit()
	}
	m.mode = modeQuit
	return nil
}

func (m *model) quitKey(k tea.KeyPressMsg) tea.Cmd {
	switch k.String() {
	case "s":
		return m.save(true)
	case "d":
		return m.quit()
	case "esc":
		m.mode = modeBrowse
	}
	return nil
}

// save writes the edits. thenQuit asks to quit once they are written.
func (m *model) save(thenQuit bool) tea.Cmd {
	if why, bad := m.firstInvalid(); bad {
		m.say("cannot save while a value is invalid:", why)
		return nil
	}
	e := m.edits()
	if e.Empty() {
		m.say("no changes to save")
		return nil
	}
	snap, err := m.b.Save(m.snap, e)
	return m.saved(snap, err, thenQuit)
}

func (m *model) firstInvalid() (string, bool) {
	for t := range tabCount {
		if why, bad := m.invalid(t); bad {
			return why, true
		}
	}
	return "", false
}

// saved is what follows a Save or an Overwrite.
func (m *model) saved(snap Snapshot, err error, thenQuit bool) tea.Cmd {
	switch {
	case err == nil:
		m.load(snap, true)
		if thenQuit {
			return m.quit()
		}
		m.say("saved " + m.info.Path)
	case errors.Is(err, ErrConflict):
		m.dlg = dialogState{thenQuit: thenQuit}
		m.mode = modeConflict
	default:
		m.mode = modeBrowse
		m.say("could not save: "+err.Error(), "file: "+m.info.Path)
	}
	return nil
}

func (m *model) conflictKey(k tea.KeyPressMsg) tea.Cmd {
	switch k.String() {
	case "r":
		m.reload()
	case "o":
		snap, err := m.b.Overwrite(m.edits())
		return m.saved(snap, err, m.dlg.thenQuit)
	case "esc":
		m.mode = modeBrowse
	}
	return nil
}

// reload reads the file again and drops the edits. A file with problems keeps them.
func (m *model) reload() {
	snap, err := m.b.Open()
	var fe *FileError
	switch {
	case errors.As(err, &fe):
		m.dlg.path, m.dlg.problems = fe.Path, fe.Problems
	case err != nil:
		m.dlg.path, m.dlg.problems = m.info.Path, []string{err.Error()}
	default:
		m.load(snap, false)
		m.say("reloaded " + m.info.Path)
	}
}

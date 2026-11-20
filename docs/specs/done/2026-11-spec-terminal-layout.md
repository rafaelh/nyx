# Spec: richer human output layout on a terminal

## Goal

When a person reads nyx's human output on a terminal (the recon summary, log lines, `nyx cve`
records and help), it is easier to scan: aligned tables, distinct headings, text wrapped to the
terminal and, where colour is on, colour on the parts that carry meaning. Output to anything that
isn't a terminal stays byte-for-byte as today, so scripts, saved logs and `--json` are unaffected.

Done when, at 80 columns, every summary table, CVE record and help screen fits the width under
the fit rule (B3) and its columns line up, and a log line longer than 80 cells wraps under the
message column.

Constraint: today's colour detection and exact palette escape sequences must still hold (B1, B4).
The layout is nyx's own code, not lipgloss: lipgloss cannot write the palette's exact sequences,
and importing it runs `tmux info` at startup (see D1). (amended by D1)

Amends, on a terminal only:

- **The log-colours spec:**
  - B6 and D14: no colour inside stage and found messages besides the severity badge;
  - B8 and D15: no colour in the summary besides badges, and no colour on any heading;
  - B13: lines are never wrapped;
  - its Out of scope bullet on coloured stage state words.
- **The CVE lookup spec:** its human layout (the header line, field layout, byte-identical output
  at depth None) and its width rule.

## Behaviours

B1. **Only terminals change.** A stream that is not a terminal gets byte-for-byte what nyx writes
    today, for every command. That covers the summary, log lines, CVE records, help, the `error:`
    line and the palette sheet. The JSON nyx writes under `--json` is unchanged everywhere. On a
    terminal, the layout of B2, B3 and B5 to B20 applies. Whether a terminal stream is coloured,
    and at what depth, is decided by today's rules, unchanged. On a terminal with colour off
    (`NO_COLOR` set, or `TERM=dumb`), the layout still applies and no escape byte is written. The
    authorisation prompt and the `error:` line are unchanged on a terminal too. Under `--json`,
    help and the palette sheet are not laid out, even on a terminal: they are byte-for-byte what
    nyx writes today. `--debug` lines on a terminal stderr are log lines and are laid out.
    (amended by D2)

B2. **Width.** Each terminal stream has its own layout width:
    - `COLUMNS`, when it is a positive number;
    - else the stream's own terminal width;
    - else 100.

    The width is never less than 60. Log lines read the width for each line, so a resize mid-run
    applies from the next line.

B3. **Fit.** On a terminal, line width is measured in terminal cells: escape codes count as zero
    and wide characters as two. No line is wider than the layout width, except a line holding one
    of these:
    - a part that never wraps, wider than the space left for it. The parts that never wrap are
      the SEVERITY, CATEGORY, EVIDENCE and PROMOTE cells, and help's usage and example lines;
    - a protected word longer than the space left for it. A protected word is a hostname, an IP
      address or CIDR netblock, an email address, or a URL with a scheme, and is never broken;
    - a table row whose wrapping columns have already shrunk to 10 cells.

    Such a line runs past the width rather than break. Text wraps at spaces, and value lists
    wrap after commas (B9, B16). Any other word longer than the space is broken at the width.
    Each table's column widths are decided once, from all its rows.

B4. **Colours.** Every colour comes from the existing palette at the stream's depth. No colour
    value is added or changed. Colours shown today stay unless a behaviour here changes them, for
    example:
    - help's flag and command names, value types and defaults;
    - the stages topic's contact column;
    - CVE reference URLs and tags.

B5. **Headings.**
    - On a coloured terminal every heading is bold in the palette's info colour. On an
      uncoloured terminal it is plain text. (Help headings are bold today; the colour is new.)
    - A heading wider than the layout width wraps at spaces. Its continuation lines take the
      heading style and start at the heading's own column.
    - In the summary, each heading also has a horizontal rule beneath its last line. The rule
      spans the layout width. On a coloured terminal it is `─` in the log line's separator
      colour. On an uncoloured terminal it is `-`, with no colour. (amended by D3)

B6. **Tables.** There are five tables: the two summary findings tables (B8), the summary
    candidates table (B9), and the findings and stages help-topic tables (B18, B19). No other
    block is a table.
    - **Header row.** Every table has one, bold, and in the log line's timestamp colour on a
      coloured terminal.
    - **Summary tables** keep the summary's two-space indent, have no borders, and separate
      their columns with two spaces.
    - **Help-topic tables** have borders, and a border with one space either side separates
      their columns. The borders are box-drawing characters on a coloured terminal and ASCII
      (`-`, `|`, `+`) on an uncoloured one. (amended by D3)
    - **Empty tables.** A table with no rows is not shown, heading included, as today.

B7. **Summary counts.** Each block of counts keeps its labels and heading text, with no header
    row. The blocks are the record counts, failed checks, deferred checks and "Since last run".
    Within each block, the numbers are right-aligned in one column.

B8. **Summary findings table.** "Findings (high and medium)" and "New findings (high and medium)"
    become tables with the columns SEVERITY, CATEGORY, TARGET and DETAIL.
    - Severity is the badge, and rows keep their order, both as today.
    - DETAIL is left out when no row has one. An empty detail counts as none.
    - When the table is too wide, DETAIL wraps within its column first, then TARGET. Both wrap
      only at spaces, and never inside a protected word (B3).

B9. **Summary candidates table.** "Candidates worth promoting (high confidence)" keeps its
    heading text and becomes a table with the columns VALUE, EVIDENCE, SOURCES and PROMOTE.
    - EVIDENCE is the evidence count alone.
    - SOURCES lists the sources separated by `, `.
    - PROMOTE is the input alone, without `promote:`.
    - When the table is too wide, SOURCES wraps first, after commas, then VALUE, at spaces only.
    - "and N more in candidates.csv" stays beneath the table.

B10. **Other summary lines.** The unconfirmed-risky-ports line, the notes and the deadline line
     keep their text. They wrap to the width, with continuation lines indented under the text.

B11. **CVE header bar.** Each record starts with a bar as wide as the layout width, with the CVE
     ID at the left and the severity label at the right.
     - On a coloured terminal the bar takes the severity's badge style.
     - A missing severity reads UNKNOWN. A value the palette doesn't know, such as NONE, keeps
       its own text. Both take the DEBUG style.
     - When `cvss_severity` isn't selected, the bar holds only the ID, in the DEBUG style.
     - On an uncoloured terminal, the bar is the ID and `[SEVERITY]` at either end of the line.

B12. **CVE sections.**
     - **Headings.** Section headings keep today's names and take the heading style, without a
       rule. A blank line precedes each section, as today.
     - **Fields.** The field labels (Status, Published, Last Modified, Base Score, Vector,
       Version, Source) have no colon. They are indented two spaces, and bold where colour is
       on. Within a section, the values start at one column, two spaces after the longest label.
     - **Text.** The description, bullets and references are indented two spaces and wrap to the
       width, with continuation lines under their text.
     - **Spacing.** Records are separated by one blank line, as today.

B13. **Log line wrapping.** A message wider than the space after the timestamp and level wraps
     as B3 says. Each continuation line is indented to the message column: 19 cells uncoloured,
     21 coloured, as in the log-colours spec's B2. This includes found lines with a badge.

B14. **Stage lines.** On a coloured terminal, the state word is coloured:

     | State | Colour |
     |---|---|
     | running | info |
     | done, done-previously | success |
     | failed | error |
     | not-configured | the timestamp colour |

     The stage name, reason and counts stay uncoloured. The level badge reads INFO for running,
     done and not-configured alike, so the colour adds the distinction.

B15. **Found lines.** On a coloured terminal, the `+` takes the success colour. In a line of the
     form `category: value`, the category takes the info colour. A found line not in that form
     colours only the `+`. Severity badges are unchanged.

B16. **Help wrapping.**
     - Flag and command descriptions wrap to the width, with continuation lines aligned under the
       description column.
     - Description paragraphs and footers re-flow to the width, ignoring today's hard line breaks
       within a paragraph. A paragraph is the lines between blank lines. The footers include
       recon's "Configuration:" footer and the topic footers.
     - Value-list lines wrap after commas, with continuation lines indented under the text after
       the label. These are the `… accepted by …:` lines, `Stages --skip refuses:` and
       `Exit codes:`.
     - Usage and example lines never wrap.

B17. **Help headings.** Section headings (Usage:, Flags:, Shared flags:, Examples:, Commands:, …)
     take the heading style.

B18. **Findings help topic.** Its severity table is a bordered table (B6) with the columns
     CATEGORY, TYPE, SEVERITY and MEANING. Severities are badges, as today. MEANING wraps within
     its column.

B19. **Stages help topic.** Its table is a bordered table (B6). WHAT IT DOES wraps within its
     column. The contact column keeps today's colours.

B20. **Palette sheet.** On a terminal, `nyx recon --palette` also shows:
     - a heading;
     - a sample findings table;
     - a CVE header bar for each severity, plus UNKNOWN and an unknown value (NONE);
     - a stage line for each state;
     - a found line;
     - a log line longer than the layout width.

B21. **Sanitising and secrets.** Text from a target or from the NVD is sanitised, and configured
     keys are redacted, before it is laid out, as today. No layout can emit a terminal control
     sequence from that text. No configured key appears in the output, whole or in part.

B22. **Docs.** The README describes the terminal layout:
     - messages wrap on a terminal (it no longer says they are never wrapped);
     - the tables;
     - the coloured state words;
     - B2's width rule.

     For `nyx cve` output that isn't a terminal, it keeps today's width rule (`COLUMNS`, default
     100, at least 60). Help text changes only as B16 to B19 lay it out.

## Out of scope

- The JSON written under `--json`, `nyx recon export`, and the CSV/TXT files.
- Output to a stream that is not a terminal (B1).
- The colour detection rules and colour values.
- The `error:` line and the authorisation prompt.
- Interactive UI such as spinners and progress bars.

# Design

Decided 2026-11-20. D1, D2 and D3 are the user's answers (D1 in two rounds: first dropping
lipgloss, then choosing `x/text/width` over `x/ansi` after the review). The rest follow from the
spec and the code. An adversarial review changed D7, D9, D11, D13, D14, D17 and D18, and added
the test rewrites in `## Tests`.

## External facts

- **lipgloss v2 resets with `ESC[m`.** *Confirmed live* (v2.1.0, a probe program):
  `Style.Foreground(…).Background(…).Render` gives `ESC[38;2;…;48;2;…m … ESC[m`. The palette and
  its tests use `ESC[0m`. lipgloss's `ansi.BasicColor(12)` gives `94` and `ANSIColor(12)` gives
  `38;5;12`.
- **Importing lipgloss v2 runs `tmux info`.** *Confirmed live* (v2.1.0, under a pseudo-terminal
  with a fake `tmux` on `PATH`): `writer.go` declares `var Writer = colorprofile.NewWriter(os.Stdout,
  os.Environ())` at package level. Importing `lipgloss/v2/table` alone triggers it. When stdout is a
  terminal, `TERM` is not `dumb`, `TMUX` is set and `COLORTERM` is not truecolor,
  `colorprofile.Detect` reads terminfo from disk and runs `tmux info`.
- **lipgloss wraps by breaking words, and its table shrinks columns by its own rule.**
  *Confirmed live*: `Style.Width(10)` turns `foo.example.com` into `foo.exampl` / `e.com`.
  `table.Width(40)` broke words in the widest column.
- **lipgloss's table passes pre-styled cells through unchanged.** *Confirmed live*. This no longer
  matters, because lipgloss is not used (D1).
- **`golang.org/x/text/width`.** *From docs*, and the module is already in `go.mod` (v0.44.0,
  indirect). `width.LookupRune(r).Kind()` returns `EastAsianWide`, `EastAsianFullwidth`,
  `EastAsianAmbiguous`, `EastAsianNarrow`, `EastAsianHalfwidth` or `Neutral`. It has no init-time
  environment read.
- **`x/ansi` and `go-runewidth` read the environment at init.** *Confirmed live*:
  `RUNEWIDTH_EASTASIAN=1` changes `ansi.StringWidth("±§°")` from 3 to 6. Box-drawing characters
  are East Asian Ambiguous. This is why D1 avoids them.
- **`golang.org/x/term.GetSize(fd)`** returns the width and height of a terminal, and an error for
  anything else. *From docs*. `x/term` is already a direct dependency (`IsTerminal`).
- **`net/netip` is not on the egress boundary's forbidden list.** *Confirmed* (read
  `internal/egress/boundary_test.go:72`): the list is exactly `net`, `net/http`, `crypto/tls`,
  `syscall` and `miekg/dns`.

## Decisions

D1. **No lipgloss, and no new module** (user decisions; amends the Goal's constraint). Layout is
    nyx's own code, in a new pure package `internal/layout`. The width of a string in cells is
    measured as follows:
    - strip each `ESC[…m` sequence (the palette writes no other kind, and target text is
      sanitised);
    - East Asian Wide and Fullwidth runes count 2;
    - runes of category Mn or Me, U+200B to U+200D and U+FE00 to U+FE0F count 0;
    - every other rune counts 1, Ambiguous included.

    `golang.org/x/text/width` classifies the runes. It moves to a direct dependency in `go.mod`.
    Emoji sequences may be measured imprecisely; that is accepted.

D2. **Under `--json`, help and the palette sheet are not laid out** (user decision; amends B1).
    `inv.helpStream()` returns a stream with `Terminal` false (and depth None) under `raw.json ||
    sh.json`, and stdout's stream otherwise. It replaces `helpDepth()` everywhere: in the root and
    command help, in the topics (which capture it when the tree is built, as `depth` is captured
    today), and in `--palette` (`recon.go:116`). `--debug` lines follow stderr's stream like
    every other log line.

D3. **Chrome is ASCII when uncoloured** (user decision; amends B5, B6). On a coloured terminal:
    rules are `─`, and table borders are `┌ ─ ┬ ┐ │ ├ ┼ ┤ └ ┴ ┘`. On an uncoloured terminal: `-`
    for rules and horizontal borders, `|` for vertical ones, `+` at every corner and junction. The
    choice follows the stream's depth, like the log line's ` | ` / ` │ `.

D4. **A stream is a terminal, a depth and a width.** `layout.Stream{Terminal bool; Depth
    palette.Depth; Width func() int}`.
    - `cli.Deps` gains `StdoutWidth` and `StderrWidth func() int`. In `DefaultDeps` each is
      `term.GetSize` on the fd, returning 0 on error; nil means 0.
    - `invocation` builds one Stream per output beside `inv.dp`. The terminal flag is
      `StdoutIsTTY()` / `StderrIsTTY()`, the depth is today's `palette.Detect` result, and
      `Width` applies D5 to `Deps.Env`'s `COLUMNS` and the Deps width function.
    - The renderers (`report.Console`, `report.WriteSummary`, `report.Sheet`, `cve.Render`, the
      help) take a `layout.Stream` where they take a `palette.Depth` today.

D5. **Width rule.** `layout.Width(columns string, term int) int`:
    - `COLUMNS` when it parses as a positive integer (after trimming spaces);
    - else `term` when it is positive;
    - else 100;
    - and never less than 60.

    `cve.Width(columns)` becomes `layout.Width(columns, 0)` for the non-terminal path, so B22's rule
    for non-terminals is unchanged. The console calls `Stream.Width()` once per line (B2), and the
    other renderers call it once per write.

D6. **Spans.** `layout.Span{Text string; Style func(string) string; Keep bool}`.
    - Text is plain, already sanitised and redacted.
    - Style is a palette function, and nil means none.
    - A Keep span is one unbreakable token. Badges and the padded stage name are Keep spans.

    Lines are broken first and styled afterwards, part by part, so every escape byte comes from the
    palette and none crosses a line break. A styled run that continues onto the next line is
    closed at the end of one line and opened again on the next.

D7. **Wrap** (review: spaces and `\n`). `layout.Wrap(spans, width, first, rest int, mode) []string`
    lays out text after a prefix `first` cells wide. Continuation lines are indented by `rest`
    spaces, which `Wrap` writes.
    - **Spaces.** Leading indentation and runs of spaces inside a line are kept: `%-14s`, the
      header's double spaces and a count line's indent all survive. Only the single space at
      which a line is broken is consumed.
    - **Line breaks.** `\n` is a hard break; each continuation starts at `rest`.
    - **Modes.**
      - `Spaces` breaks only at spaces: not after hyphens, slashes or other punctuation. This is
        how "wraps only at spaces" in B8 and B9 is read.
      - `Commas` breaks only after `, `. A segment too long for a line falls back to `Spaces`
        within it.
    - **A token longer than the space left.**
      - A protected word (D8) or a Keep span is left whole, and the line runs past the width.
      - Any other word is broken at the width.

D8. **Protected words.** A token is first stripped of surrounding punctuation: `([{<"'` at the
    start and `)]}>"',.;:` at the end. It is then protected when it is:
    - a URL: `scheme://` followed by at least one character, with the scheme `[a-z][a-z0-9+.-]*`;
    - an email address: one `@`, a non-empty local part, and a host that passes the hostname
      test;
    - an IP address or CIDR netblock: `netip.ParseAddr` or `netip.ParsePrefix`;
    - a hostname: at least one dot, and every label passes `dnsname.ValidLabel`, with an optional
      leading `*.`.

    `CVSS:3.1/AV:N/…` is not a URL. `e.g` and version numbers such as `2.4.41` do count as
    hostnames: they are short, so this does no harm, and a test pins it so that nobody changes it
    later.

D9. **Tables** (review: the shrink floor). `layout.Table{Columns []Column; Rows [][]Cell; Indent
    int; Bordered bool}` rendered on a Stream. `Column{Header string; Wrap Mode (None, Spaces,
    Commas); Shrink int}`, where 0 means the column never shrinks and 1 is the first to shrink.
    - **Natural width.** A column's natural width is its widest cell, header included.
    - **Shrinking.** When the table is wider than the stream's width, wrapping columns shrink in
      `Shrink` order, each only as far as needed and no lower than its floor, until it fits. A
      column's floor is the larger of 10 and its widest unbreakable token (a protected word or a
      Keep span). A table that still does not fit runs past the width; B3 allows that.
    - **Fixed widths.** Column widths are decided once, from every row, so the columns line up in
      every row.
    - **Header row.** Bold, in chrome TIMESTAMP when coloured, and plain text otherwise. A header
      wraps like its column.
    - **Unbordered.** Indent, then the columns separated by two spaces, with trailing spaces
      trimmed.
    - **Bordered.** Indent, then a top border, the header row, a border under the header, the
      rows and a bottom border. Columns are separated by `│` with one space either side, and the
      characters follow D3. Borders take chrome SEPARATOR when coloured.
    - **Empty.** A table with no rows renders as "", and the caller writes no heading for it.
    - Cells are left-aligned. No column is right-aligned.

D10. **Two palette functions, no new colour values.**
     - `Depth.BoldText(g Group, name, s)` writes `ESC[1;<fg>m` + s + `ESC[0m`, with fg the entry's
       foreground parameters at the depth. Headings use semantic `info`, and table header rows use
       chrome `TIMESTAMP`.
     - `Depth.BadgeText(c Category, label, text)` writes text, unpadded, in the badge style that
       `label` takes (looked up as `Value` does; DEBUG when unknown).

     At None both return the text unchanged. These and the existing functions are the only places
     that write SGR.

D11. **Log lines: one code path** (review: no second path; the order of redaction).
     - `Console.Emit` builds the message as spans. At depth None every style is the identity.
     - The message is wrapped only when the log stream is a terminal, so a non-terminal line is
       exactly today's line by construction.
     - **Colours** (on a terminal at a colour depth only; elsewhere the styles are identities):
       - the state word: `running` semantic info; `done` and `done-previously` semantic success;
         `failed` semantic error; `not-configured` chrome TIMESTAMP.
       - found lines: the `+` takes semantic success. The category takes semantic info when the
         event has no `text` field, so the line is `category: value`. This is decided from the
         fields, not by parsing the text.
       - The badge is a Keep span on the first line.
     - **Wrapping.** `Line` lays the message out after the prefix: width − 19 cells uncoloured,
       width − 21 coloured, with `rest` at 19 or 21. The sheet's embedded `\n` still gives a
       continuation line (D7).
     - **Redaction.** The console redacts after `str()` has sanitised a field: `ConsoleOptions`
       gains the redactor, and `WithRedactor` stays in front as today. A key that sanitising
       joins back together is then still redacted, and B21 holds for both paths: the summary's
       `cleanText` already sanitises and then redacts.

D12. **Summary on a terminal.** `WriteSummary` returns today's code at once when the stream is not
     a terminal. On a terminal:
     - **Headings.** Every heading, "Summary" included, is `BoldText(Semantic, "info")`, wrapped
       at spaces with continuation lines at column 0 in the heading style. Under its last line is
       a rule of the full width (D3) in chrome SEPARATOR.
     - **Count blocks** (B7). Labels in a column as today (at least 16 wide, and wide enough for
       the longest label). Then one space, then the numbers right-aligned to the widest number in
       the block. These are not tables.
     - **Findings** (B8), both blocks. A table with the columns SEVERITY (Keep span, the
       `Value` badge), CATEGORY, TARGET (Spaces, Shrink 2) and DETAIL (Spaces, Shrink 1). DETAIL
       is dropped when no row has a non-empty detail.
     - **Candidates** (B9). A table with the columns VALUE (Spaces, Shrink 2), EVIDENCE (the
       count), SOURCES (joined with `, `, Commas, Shrink 1) and PROMOTE (the input alone). Then
       "and N more in candidates.csv", indented 2, wrapped.
     - **Other lines** (B10). The risky-ports line, the notes and the deadline line are wrapped
       with `first` and `rest` at 2.

D13. **CVE records on a terminal** (review: references). `cve.Render` returns today's code at once
     when the stream is not a terminal. Each NVD value is cleaned, then wrapped, then coloured, as
     today.
     - **The bar.**
       - Coloured: one line exactly as wide as the stream's width. It holds a space, the ID,
         padding, the label and a space, all in `BadgeText(Severity, label)`.
       - The label is the severity as recorded. It is `UNKNOWN` when missing, and an unknown
         value keeps its own text; both take the DEBUG style through the lookup.
       - Without `cvss_severity`: a space and the ID, padded to the width, in the DEBUG style.
       - Uncoloured: the ID, padding and `[LABEL]`, filling the width; or the ID alone without
         `cvss_severity`.
     - **Sections.** A blank line, then the heading `BoldText(Semantic, "info")` with no rule.
     - **Fields.** Labels without a colon, indented 2, bold when coloured, padded to the longest
       label of the section plus 2. Values wrap with `rest` at the value column.
     - **Text.**
       - The description is indented 2.
       - Bullets are `  - ` with `rest` at 4.
       - References are indented 2: the URL as a protected span in semantic info, then the tag
         list `[a, b]` as a span in chrome TIMESTAMP that wraps at spaces, with `rest` at 4.
       - The fallback lines are indented 2.
     - Records are separated by one blank line, as today.

D14. **Help is built as tagged blocks** (review: the line classifier gets nyx's own help text
     wrong). `rootHelp`, `commandHelp` and `writeCommandReference` emit a list of `helpBlock`s
     instead of writing a string. The kinds:
     - heading;
     - usage line;
     - example line;
     - command summary, the indented `Short` line;
     - flag list, from `flagUsages`, kept as pflag's text and split into rows of names and
       description by the existing `helpFlag` regex;
     - command rows (`Commands:`, `Help:`);
     - value list, with its label and its items;
     - paragraph;
     - table, for the topics;
     - blank line.

     **Plain.** On a stream that is not a terminal, the blocks are joined back into exactly
     today's text, so B1 holds by construction. A test compares that text with today's.

     **Terminal.** Each kind is laid out:
     - **Headings** take the heading style (B17) and wrap.
     - **Usage and example lines** never wrap.
     - **Flag rows** keep today's colours: names in semantic info, the value type, the
       `(default …)`/`(e.g. …)` aside and the `(repeatable)`/`(# comments allowed)` notes in chrome
       TIMESTAMP. The description wraps with `rest` at the description column (B16).
     - **Command rows** split at the first gap of two or more spaces. The name is in semantic
       info, and the summary wraps under the summary column.
     - **Value lists** (`Fields accepted by --fields:`, `Kinds accepted by --kind:`, `Stages
       accepted by --redo and --skip:`, `Stages --skip refuses:`, `Exit codes:`). The label is
       bold and the items are laid out in Commas mode, with `rest` at the column after the label
       and its space. The value annotation is split at its first `: `; an annotation of several
       lines gives several value lists.
     - **Paragraphs.** The lines of a paragraph are joined with a space and re-flowed, with
       `first` and `rest` at the paragraph's indent.

     **Free text.** `Long`, the annotation note, `reconFooter` and the topic footers are split into
     blocks by a small parser:
     - a blank line ends a paragraph;
     - an unindented line ending in `:` is a heading;
     - a run of other lines with the same indent is one paragraph.

     `colourHelp` and its regexes other than `helpFlag` are deleted.

D15. **Help topics on a terminal.**
     - **Findings.** A bordered table built from `findings.SeverityTable()`, with the columns
       CATEGORY, TYPE, SEVERITY and MEANING. SEVERITY is a Keep span with the `Value` badge, and
       MEANING wraps at spaces (Shrink 1).
     - **Stages.** A bordered table with the columns STAGE (semantic info), CONTACT (semantic
       success for third party, warning for target, as today), KEY (chrome TIMESTAMP) and WHAT IT
       DOES (Spaces, Shrink 1).
     - Each topic's heading and footer paragraphs go through D14.
     - Off a terminal, both topics are today's text.

D16. **Palette sheet on a terminal** (not under `--json`). Today's sheet comes first, with its
     category and group headings in the heading style (B5 says every heading). Then:
     - a heading, "layout";
     - a sample findings table, through D12's table;
     - a CVE bar for each severity label, plus UNKNOWN and NONE, through D13's bar function;
     - one stage line per state (running, done, done-previously, failed, not-configured), through
       the console's message builder and `Line`;
     - a found line with a severity badge, and one of the form `category: value`;
     - a log line whose message is longer than the width.

     Off a terminal, the sheet is today's sheet.

D17. **Goldens only for fixture output** (review: churn). Each renderer that has a separate
     terminal path (summary, CVE, sheet, help) returns today's code first when the stream is not
     a terminal.
     - Before any code changes, `/spec-develop` captures golden files of today's non-terminal
       output for fixture-driven text: a summary with every block, the log lines of a run, CVE
       records with each `--fields` shape, the palette sheet and the `error:` line. They live
       under `internal/cli/testdata/plain/`.
     - Help is not stored as goldens. Its plain path is checked by joining the blocks and
       comparing with today's `rootHelp` and `commandHelp` text. To get that text, copy today's
       builders into the test file once, and delete the copy at the end of the step.

D18. **Existing tests that this spec amends are rewritten** (review). None is deleted while it
     still pins a security property: no escape byte from target text, and no key. See `## Tests`.

## Files

- `internal/layout/` (new, pure, no I/O):
  - `stream.go`: `Stream`, `Width`;
  - `measure.go`: cell width (D1);
  - `wrap.go`: `Span`, `Wrap`, modes (D6, D7);
  - `protect.go`: D8;
  - `table.go`: D9, plus the rule and border characters (D3);
  - tests for each.
- `internal/palette/palette.go`: `BoldText`, `BadgeText` (D10).
- `internal/report/report.go`: the Console on spans, colours, wrapping and redaction (D11).
- `internal/report/summary.go`: the terminal path (D12).
- `internal/report/sheet.go`: D16.
- `internal/report/report_test.go`, `summary_test.go`: updated for the Stream signatures.
- `internal/cve/render.go`, `render_test.go`: D13; `Width` delegates to `layout.Width`.
- `internal/cli/cli.go`: `Deps.StdoutWidth` and `Deps.StderrWidth`, the Streams, `helpStream`, and
  the console options (D2, D4).
- `internal/cli/help.go`: help blocks, the plain join and the terminal layout (D14).
- `internal/cli/stages_topic.go`: D15.
- `internal/cli/recon.go`, `internal/cli/cve.go`: pass the Streams; the annotation strings stay
  as they are.
- `internal/cli/harness_test.go`: `stdoutWidth` and `stderrWidth` fields; `logLines()` folds a
  continuation line, one indented 19 or 21 cells, into the line before it.
- `internal/cli/testdata/plain/`: the goldens (D17).
- `go.mod`: `golang.org/x/text` becomes a direct dependency.
- `README.md`: B22. It also says that the box-drawing characters are East Asian Ambiguous, so a
  CJK-locale terminal may draw them two cells wide.
- `CLAUDE.md`: add `layout` to the list of pure packages and mention `layout.Stream` in the flow.

## Tests

Width-sensitive cli tests set `COLUMNS=80` with `h.setenv` and turn on `h.stdoutTTY` or
`h.stderrTTY`.

**Not applicable to this spec:**
- External dependencies: the only one is `term.GetSize`, and its failure is covered under B2.
- Batches: there are none.
- Interrupts: the summary and each CVE batch are written in one write, and log lines one line at
  a time, as today.
- Re-runs: the rendering is pure, so a re-run gives the same output.

**Mutation check** in `/spec-develop`: **B1** (scripts and saved logs depend on the exact bytes)
and **B21** (escape injection and key leaks).

- **B1** *(mutation check)*
  - Byte equality with the D17 goldens for every non-terminal output, with `COLORTERM=truecolor`
    and `TERM=xterm-256color` set, to show that colour variables change nothing off a terminal.
  - The help plain-join test (D17), for the root help, recon, recon export, cve, help and both
    topics.
  - On a terminal under `--json`, help, the topics and `--palette` equal their non-terminal
    bytes (D2). `--debug` lines on a terminal stderr under `--json` are wrapped.
  - On a `NO_COLOR` terminal and on a `TERM=dumb` terminal, no `\x1b` in stdout or stderr for:
    a run with findings and candidates, `nyx cve`, every help screen and the sheet.
  - On a terminal, the `--json` envelope equals the non-terminal one.
  - On a terminal, the `error:` line and the authorisation prompt are unchanged.
- **B2**
  - `layout.Width` table: `COLUMNS` of `80`, `" 90 "`, `0`, `-5`, `abc` and unset, each with a
    terminal width of 0, 50 and 120. The cases cover a negative fallback to the terminal, the
    default of 100, and 40 → 60.
  - A cli test with `stdoutWidth` 70 and no `COLUMNS` lays the summary out at 70.
  - Console: a `Width` function that returns 80 and then 120 lays out two events differently
    (resize).
  - `StderrWidth` nil, or returning 0, gives 100.
- **B3**
  - `measure`: SGR counts zero, wide CJK characters count two, a combining mark counts zero, and
    an Ambiguous character counts one.
  - `Wrap`:
    - each protected type (URL, email, IPv4, IPv6, CIDR, hostname, `*.example.com`) longer than
      the space is left whole, as is a protected word with trailing punctuation (`example.com,`);
    - an unprotected long word is broken at the width;
    - `CVSS:3.1/AV:N/…` is broken;
    - `2.4.41` counts as protected (D8);
    - a padded stage line and a two-space count line keep their spaces (D7);
    - `\n` is a hard break;
    - Commas mode, including the fallback to Spaces;
    - a styled span across a break is closed and opened again, and no line ends inside an escape
      sequence.
  - `Table`:
    - columns shrink in `Shrink` order;
    - a floor of 10;
    - a floor of the widest protected word: a 40-cell URL in TARGET at 80 columns keeps DETAIL
      aligned on every row;
    - widths are decided once across the rows.
  - **Goal property test.** A fixture with no unbreakable token longer than its space: at
    `COLUMNS=80`, every line of the summary, of CVE records and of every help screen and topic is
    at most 80 cells. Usage and example blocks are excluded by kind, not by pattern matching.
  - One targeted test for each B3 exception: a usage line, a protected word, a table at its
    floors.
- **B4**
  - Every SGR sequence in terminal output at each depth is in the set the palette can produce:
    collect the sequences and compare them with those from `Badge`, `Value`, `Text`, `Bold`,
    `BoldText` and `BadgeText` over every table.
  - `BoldText` and `BadgeText` give exact bytes at each depth.
  - Help flag names, value types, defaults, the stages contact column and CVE URLs and tags keep
    today's colours.
- **B5**
  - A summary heading is `BoldText(info)` with a full-width rule: `─` in SEPARATOR coloured, `-`
    plain uncoloured.
  - A heading wider than the width wraps, with continuations in the heading style at its column.
  - Help and CVE headings take the style and have no rule.
- **B6**
  - The header row is bold and TIMESTAMP when coloured, and plain when uncoloured.
  - Summary tables have an indent of 2, a gap of 2, no border characters and no trailing spaces.
  - Topic tables have the box characters coloured and ASCII uncoloured.
  - A summary with no findings or candidates has neither the heading nor the table.
- **B7**: Counts and failed, deferred and "Since last run" blocks with numbers of 1 to 4 digits are
  right-aligned, with today's labels and no header row.
- **B8**
  - Columns and order, with the badge and rows in input order.
  - DETAIL is dropped when every detail is nil or "".
  - At 80 columns, a long DETAIL wraps before TARGET does.
  - A hostname TARGET is never broken.
  - The same for "New findings".
- **B9**
  - The columns.
  - EVIDENCE is a bare number, and PROMOTE has no `promote:`.
  - SOURCES wraps after commas before VALUE wraps.
  - "and N more in candidates.csv" comes after the table.
- **B10**: A long note and the deadline line wrap with continuation lines at 2.
- **B11**
  - A bar per severity label, UNKNOWN (null severity) and NONE: its exact width, the ID at the
    left, the label at the right, and the style.
  - Without `cvss_severity`, the ID alone in DEBUG.
  - The uncoloured form `ID … [HIGH]`.
- **B12**
  - Field labels without colons, with values at one column per section.
  - A long description and long bullets wrap under their text.
  - A reference with tags wraps, and the URL stays whole.
  - One blank line between records.
- **B13**
  - A long warning wraps, with continuation lines at 19 (uncoloured terminal) and 21 (coloured).
  - A found line with a badge wraps at 21.
  - `logLines()` folds continuation lines.
- **B14**: Each state's word has its colour, with the level badge INFO for running, done and
  not-configured. The name, reason and counts are uncoloured.
- **B15**: `+` is success. The category is info for a `category: value` event. An event with
  `text` colours only the `+`.
- **B16 to B19**
  - At 80 columns: flag descriptions continue under the description column; root `Long`, recon's
    `Configuration:` footer and the stages footer re-flow; `Stages accepted by --redo and
    --skip:` and `Exit codes:` wrap after commas under their text; usage and example lines are
    unbroken (recon's second example runs past 80); headings are styled.
  - The findings topic is a bordered table with the header CATEGORY TYPE SEVERITY MEANING, and
    the stages topic a bordered table with its contact colours.
- **B20**: On a coloured terminal and on an uncoloured one, `--palette` holds each added part
  (D16). Under `--json` it is today's sheet.
- **B21** *(mutation check)*. Extend `TestLog_MessageHandling` and its fixture:
  - Target text with CSI, OSC and bidi characters, placed where wrapping breaks, gives no `\x1b`
    except the palette's.
  - A configured key inside a long word that is hard-broken does not appear whole, nor any
    8-character piece of it, in stderr or stdout.
  - A key split by a control character that sanitising removes is redacted on the log path
    (D11).
  - The same for a summary note and a CVE description.
- **B22**: Review the README by hand in `/spec-verify` against the list in B22.

**Existing tests to rewrite** (D18):
- `internal/cli/logcolours_test.go`:
  - `TestLog_MessageHandling`: the 800-character warning now wraps; keep its escape and key
    assertions.
  - `TestLog_FoundLinesColoured`: `+` and the category are coloured.
  - `TestLog_Summary`, coloured half: headings, rules and table headers.
  - `TestLog_Palette`, coloured half: the added sheet.
- `internal/cli/help_test.go`:
  - `TestHelp_Colour`: stripped coloured help no longer equals plain help. Assert the plain-join
    test and B16/B17 instead.
  - The stripped-stages check, around lines 153 to 162.
- `internal/cli/cve_test.go`, around lines 601 to 615: the header assertion becomes the bar.
- `internal/cli/error_contract_test.go` `TestContract_NoPrompt`: read the WARN message through the
  folding `logLines()`.
- `internal/report/report_test.go`, `summary_test.go` and `internal/cve/render_test.go`: the
  signature changes.

## Conventions

- `CLAUDE.md`:
  - only `internal/egress` does network I/O;
  - read the environment only through `Deps.Env` (D1 avoids init-time env reads);
  - every test is `t.Parallel()`, and uses `h.setenv`;
  - Australian English;
  - no spec numbers in code or tests;
  - commit prefixes.
- `docs/log-colors.md`: the palette, unchanged (D10 adds no colour values).
- `docs/specs/done/2026-11-spec-log-colours-22.md`: D1 to D4 (palette as data, nyx writes its own
  escape codes, Detect, the 16-colour table) and D13 (one line formatter) still hold. This spec
  amends B6, B8, B13 and D14, D15 there, on a terminal only.
- `docs/specs/done/2026-11-spec-cve-lookup-25.md`: D9's order of work (clean, wrap, colour) and
  its non-terminal layout still hold.

# Implementation

## Develop

Built in two waves, all in the working tree, with no worktree.

**Before any renderer changed**, goldens of today's non-terminal output were captured under
`internal/cli/testdata/plain/` and `TestPlain_*` (`plain_golden_test.go`) compares each run with them,
with and without `COLORTERM`/`TERM` colour variables set (B1). They cover:
- the summary with every block (the deadline line is a separate file);
- the log lines of three runs, including `--debug`;
- the palette sheet;
- the `error:` lines;
- 13 `--fields` shapes of `nyx cve`, at `COLUMNS` unset, 80 and 40.

The goldens never changed. The harness temp directory is normalised to `<OUTPUT-DIR>`.

**Foundation.** `internal/layout` (stream, measure, wrap, protect, table, rule and heading helpers)
and `palette.BoldText` / `palette.BadgeText` (D10). The invocation builds a `layout.Stream` for each
output (`inv.st`), `Deps.StdoutWidth` / `StderrWidth` carry the terminal widths, and `helpStream()`
replaced `helpDepth()` (D2, D4, D5).

**Renderers.**
- `report`: the console builds spans, wraps only on a terminal, colours state words and found lines
  and redacts after sanitising (D11). `WriteSummary` has a terminal path of headings, rules, count
  blocks and tables (D12). `Sheet` adds the layout parts (D16).
- `cve`: `Render` returns today's code first off a terminal and has a terminal path of bar, sections,
  fields and references (D13). `cve.Bar` is shared with the sheet.
- `cli`: help is built as tagged blocks that join back into today's text off a terminal and are laid
  out on one (D14), and both topics are tables (D15). `colourHelp` and its regexes were deleted.

**Tests per behaviour.**
- B1: the `TestPlain_*` goldens, the plain-join test for help, `--json` on a terminal, `NO_COLOR` and
  `TERM=dumb` with no `\x1b`, and the unchanged `error:` line.
- B2: `layout.Width`, the console resize test, nil and zero widths, and `stdoutWidth` 70 for the
  summary.
- B3: `Measure`, `Wrap`, `Table`, one test per exception, and goal property tests at 80 columns for the
  summary, CVE records and every help screen.
- B4: the SGR set of terminal output at each depth, and exact bytes for `BoldText` and `BadgeText`.
- B5 to B22: layout, colour and wrapping tests in `report`, `cve` and `cli`.
- B21: key and escape tests on the log, summary and CVE paths.
- B22: the README, by hand (see `/spec-verify`).

**Deviations from the plan.**
- **Help oracle.** D17 asked for a copy of today's help builders to be deleted at the end. Instead,
  today's plain help for the root, recon, export, cve, help and both topics was captured as
  `testdata/plain/help-*.txt` before `help.go` changed, and `TestHelp_PlainJoin` compares with those
  files. The result is the same check and nothing temporary to delete.
- **CVE redaction.** The spec said keys were redacted in human CVE output "as today", but `Render` had
  no redactor. `cve.Render` now takes the redactor, applied after cleaning and before wrapping
  on both paths. Off a terminal and with no key present, the output is byte-identical.
- **`Wrap`.** Its `width` counts the first-line prefix, and the returned first line excludes it. A
  line off a terminal for `nyx cve` wraps at `Stream.Cols()`, which gives today's width because
  stdout reports no width off a terminal.
- **Command rows.** Help command rows are structured (lead, name, gap, summary) rather than split by a
  regex. recon's `export` row has a one-space gap, so its name is now coloured, and the `Help:` rows
  take the info colour too.
- **`Measure`** strips any CSI sequence, not only `ESC[…m`. The palette writes only the `m` kind.
- **`Protected`** compares hostname labels in lower case, because `dnsname.ValidLabel` accepts only
  lower case. A name with an underscore, such as `_dmarc.example.com`, is therefore not protected.
- **Test order.** The `layout` tests and the cli `TestLayout_*` tests were written after their code,
  so they were not seen to fail first. The `layout` tests were mutation-checked instead (14
  mutations, each failing a test). The `report`, `cve`, `palette` and help tests failed on their
  assertions before the code, apart from guards on behaviour that already held.
- `internal/report` now imports `internal/cve`, for `cve.Bar`. There is no cycle and the egress
  boundary test passes.

External facts: none turned out different from `## External facts`.

**Mutation checks** (B1 and B21), each made by hand after simplifying and then undone by hand. Each
was killed by the tests named:
- B1, summary: removing the not-a-terminal guard in `WriteSummary` fails `TestWriteSummary_PlainText`
  and the other plain summary tests.
- B1, help: removing the guard in `renderHelp` fails the help tests of every command and the
  plain-join test.
- B1, CVE: always taking the terminal path in `cve.Render` fails `TestRender_Wraps` and the other
  plain render tests.
- B1, log: wrapping off a terminal fails `TestLineNeverWrapsOffATerminal`, `TestConsoleSanitises` and
  the `TestPlain_Log*` goldens.
- B21, console: removing the redaction fails `TestConsoleRedactsAfterSanitising` and
  `TestLog_MessageHandling`; removing the sanitising fails `TestConsoleSanitises`,
  `TestConsoleWritesOnlyPaletteSequences` and `TestConsoleTextAtWrapPoints`.
- B21, CVE: removing the redaction, or redacting before cleaning, fails `TestRender_RedactsKeys` and
  `TestCVE_HumanOutputRedactsTheKey`.
- B21, summary: removing the sanitising on the terminal path fails `TestSummaryTerminalSanitises`.

## Known limitations

- **B11**: `cve.Bar` does not truncate an ID wider than the layout. It keeps one space of padding and
  runs past the width.
- **B3, B18**: at 80 columns the findings topic's MEANING column is about 17 cells, as CATEGORY, TYPE
  and SEVERITY never shrink. Words longer than that (`Strict-Transport-Security`,
  `--cert-expiry-days`) are hard-broken, and under about 75 columns the table runs past the width.
- **B3**: the summary's goal test runs at 80, 100 and 120 columns, not 60, where a long URL in TARGET
  cannot fit beside the fixed columns. B3 allows that.
- **B8**: a finding row without detail is not reachable through the cli, so only the report-level
  test covers it.
- **D1**: emoji sequences may be measured imprecisely, as D1 accepts.
- **Harness**: `theError`, `failed` and `partial` treat any stderr line that is not a plain-layout
  log line as an error line, so a test that wraps stderr on a terminal cannot use them. `logLines()`
  folds continuation lines.

## Simplify

Four reviewers looked at reuse, simplification, efficiency and altitude. No output changed: the plain
goldens and every test pass, and lint is clean.

**Fixed.**
- `layout.Hang(prefix, spans, width, mode)` writes a prefix and indents continuation lines by its
  measured width. It replaces help's `hang`, the summary's `indented`, three hand-written copies in
  the CVE terminal renderer and the log-line indent arithmetic in `LineSpans`. That arithmetic
  repeated the palette's badge geometry. Off a terminal, `LineSpans` now calls `Hang` in `None` mode
  instead of flattening the spans and indenting by hand.
- `Stream.Fixed()` reads the width once for a whole write. It is used by the summary, the sheet, the
  CVE terminal renderer and help. Before, the CVE bar and headings and each help block re-read the
  live width. `termRenderer.width` is gone.
- Help headings call `layout.Heading` instead of rebuilding its style. `Stream.HeadingStyle` is
  folded into `Heading`.
- `badgeSpan` is a Keep span styled by `Depth.Value` and no longer copies the palette's padding.
- `cve.Render` takes `*config.Redactor` as a parameter instead of a one-option `WithRedactor`
  functional option. The dead `cve.Width` and its test, and `derefOr`, are removed.
- `invocation.dp` and the `depths` type are removed; `inv.st` holds the depths. `newStream` reads
  `COLUMNS` once instead of on every log line.
- The console's `messageOf` is a method, so `str` is no longer passed in. `coloursText` is inlined.
- In `wrap.go`, `render` no longer concatenates strings quadratically or clones the line slice, and a
  word of one fragment no longer goes through a builder.
- `paletteSequences` and `onlyPaletteEscapes` had two copies, in the cli and report tests. They are
  now one `testkit.OnlyPaletteEscapes`. `maxCells` uses `widest`, and help's leading-space count is
  one `indentOf`.

**Skipped.**
- Tokenising each table cell once instead of three times, and a fast path for log lines that fit.
  Output is human-scale and either change would add complexity to the wrap engine.
- Building debug events before checking the level. This ordering predates the change.
- Sharing field selection between the plain and terminal CVE renderers. The plain path is kept
  byte-identical on purpose (D13, D17).
- Moving `cve.Bar` into `layout`, and curried palette style helpers. Both reach outside the change
  for little gain.
- Merging help block kinds, and `commandRow.lead`. The kinds name the spec's block types. The
  `exhaustive` lint needs `blockTable` listed in the switch.
- `layout.Rule`'s width parameter. A test uses a non-zero width.
- The report tests' `cells` alias for `layout.Measure`. Renaming it is churn.

# Verification

## Result

Verified on 2026-11-20 against the working tree on `main` (`8180115` plus the uncommitted change).
The method:
- read every changed file against the behaviours, using `# Design` as a map;
- ran the tests and lint;
- built the binary and ran it under a pseudo-terminal (`script`) at `COLUMNS=80`, coloured
  (`COLORTERM=truecolor`) and with `NO_COLOR=1`: the root help, `recon --help`, `recon export --help`,
  `cve --help`, both topics and `--palette`, and one live `nyx cve CVE-2021-44228 CVE-2024-3094`;
- printed the terminal summary of the report tests' rich fixture at 80 and 60 columns.

**Goal: met.** At 80 columns, coloured and not, the only lines of the help screens wider than 80
are recon's and export's long example lines, and the only lines of the live CVE records wider than 80
are reference URLs, which are protected words. Both are B3 exceptions. Every table's columns line up,
and a long log line wraps under the message column (21 cells coloured, 19 plain). The goal property
tests at 80 columns (summary, CVE, every help screen and topic) pass.

- **B1 met.** Every renderer with a terminal path returns today's code first off a terminal, and the
  `TestPlain_*` goldens, captured before any renderer changed, pass with and without the colour
  variables. Help's plain join equals the captured help of every screen. Under `--json` help, the
  topics and the sheet are plain on a terminal, and `--debug` lines wrap. `NO_COLOR` and `TERM=dumb`
  terminals get the layout with no escape byte.
  - **Corrected:** `Deps.StdoutWidth` and `StderrWidth` are documented as consulted only for a
    terminal, but `newStream` always asked them, so a non-terminal stream that reported a width
    would have changed `nyx cve`'s plain wrap width. `newStream` now asks only on a terminal, and
    `cveGolden` sets a reported width of 70 off a terminal to pin it (it fails without the fix).
- **B2 met.** `layout.Width` is the rule, each stream has its own width function, and the console
  reads the width per line (`TestConsoleResize`).
- **B3 met.** Cells are measured as D1 says, protected words and Keep spans are never broken, other
  long words are broken at the width, and table widths are decided once from every row.
- **B4 met.** Only `BoldText` and `BadgeText` are added; every SGR sequence in terminal output is
  one the palette writes (`testkit.OnlyPaletteEscapes`). Flag names, value types, defaults, the
  stages contact column and CVE URLs and tags keep today's colours.
- **B5 met.** Headings are bold info, wrap at spaces at their own column, and the summary's carry a
  full-width rule (`─` in SEPARATOR, or `-`).
- **B6 met.** Five tables, header row bold TIMESTAMP, summary tables unbordered with a two-space
  gap, topic tables bordered (box-drawing coloured, ASCII uncoloured), and empty tables omitted with
  their heading.
- **B7 met.** Count blocks keep their labels with the numbers right-aligned per block.
- **B8 met.** SEVERITY, CATEGORY, TARGET, DETAIL, DETAIL dropped when every detail is empty, DETAIL
  shrinking before TARGET. As D9 specifies, DETAIL shrinks all the way to its floor of 10 before
  TARGET gives up any width. With a long target and a long detail at 80 columns, DETAIL is then 10
  cells wide and a word such as "administration" is broken. That follows B3 and D9, but it is hard
  to read. See Follow-ups.
- **B9 met.** VALUE, EVIDENCE (bare count), SOURCES (joined with `, `, Commas) and PROMOTE (without
  `promote:`), then "and N more in candidates.csv". The same floor rule breaks source names longer
  than 10 cells (`securitytrails`, `hackertarget`) when SOURCES is at its floor.
- **B10 met.** The risky-ports line, notes and deadline line wrap with continuations at 2.
- **B11 met in practice.** The bar is exactly the width, with the badge style of the severity,
  UNKNOWN and an unknown value in DEBUG, the ID alone in DEBUG without `cvss_severity`, and `ID …
  [LABEL]` uncoloured. Known limitation: an ID wider than the layout is not truncated. `nyx cve`
  accepts only `CVE-YYYY-NNNN…` IDs, so this needs an ID of more than 50 digits.
- **B12 met.** Section names are unchanged, headings have no rule, labels have no colon and align per
  section, the description, bullets and references wrap under their text, and records are separated
  by one blank line.
- **B13 met.** Continuations at 19 or 21 cells, found lines with a badge included.
- **B14 met.** State words take info, success, error and TIMESTAMP. The name, reason and counts
  stay uncoloured.
- **B15 met.** `+` in success, and the category in info only for an event without `text`.
- **B16 met.** Flag and command descriptions hang under their column, paragraphs and footers
  re-flow, value lists wrap after commas under the text after the label, and usage and example lines
  never wrap.
- **B17 met.** Help headings take the heading style.
- **B18 met.** A bordered table of CATEGORY, TYPE, SEVERITY (badges) and MEANING (wrapping). Known
  limitation: CATEGORY, TYPE and SEVERITY never shrink, so at 80 columns MEANING is about 17 cells
  and longer words are broken. Under about 75 columns the table runs past the width. Both fall
  under B3's exceptions.
- **B19 met.** A bordered table, WHAT IT DOES wraps, and the contact colours are kept.
- **B20 met.** On a coloured and an uncoloured terminal the sheet adds the heading, a sample findings
  table, a bar for each severity plus UNKNOWN and NONE, a stage line per state, two found lines and a
  long log line. Under `--json` it is today's sheet.
- **B21 met.** The console sanitises and then redacts each field. The summary is cleaned and
  redacted before layout. `cve.Render` now redacts each cleaned value before wrapping, which it did
  not do before. Tests cover CSI, OSC and bidi text at wrap points, a key inside a hard-broken word
  (no 8-character piece survives), and a key split by a control character, on the log, summary and
  CVE paths.
- **B22 met, after one correction.** README's "Terminal layout" covers wrapping, the tables, the
  coloured state words, B2's width rule, the unchanged non-terminal `nyx cve` rule and the East Asian
  Ambiguous box characters. CLAUDE.md names `layout` and `layout.Stream`.
  - **Corrected:** the section said "the `error:` line and the authorisation prompt are never laid
    out". nyx has no authorisation prompt (README says so twice elsewhere), so the sentence now names
    only the `error:` line.

The other known limitations (the summary's goal test runs at 80, 100 and 120, not 60; a finding
without detail is reachable only in the report test; emoji measured imprecisely; the harness's
error-line helpers) do not leave a behaviour unmet.

**Changed during verification:**
- `internal/cli/cli.go`: `newStream` asks a stream's width only on a terminal.
- `internal/cli/plain_golden_test.go`: `cveGolden` reports a width of 70 off a terminal.
- `README.md`: the authorisation-prompt sentence.

**Tests.** `make test` passes: `go vet` for the four targets, then `go test -race ./...`.
`make lint` reports 0 issues.

## Code review

`/code-review high --fix` ran over every changed file. It reported six findings and fixed three.
Each fix was checked against the spec, and all three were kept:
1. **B3, B8:** `Protected` also accepts an address or hostname with a port (`198.51.100.7:3389`,
   `[2001:db8::1]:3389`, `www.example.com:8443`). A risky port's target is `addr:port`, so before the
   fix the TARGET column's floor ignored it, and the address could be broken mid-address, against
   B3's "an IP address … is never broken". Cases were added to `TestProtected`. README's wrapping
   bullet mentions `:port`, and the CVSS vector is still not protected.
2. **No behaviour change:** `Sheet` uses `Stream.Fixed()` instead of its own copy.
3. **No behaviour change:** one `measureSpans` pass gives a cell's natural and unbreakable widths,
   instead of a full wrap and a second tokenise.

Fixed after the review, from a finding it skipped:
4. **No behaviour change:** `Wrap`'s doc comment said that a word too long for the space left
   always moves to the next line first. On the first line, with no word on it yet, it is broken
   there instead. That only matters when `first` is wider than `rest`, which no caller passes. The
   comment now says what the code does.

Left unfixed:
- **B13 against D7: spaces carried over a break.** When a line breaks inside a run of several
  spaces, only one is consumed (D7) and the rest start the next line. A wrapped `run_start` line
  (`nyx <engagement>  <scope>  [passive-only]`) can then continue at 20 or 22 cells, not at the
  message column. D7 and `TestWrap_KeepsSpaces` ("one space consumed at a break") pin the current
  behaviour, so this is a decision for the user (see Follow-ups).
- **Colour in the plain renderers.** The non-terminal summary, CVE and stages renderers keep colour
  branches that the CLI never reaches, because `palette.Detect` gives depth None off a terminal. The
  tests use them, and removing them is outside this spec.

Afterwards the `layout`, `report`, `cve`, `palette` and `cli` tests pass. `make test` (with `-race`)
passes, and `make lint` reports 0 issues. During the review `TestCVE_Pacing` failed once under
full-suite load, then passed five times. It is a timing test that this change does not touch.

# Follow-ups

1. Look at the layout on the terminals and themes you use, at 80 columns and wider, then again with
   `NO_COLOR=1` and inside tmux. Until then only tests and a pseudo-terminal (`script`) have checked
   it.
   - `./nyx --help`
   - `./nyx help stages`
   - `./nyx help findings`
   - `./nyx recon --palette`
   - `./nyx cve CVE-2021-44228`
   - a real recon summary: `./nyx recon example.com --output-dir /tmp/nyx-check`
2. Decide whether a summary table's wrapping column should give up all its width before the next
   one gives any. This is D9's rule in `layout.Table.widths` (`internal/layout/table.go`).
   - Today, at 80 columns, a findings table with a long TARGET and a long DETAIL gets DETAIL at
     10 cells, and words such as "administration" are broken. The same rule breaks source names
     such as `securitytrails` in SOURCES.
   - Alternatives: shrink the columns in turn, or give a Spaces or Commas column a floor of its
     widest word (capped), so that words are not broken.
   - To see it, print `termSummary(palette.None, 80, richEnvelope())` from
     `internal/report/summary_layout_test.go`.
3. Decide whether a line break inside a run of spaces should consume the whole run (B13) or one
   space (D7, today).
   - To consume the whole run, set `e.pending = nil` at the break in `engine.place`
     (`internal/layout/wrap.go`, the "only one space is consumed" line).
   - Then change the "one space consumed at a break" case of `TestWrap_KeepsSpaces` to expect
     `bbbb`, and amend D7.
4. Investigate `TestCVE_Pacing`, which failed once under full-suite load during the code review:
   `go test ./internal/cli/ -run TestCVE_Pacing -count=20`.

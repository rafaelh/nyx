# Spec: richer human output layout on a terminal

## Goal

When a person reads nyx's human output on a terminal (the recon summary, log lines, `nyx cve`
records and help), it is easier to scan: aligned tables, distinct headings, text wrapped to the
terminal and, where colour is on, colour on the parts that carry meaning. Output to anything that
isn't a terminal stays byte-for-byte as today, so scripts, saved logs and `--json` are unaffected.

Done when, at 80 columns, every summary table, CVE record and help screen fits the width under
the fit rule (B3) and its columns line up, and a log line longer than 80 cells wraps under the
message column.

Constraint: lipgloss is the chosen layout library, bound by B1 and B4: today's colour detection
and exact palette escape sequences must still hold. If lipgloss can't meet them, the design step
raises it rather than relaxing those behaviours. (The log-colours spec removed lipgloss for
exactly this reason; see its D2.)

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
    authorisation prompt and the `error:` line are unchanged on a terminal too.

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
      spans the layout width and takes the log line's separator colour, or no colour on an
      uncoloured terminal.

B6. **Tables.** There are five tables: the two summary findings tables (B8), the summary
    candidates table (B9), and the findings and stages help-topic tables (B18, B19). No other
    block is a table.
    - **Header row.** Every table has one, bold, and in the log line's timestamp colour on a
      coloured terminal.
    - **Summary tables** keep the summary's two-space indent, have no borders, and separate
      their columns with two spaces.
    - **Help-topic tables** have borders, and a border with one space either side separates
      their columns.
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

# Follow-ups

- Open questions from the specification review, for the user to settle before or during design:
  - On a terminal under `--json`, should help, the palette sheet and `--debug` lines get the
    layout without colour?
  - On a terminal with colour off, should borders and rules be drawn in ASCII (`-`, `|`, `+`) or
    in box-drawing characters?

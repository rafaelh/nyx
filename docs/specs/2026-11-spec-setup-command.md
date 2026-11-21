# Spec: Setup command

## Goal

A user who has just installed nyx, or who later needs to add, rotate or remove a key, can store their
API keys, output directory and common settings, and confirm the keys work, without reading the
README's Configuration section or opening the config file. The next `nyx recon` or `nyx cve` uses
those values.

## Behaviours

- B1. `nyx setup` opens a full-screen terminal UI that edits one config file: the one given by
  `--config`, or the default path. It is in the root help with an example. With no `--config` and
  no default path (neither `XDG_CONFIG_HOME` nor `HOME` is set), setup exits 2 and says to pass
  `--config`. Any positional argument exits 2.
- B2. It lists every key source (`securitytrails`, `shodan`, `virustotal`, `whoisxml`, `censys`,
  `chaos`, `github`, `certspotter`, `nvd`) with what each turns on (for `certspotter`, that it also
  works without one), and `output_dir`, `concurrency`, `rate.per_host`, `rate.per_source`,
  `rate.dns`, `wordlist`, `sensitive_paths` and `skip`, each showing its file value, or its default
  when the file doesn't set it. An unset `output_dir`, and any relative path already in the file, is
  shown as resolving against the directory nyx is later run from, with the current result as an
  example.
- B3. A set key of 12 or more characters is shown masked with its last 4 characters; a shorter one
  shows only "set"; an unset key, or one that is empty in the file, shows "not set". While a key is
  typed, one mask character is shown per character; pasting is accepted.
- B4. No key, in full or beyond its last 4 characters, appears on screen, in any error or test
  reason, on stderr under `--debug`, or in the terminal after setup exits.
- B5. You can enter or replace a key, or clear it, which removes it from the file. A key is stored
  without surrounding whitespace, and an entered key that is empty after trimming counts as clearing
  it. Keys for sources nyx doesn't know are kept untouched and not listed.
- B6. A setting or key source whose name in the file differs only in case (`keys.Shodan`,
  `Concurrency`) is shown as that setting and replaced in place, leaving one entry. If the file holds
  two case variants of one name, that setting is marked invalid until it is edited or cleared, and
  saving it leaves one entry.
- B7. Non-key values are checked as they are entered, with the same rules and messages that
  `nyx recon` gives for the file; an invalid value isn't accepted. Clearing a setting removes it from
  the file so its default applies. A relative `output_dir`, `wordlist` or `sensitive_paths` that is
  entered is saved as an absolute path, expanded against the directory setup runs from; a leading
  `~/` is kept as typed.
- B8. `skip` is edited by toggling stages from the stage list, with each stage's one-line
  description as in `nyx help stages`; stages that can't be skipped aren't offered. Each `skip` entry
  in the file that is unknown or can't be skipped is listed with its message and can be removed on
  its own; the other entries are kept.
- B9. A key can be tested, including an entered, unsaved key: one authenticated request to that
  source only, never to a target. It shows "accepted" when the source accepts the key, "rejected"
  when the source says the key is invalid, and "could not check: <reason>" for a rate limit,
  exhausted credits, a network failure or any other answer. A reason taken from a source's answer is
  shown with terminal control characters removed and cut to one line. A test gives up after 15
  seconds with "could not check: timed out"; the UI stays usable while it runs, and quitting
  abandons it. A result is shown only while the key it tested is unchanged: editing or clearing the
  key removes it, and an answer for a key that has since changed is discarded.
- B10. Edits are held until you save; a value changed and changed back counts as unchanged.
  Quitting (Ctrl+C in the UI is a quit) with unsaved changes asks: save, discard, or go back.
  Quitting with no changes writes nothing. Setup exits 0 after a save, a discard or no change.
  SIGTERM or SIGHUP exit with their usual exit code and leave the file as it was, or as fully saved
  if a save was already under way.
- B11. On every exit (save, discard, quit, SIGTERM, SIGHUP, an unexpected error) the terminal is
  returned to the state it was in before setup started, and any error message is printed after that,
  so it stays visible.
- B12. Saving changes only the edited values and keeps every other setting, comment and their order;
  a cleared value's own comment goes with it, and a `keys:` block left empty is removed. It creates
  the file and any missing directories; a created directory and the saved file are readable only by
  their owner, and saving tightens an existing file's broader permissions. A crash during save leaves
  either the old or the new file, never a partial one. If the config path is a symlink, the file it
  points to is updated and the link stays.
- B13. After a save, `nyx recon` run from the directory setup was run from, with no `NYX_*`
  variables and no flags, uses exactly the values setup showed, and with no `NVD_API_KEY`, `nyx cve`
  sends the `nvd` key setup saved. Every key and path is stored exactly as entered (after B5's
  trimming and B7's absolute paths), whatever characters it contains.
- B14. If a save fails, setup stays open with the edits kept, shows the reason and the file path,
  and the file on disk is unchanged.
- B15. If the file changed on disk since setup opened, last saved or reloaded it, saving warns and
  offers to reload (discarding setup's edits) or overwrite. If a reload finds the file unreadable,
  unparseable or holding an unknown key, setup stays open with its edits kept, shows the problems and
  the path, and still offers to overwrite.
- B16. A missing file, at the default path or at `--config`, opens with every value at its default
  and is created on save. An unreadable or unparseable file, or one with an unknown key, makes setup
  exit 2 with the problems `nyx recon` reports for the file alone (as if no `NYX_*` variable were
  set), with an error naming the file's full path; the UI doesn't open. A file that parses but holds
  an invalid value (including a `wordlist` or `sensitive_paths` file that can't be read, or a `skip`
  stage that doesn't exist or can't be skipped) opens with that value marked invalid and its message
  shown; saving is blocked until it is fixed or cleared.
- B17. `NYX_*` variables and `NVD_API_KEY` are ignored entirely: they don't change what's shown, and
  an invalid one doesn't stop setup.
- B18. If stdin or stdout isn't a terminal, setup exits 2 with error code `INVALID_INPUT`, an error
  naming the config file path and a hint to edit it by hand; under `--json` that error is the usual
  JSON error. `nyx setup --help` prints help and exits 0 even when piped.
- B19. When no config file exists at the default path, a default path exists, and `--config` isn't
  given, `nyx recon` (a run, not `nyx recon export`) and `nyx cve` print one hint line on stderr
  suggesting `nyx setup`. It is not printed under `--json` or `--quiet`, or when the command fails
  with a usage error, and changes nothing else: exit code, stdout and events are as before.
- B20. A footer always shows the available keystrokes. A terminal too small to draw the UI shows a
  message asking for a larger one in its place.
- B21. The README documents `nyx setup`, its exit-2 cases in the exit-code table, the no-config
  hint, and that `NYX_*` variables and `NVD_API_KEY` still override what setup saves.

## Out of scope

- Editing settings other than those in B2: they stay hand-edited in the file.
- A line-prompt fallback when there is no terminal: setup exits 2 instead (B18).
- Showing or editing values from `NYX_*` variables: setup edits the file only (B17).
- Warning before a key test that spends a query credit: the test is just sent.
- Narrowing the no-config hint to users with no keys in the environment: it shows whenever there is
  no file (B19).
- The no-config hint for `nyx ip` (it reads no configuration) and `nyx recon export` (it reads an
  engagement that already exists).
- A help topic for setup beyond its command help.

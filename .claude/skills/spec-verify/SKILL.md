---
name: spec-verify
description: >
  Verify that a specification file has been implemented correctly. Use after a specification has
  been implemented.
argument-hint: Which spec.md are we verifying?
context: fork
background: false
model: opus
metadata:
  version: "1.5"
---

Check that the specification file at $ARGUMENTS has been implemented correctly. If no complete
specification file was supplied, say which file is missing and stop. Don't stash, reset or commit,
and don't move the file: `/spec-develop` settles the follow-ups with the user and commits.
Don't return until every sub-agent you, or a skill you run, started has reported and its findings
are handled; a status line is not a result.

The implementation is every file that differs from the base commit on the first line of
`## Develop` (if there is none, the merge-base with the default branch, usually `main`), whether
committed, uncommitted or untracked. Run `git add -N` on untracked files so they show in the diff,
then list the files with `git diff --name-only <base>`.

Judge the implementation against the goal, the behaviours (as amended) and `## Out of scope`. Use
`# Design` only as a map to find the code, and read the docs listed under `## Conventions`. Treat
`# Implementation` as claims to check, not as evidence. A behaviour, or part of one, listed under
`## Known limitations` is not met, or only partly met, unless `## Out of scope` shows the user
agreed to leave it out.

Confirm each fact that `## Known limitations` lists as *unconfirmed*, and each *assumed* fact in
`## External facts` that a behaviour rests on, with a read-only probe where you can: fetch the
source, read the docs, or make a read call. A fact that turns out wrong is a discrepancy.

Report any discrepancies between the specification and the implementation, including missing
behaviours, incorrect behaviours, or any other issues that prevent the implementation from meeting
the specification.

If you identify any bugs that can be fixed without deviating from the spec, fix them and confirm
that the tests still pass. If a test fails that you didn't expect, follow the failing-test rule in
the standing rules of [spec-develop](../spec-develop/SKILL.md), with the base commit above.

Write `# Verification` in the specification file, using the skeleton's headings. Under
`## Result`, briefly describe to what degree the code met each behaviour and the goal, and
summarise anything you changed or corrected up to this point.

When you are finished:
- Run `/code-review high --fix` on the files listed above. Wait for its result before continuing.
- Check each fix it applied against the spec. Undo by hand any fix that changes behaviour the spec
  doesn't ask for or edits a test that pins a behaviour, and list it as left unfixed.
- Confirm the tests still pass. If a code-review fix broke a test, fix it before continuing.
- Write a short `## Code review` section that says what was fixed, which behaviour each fix
  touched, and what was left unfixed and why.
- Rewrite `# Follow-ups` as the last section of the file. Gather everything left for a person from
  every section of the file into three numbered lists, under these bold labels, and leave out any
  label with nothing under it. If there is nothing at all, write "None."
  - **Decisions:** choices only the user can make. For each one, give the options, your
    recommendation, and the exact file and function each option changes.
  - **Deferred work:** work that outlasts this spec, such as a test that also fails on the base, a
    bug outside the change, or a design question for a later spec. If the project's list of known
    deferred work already has the item, say so instead of describing it again.
  - **Manual steps:** what a person must do by hand, such as live runs, account settings and
    checks on another platform, each with the exact command or place to do it.
- Return a short summary of what was fixed and what was skipped, then the follow-ups as written,
  and stop.

---
name: spec-develop
description: >
  Implement a specification file into code and tests. Use after a plan has been made and the user
  wants to implement it.
argument-hint: "<spec.md> [--wt]"
metadata:
  version: "1.6"
---

Implement a specification file into code and tests. The arguments are the specification file and,
optionally, the `--wt` flag. If a complete specification file is not supplied, ask the user to
provide one and stop.

For a specification file to be considered complete, it must have a `# Design` section with all
decisions resolved. If the specification file is missing a `# Design` section, ask the user to run
`/spec-design` and stop.

# Standing rules

These apply at every step, and to every sub-agent you brief: `spec-test-writer` writes the tests
and `spec-develop-worker` writes the code.

- **The spec must agree with itself.** If two behaviours, or a decision and a behaviour, can't both
  hold as written, stop and ask the user which way to go before you write code that picks one. Use
  `AskUserQuestion`, quote both sides, and give your recommendation first. Record the answer as the
  next `Dn` in `## Decisions`, and amend the behaviour it changes, ending it with `(amended by Dn)`.
  A sub-agent that finds one reports itself blocked; put it to the user the same way.

- **External data is never written from memory.** Data the code embeds or encodes from outside the
  codebase, such as a registry, a published list or a standard's table, is built from the source
  `## External facts` names for it. If you can't reach that source, ask the user before you write
  the data from memory. If they agree, list each such fact under `## Known limitations` as
  *unconfirmed*, with its source, so `/spec-verify` checks it.

- **A test that fails and you didn't expect it to.** Before you treat it as the change's or not,
  find out:
  1. Run it alone, uncached and repeated (in Go, `-count=20`), to see whether it fails every time
     or only sometimes.
  2. Run it the same way on the base commit, in a scratch worktree outside the repository that
     leaves this one alone: `git worktree add --detach <scratch>/base <base commit>`, run the test
     there, then `git worktree remove --force <scratch>/base`. Never stash, reset or check out the
     base in this worktree.
  3. If it fails on the base too, it predates the change: don't fix it within this spec. Record it
     in `## Develop` with the command and how often it failed on each side, and add it to the
     project's list of known deferred work (if its instructions name one) unless it is there
     already. If it fails only with the change, it is the change's: fix it.

  A sub-agent never does this itself: it reports the failure.

- **Code, comments, test names and file names must never cite spec numbers or spec IDs.** Describe
  the behaviour instead.

# Steps

1. **Set up a worktree.** Only if `--wt` was passed; without the flag, skip this step.
   - Bring local `main` up to date: run `git fetch origin`, then find the worktree that has `main`
     checked out with `git worktree list --porcelain`. If one does, run
     `git -C <that worktree> merge --ff-only origin/main`; if none does, run
     `git fetch origin main:main`. If `main` can't fast-forward, tell the user and stop.
   - Create a worktree on a new branch from `main`, named after the spec's goal with a
     conventional-commit prefix:
     `git worktree add -b feat/<short-name> .claude/worktrees/<short-name> main`. Then call
     `EnterWorktree` with that `path`, so every later step, including the forked skills, runs in
     the worktree.
   - Set up the worktree's environment the way the project's instructions (e.g. `CLAUDE.md`) say
     to, such as installing dependencies, without changing any lockfile.
   - Copy the spec file's current contents to the same relative path in the worktree, whether or
     not git tracks it, and use that copy as `<spec file>` from here on.

2. **Record the base.** Run `git rev-parse HEAD`. Add `# Implementation` and `## Develop` to the
   spec file, with `Base commit: <sha>` as the first line of `## Develop`. `/spec-simplify` and
   `/spec-verify` review every file that differs from it, so commits made along the way stay in
   their review.

3. **Read the conventions.** Read the docs listed under `## Conventions`, if any.

4. **Map behaviours to tests.** List every behaviour in the spec next to the test(s) that will pin
   it, using `## Tests`, including its failure-path tests. Every behaviour needs at least one test.

5. **Have the tests written.** Don't write the behaviour tests yourself. Group the behaviours from
   step 4 by the files their tests and stubs touch (one group for a small spec). Spawn one
   `spec-test-writer` agent per group, in one message when their files don't overlap. Brief each
   with the spec path, its behaviours, the tests `## Tests` lists for them, and the test and stub
   files it owns. The agent already carries its rules and report format. When each returns:
   - If it is blocked by a contradiction in the spec, settle it with the user under the standing
     rule, then send the answer back to the same agent.
   - Read its invented signatures. Accept any that fit `# Design`. Put one that changes a decision
     to the user.
   - Note the goldens it left open, and any behaviour it couldn't test. Each is yours to cover in
     step 7.

6. **Watch them fail, then freeze them.** Run the new tests yourself and show the user that they
   fail on their assertions, not on a build error or a panic. The tests the agent said pin existing
   behaviour may pass. Then stage the test files with `git add` (stage only, never commit), so that
   `git diff -- <test files>` shows any later change to them. List the frozen files in
   `## Develop`.

7. **Write the code** that makes the frozen tests pass, yourself or through workers. If you split it
   across sub-agents, spawn each as the `spec-develop-worker` agent and brief it with its group's
   behaviours, its owned files (the stubs included) and its frozen tests. The agent already carries
   the standing rules and report format. Keep every git write to yourself, and check a worker's
   claims against the tree before you repeat them.
   - **Frozen tests don't change.** Adding a test to a frozen file is fine; changing or deleting
     one is not. If a frozen test looks wrong, stop. Show the user the test, the behaviour it pins
     and why it looks wrong, and change it only with their agreement, recording that in
     `## Develop`.
   - **Goldens of new output** that the test writer left open: generate them, read every line
     against the behaviour, and show the user what they contain.
   - **Code the tests don't reach**, such as a helper you add, gets its own tests now. It is the
     first candidate for a mutation check in step 12.
   - **A commit of its own.** If `# Design` asks for part of the change to be committed separately,
     such as a refactor that lands first, commit that part once its tests pass, before you write
     the rest. Use `git commit -- <its files>`, so the frozen tests stay staged and out of it, with
     the message the design gives or a conventional prefix.

8. **Confirm the tests pass and the frozen ones held.** Confirm all the tests pass. Then run
   `git diff -- <frozen test files>`: it must show only added tests, plus any change the user
   agreed to in step 7. Undo any other change by hand.

9. **Update the specification file.** Under the base commit line, finish `# Implementation` using
   the skeleton's headings:
   - `## Develop`: a short, concise account of how the specification was implemented, how each
     behaviour was tested, any deviations from the plan, and any external fact that turned out
     different from `## External facts`.
   - `## Known limitations`: any behaviour, or part of one, that isn't fully met, and edge cases
     that weren't addressed, each naming its behaviour. Never move these into `## Out of scope`;
     that section holds only what the user agreed to leave out.
   - Add anything left for a person to do to `# Follow-ups`.

10. **Simplify the code.** Run `/spec-simplify <spec file>` and show the user its summary of what
    was fixed and what was skipped. If it returns before its sub-agents have reported, wait for
    their reports and handle the findings before continuing.

11. **Confirm the tests still pass.** If a simplification broke a test, fix it before continuing.

12. **Check the tests can fail.** Do this now, once the code has stopped moving, so each check runs
    once. For each behaviour `## Tests` marks for a mutation check, break the code that implements
    it by hand, for example by removing a guard or inverting a condition. Run the tests and confirm
    at least one fails, then undo your edit by hand. Don't undo it with git, which would also
    discard other uncommitted work. If no test fails, add one that does. Record the results in
    `## Develop`.

13. **Verify the implementation.** Run `/spec-verify <spec file>` and show the user its summary of
    what was fixed and what was skipped. If it returns before its sub-agents have reported, wait
    for their reports and handle the findings before continuing.

14. **Settle the follow-ups.** `/spec-verify` sorts `# Follow-ups` into decisions, deferred work
    and manual steps.
    - **Decisions.** Put them to the user with `AskUserQuestion`, up to four per call, the most
      consequential first. Give the recommendation first when there is one, and always offer
      leaving it open. For each answer:
      - Act on it now only if the change is small and within the spec's goal. Have the test
        written and frozen first, as in steps 5 and 6, then write the code and confirm the tests
        pass, as in steps 7 and 8.
      - Record it as the next `Dn` in `## Decisions`, marked as settled after verification. If it
        changes what a behaviour says, amend that behaviour with `(amended by Dn)`.
      - Treat anything larger, and every decision left open, as deferred work.
    - **Deferred work.** Add each item to the project's list of known deferred work, if its
      instructions name one, under the heading that fits. Read the list first: if an item is
      already there, update that entry instead of adding a second one.
    - **Rewrite `# Follow-ups`.** Replace each settled decision with a one-line note of its answer
      and its `Dn`. Replace each deferred item with a one-line pointer to where it now lives. Leave
      the manual steps as they are.

15. **Commit.** Run the project's full test command (here `make test`) and lint. If anything fails,
    apply the failing-test rule above, and don't commit while a failure is the change's own. Move
    the spec file to `docs/specs/done`. Commit the whole change to the current branch with a
    conventional-commit message. If a test also fails on the base, name it in the message body.
    Never push.

16. **Stop.** List the manual steps left in `# Follow-ups`. If `--wt` was passed, also tell the user
    the worktree path and branch, and leave the worktree in place. Then stop.

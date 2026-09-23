# Project Guidelines

## Language

- All source code, comments, variable names, function names, test descriptions, and commit messages must be written in **English only**.
- Responses to the user may be in any language.

## README Files

Each kind of documentation has one job, so that every fact has one home and nothing is kept in two places that can drift apart:

| Where | Its job | Written for |
| --- | --- | --- |
| The repository's root `README.md` | What the product does, where it sits in the auth stack, how to run and configure it | Users and operators |
| A package's root `README.md` | How to use the package and a guide to its public API (linking the definitions) | People installing the package |
| A `README.md` inside a source directory | That directory's responsibility, role and invariants: its boundary, the direction of its dependencies, the contracts it keeps | People changing the code |
| The header comment of a source file | What that file does | People changing the code |

Rules for every README:

- **A last-updated date is required**, on the line directly under the H1 title: `Last updated: YYYY-MM-DD` (`最終更新: YYYY-MM-DD` in a `README.ja.md`). Update it whenever you change the README.
- **Responsibility and role are required**, in a `## Responsibility` section (`## 責務と役割` in Japanese) near the top: what the module is for and where it sits, what it owns and what it does not, and why it is a separate module.
- **Refer to code by file name, never by line number.** Line numbers drift with every edit, and a README does not need that precision.
- **Link definitions instead of copying them.** A copied type or signature drifts from the code.

Rules for a source directory's README — it describes the directory, not its files:

- **No per-file descriptions.** What a file does belongs in that file's header comment, which is the source of truth. Do not add a table of files, a line per file, or per-file dependency lists. Name a file only to point at where a contract or entry point lives.
- **No lists of test names.** Test names change like line numbers do. When an invariant is pinned by tests, name the test file.
- **State invariants as rules**, not as history: what holds now. The history belongs in commits, issues and the CHANGELOG.
- A small directory may be described by its parent's README instead of having its own.

When you change what a directory does, what it depends on or an invariant it keeps, update its README in the same PR. When you change what a file does, update its header comment.

`src/router/` and `src/modes/` are described by `src/README.md`. `README.md` is the source of truth for the root documentation; `README.ja.md` carries the same facts.

## Development Process

- All feature work and bug fixes **must** follow TDD (Test-Driven Development).
- Write the failing test first. Watch it fail. Then write the minimal code to make it pass.
- Never write production code without a failing test that demands it.
- If code was written before its test, delete it and start over from the test.
- When generating implementation plans, every task must include explicit RED → GREEN → REFACTOR steps.

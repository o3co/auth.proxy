# Project Guidelines

## Language

- All source code, comments, variable names, function names, test descriptions, and commit messages must be written in **English only**.
- Responses to the user may be in any language.

## README Files

Every source directory that is a module of its own has a `README.md` (a small directory may instead be described by its parent's README — `src/router/` and `src/modes/` are described by `src/README.md`). Each README follows these rules:

- **A last-updated date is required**, on the line directly under the H1 title: `Last updated: YYYY-MM-DD` (`最終更新: YYYY-MM-DD` in a `README.ja.md`). Update it whenever you change the README.
- **Responsibility and role are required**, in a `## Responsibility` section (`## 責務と役割` in Japanese) near the top: what the module is for and where it sits, what it owns and what it does not, and why it is a separate module.
- **Refer to code by file name, never by line number.** Line numbers drift with every edit, and a README does not need that precision. Link the file, and name the symbol where it helps.
- **Link definitions instead of copying them.** A copied type or signature drifts from the code.
- Other sections are optional and depend on the module.

When you change what a module does or depends on, update its README in the same PR. `README.md` is the source of truth; `README.ja.md` carries the same facts.

## Development Process

- All feature work and bug fixes **must** follow TDD (Test-Driven Development).
- Write the failing test first. Watch it fail. Then write the minimal code to make it pass.
- Never write production code without a failing test that demands it.
- If code was written before its test, delete it and start over from the test.
- When generating implementation plans, every task must include explicit RED → GREEN → REFACTOR steps.

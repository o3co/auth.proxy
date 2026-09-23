# `config`

Last updated: 2026-09-24

The proxy's configuration contract: [`application.conf`](application.conf) is the shipped HOCON with an environment override per key, and [`application.schema.mts`](application.schema.mts) is the Zod schema that validates the parsed file and produces the [`AppConfig`](application.schema.mts) the code reads. The environment variables themselves are listed in the root README under [Configuration](../README.md#configuration). The boundary review behind this file is [#95](https://github.com/o3co/auth.proxy/issues/95).

## Responsibility

**Role.** The configuration contract between the deployment and the code: the deployment sets environment variables (or edits the conf), [`app.mts`](../src/app.mts) parses and validates once at boot, and the routers and the decisions they build read the typed result.

**Owns:** every key's name, type, default and environment override; the cross-field invariants; the `AppConfig` type the code reads.

**Does not own:** what a value *means* at runtime — each reader's README states that; when the file is parsed (`app.mts`); `LOG_LEVEL`, which the logger reads itself.

**Why separate.** The shipped conf and the schema that validates it are one contract — the defaults are declared in both and must agree — and they sit together, apart from the code that reads the result; that is the observed arrangement, not a recorded reason. Why the directory is outside `src/` is not recorded.

## Dependencies

`zod` only. Imported by `src/app.mts` (the one value import: parse and validate) and, as types only, by the mode selection and the mode code. Nothing under `src/express`, `src/oauth` or `src/router` imports it.

## Invariants

- **The schema is authoritative (#95 F23).** Every default is declared twice — as a literal in the conf and as a Zod `.default()` — and the two must agree: the conf literal reaches the code when the environment is silent, the schema default when the key is absent altogether. No parameter default elsewhere in code repeats a configured value. The exceptions (keys whose default lives only in the conf, and keys the conf sets to a placeholder the schema refuses) are listed in the header of [`application.schema.mts`](application.schema.mts).
- **Every key survives the environment round trip.** An override arrives as a string, so numbers are coerced, booleans accept exactly `true` / `false` (a coerced `"false"` would read as `true`), lists are whitespace-split and their entries must be expressible that way, and an empty optional string means unset.
- **Cross-field invariants live only in the schema**; the conf cannot express them.
- **Parsed once, at boot, and never re-read.** The schema never reads the environment — substitution happens in the HOCON parse. A violation stops the process before it listens, naming the key; there is no reload, so a change needs a restart. The parsed object is passed to the routers as an argument, not read from a global.
- **The shipped conf is tested.** [`src/__tests__/config.test.mts`](../src/__tests__/config.test.mts) parses the shipped `application.conf` with environment overrides, so a conf literal that drifts from what a test asserts is caught there. That every conf literal equals its schema default is checked only for the keys those tests assert.

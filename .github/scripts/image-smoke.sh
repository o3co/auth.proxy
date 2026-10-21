#!/usr/bin/env bash
# Runs a built runtime image the way an orchestrator does and checks what an
# operator relies on: it runs as a non-root user, ships no tests, boots on a
# read-only root filesystem without network access, turns healthy through its
# own HEALTHCHECK, and on SIGTERM drains and exits 0 with nothing on stderr.
#
# Usage: image-smoke.sh <image>
set -euo pipefail

image="${1:?usage: image-smoke.sh <image>}"
name="auth-proxy-smoke-$$"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}
cleanup() {
	docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

uid="$(docker run --rm --entrypoint id "$image" -u)"
[ "$uid" != 0 ] || fail "the image runs as root"

tests="$(docker run --rm --entrypoint find "$image" dist -name __tests__)"
[ -z "$tests" ] || fail "the image ships tests: $tests"

# Nothing listens on port 9: the proxy boots without reaching either, and the
# liveness probe does not depend on them.
docker run -d --name "$name" --read-only --network none \
	-e AUTH_MODE=validation \
	-e INTROSPECT_URL=http://127.0.0.1:9/oauth/introspect \
	-e UPSTREAM_BASEURL=http://127.0.0.1:9 \
	"$image" >/dev/null

status=starting
for _ in $(seq 1 60); do
	status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$name")"
	[ "$status" != none ] || fail "the image has no HEALTHCHECK"
	[ "$status" != healthy ] || break
	if [ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]; then
		docker logs "$name" >&2 || true
		fail "the container exited while booting"
	fi
	sleep 1
done
[ "$status" = healthy ] || fail "not healthy after 60s: $status"

# docker stop sends SIGTERM, and SIGKILL only after the 30s grace.
docker stop -t 30 "$name" >/dev/null
code="$(docker inspect -f '{{.State.ExitCode}}' "$name")"
[ "$code" = 0 ] || fail "exit code $code after SIGTERM"
docker logs "$name" 2>/dev/null | grep -q '"msg":"graceful shutdown: complete"' ||
	fail "SIGTERM did not run the graceful shutdown"
stderr="$(docker logs "$name" 2>&1 >/dev/null)"
[ -z "$stderr" ] || fail "stderr is not empty: $stderr"

echo "ok: $image"

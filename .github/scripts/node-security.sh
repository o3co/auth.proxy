#!/usr/bin/env bash
# Checks that an image's Node.js runtime is not behind a security release of
# its major line, as listed in Node's release index. Trivy does not read the
# node binary of the official Node images, so it cannot see this; and a
# security release that reaches only a newer minor never reaches an image
# whose FROM line names an older minor, however often it is rebuilt.
#
# Prints a Markdown section for a job summary. Exits 1 when the major has a
# newer security release, and 2 when the check could not be made: it passes
# only on a release index it has read and that lists the image's version.
#
# Usage: node-security.sh <image>
set -euo pipefail

image="${1:?usage: node-security.sh <image>}"
index_url=https://nodejs.org/dist/index.json

echo "### Node.js security releases"
echo

not_checked() {
	echo "**Not checked:** $*"
	exit 2
}

version="$(docker run --rm --entrypoint node "$image" -p process.version)" ||
	not_checked "could not read the Node version of \`$image\`."
[[ "$version" =~ ^v([0-9]+)\.[0-9]+\.[0-9]+$ ]] ||
	not_checked "\`$image\` reports Node version \`$version\`."
major="${BASH_REMATCH[1]}"

index="$(curl -fsSL --retry 3 --max-time 60 "$index_url")" ||
	not_checked "could not fetch $index_url."

# Prints `<listed> <newest>`: whether the index lists the image's version, and
# the newest security release of its major ("none" when there is none).
# Versions compare as arrays of numbers. Prereleases in the index
# (`v27.0.0-alpha.0.1.0`) are not releases an image runs, and are skipped.
result="$(jq -r --arg version "$version" --argjson major "$major" '
	def parts: ltrimstr("v") | split(".") | map(tonumber);
	[.[] | select(.version | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$")) | select((.version | parts)[0] == $major)] as $line
	| ([$line[] | select(.version == $version)] | length > 0) as $listed
	| ([$line[] | select(.security == true)] | max_by(.version | parts) | .version // "none") as $newest
	| "\($listed) \($newest)"
' <<<"$index")" || not_checked "could not parse $index_url."
read -r listed newest <<<"$result"

[ "$listed" = true ] ||
	not_checked "$index_url does not list Node $version, the version \`$image\` runs."

if [ "$newest" = none ]; then
	echo "Node $version: Node $major has no security release."
	exit 0
fi

newer="$(jq -rn --arg a "$version" --arg b "$newest" '
	def parts: ltrimstr("v") | split(".") | map(tonumber);
	($b | parts) > ($a | parts)
')"
if [ "$newer" = true ]; then
	[[ "$newest" =~ ^v([0-9]+\.[0-9]+)\. ]]
	echo "**Fail:** \`$image\` runs Node $version, older than $newest, the newest security release of Node $major. The FROM line must name Node ${BASH_REMATCH[1]} or later."
	exit 1
fi
echo "Node $version: no newer security release of Node $major (newest: $newest)."

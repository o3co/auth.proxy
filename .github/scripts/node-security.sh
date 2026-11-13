#!/usr/bin/env bash
# Checks that an image's Node.js runtime is not behind a security release of
# its major line, as listed in Node's release index. Trivy does not read the
# node binary of the official Node images, so it cannot see this; and a
# security release that reaches only a newer minor never reaches an image
# whose FROM line names an older minor, however often it is rebuilt.
#
# Prints a Markdown section for a job summary. Exits 1 when the major has a
# newer security release, and 2 when the check could not be made: it passes
# only on a release index it has read, that lists the image's version, and
# that marks every newer release of the major as a security release or not.
#
# NODE_INDEX_FILE reads the index from that file instead of nodejs.org; it
# exists to test this check.
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

if [ -n "${NODE_INDEX_FILE:-}" ]; then
	index_url="$NODE_INDEX_FILE"
	index="$(cat "$NODE_INDEX_FILE")" || not_checked "could not read $index_url."
else
	index="$(curl -fsSL --retry 3 --max-time 60 "$index_url")" ||
		not_checked "could not fetch $index_url."
fi

# Prints `<listed> <unmarked> <newer> <newest>`, over the releases of the
# image's major:
#   listed    whether the index lists the image's version;
#   unmarked  the first release newer than the image's without a boolean
#             `security` ("none" when every one has it);
#   newer     the newest security release newer than the image's ("none");
#   newest    the newest security release ("none").
# Versions compare as arrays of numbers. Prereleases in the index
# (`v27.0.0-alpha.0.1.0`) are not releases an image runs, and are skipped.
result="$(jq -r --arg version "$version" --argjson major "$major" '
	def parts: ltrimstr("v") | split(".") | map(tonumber);
	($version | parts) as $current
	| [.[] | select(.version | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$")) | select((.version | parts)[0] == $major)] as $line
	| [$line[] | select((.version | parts) > $current)] as $after
	| [
		([$line[] | select(.version == $version)] | length > 0),
		([$after[] | select((.security | type) != "boolean")] | first | .version // "none"),
		([$after[] | select(.security == true)] | max_by(.version | parts) | .version // "none"),
		([$line[] | select(.security == true)] | max_by(.version | parts) | .version // "none")
	]
	| map(tostring) | join(" ")
' <<<"$index")" || not_checked "could not parse $index_url."
read -r listed unmarked newer newest <<<"$result"

[ "$listed" = true ] ||
	not_checked "$index_url does not list Node $version, the version \`$image\` runs."
[ "$unmarked" = none ] ||
	not_checked "$index_url does not say whether Node $unmarked, newer than the image's $version, is a security release."

if [ "$newer" != none ]; then
	[[ "$newer" =~ ^v([0-9]+\.[0-9]+)\. ]]
	echo "**Fail:** \`$image\` runs Node $version, older than $newer, the newest security release of Node $major. The FROM line must name Node ${BASH_REMATCH[1]} or later."
	exit 1
fi
echo "Node $version: no newer security release of Node $major (newest: $newest)."

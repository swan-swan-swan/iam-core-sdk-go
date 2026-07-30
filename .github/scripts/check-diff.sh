#!/usr/bin/env bash

set -euo pipefail

event_name=${IAMCORE_CI_EVENT_NAME:?IAMCORE_CI_EVENT_NAME is required}
head_sha=${IAMCORE_CI_HEAD_SHA:?IAMCORE_CI_HEAD_SHA is required}
base_sha=${IAMCORE_CI_BASE_SHA:-}
before_sha=${IAMCORE_CI_BEFORE_SHA:-}
zero_sha=0000000000000000000000000000000000000000

is_sha() {
	[[ $1 =~ ^[0-9a-fA-F]{40}$ ]]
}

if ! is_sha "$head_sha"; then
	echo "invalid head SHA" >&2
	exit 1
fi
git cat-file -e "${head_sha}^{commit}"

case "$event_name" in
pull_request)
	if ! is_sha "$base_sha"; then
		echo "invalid pull request base SHA" >&2
		exit 1
	fi
	git cat-file -e "${base_sha}^{commit}"
	if [[ $(git rev-parse HEAD) != "$head_sha" ]]; then
		echo "checked-out HEAD does not match event SHA" >&2
		exit 1
	fi
	git diff --check "${base_sha}...HEAD" --
	;;
push)
	if [[ "$before_sha" == "$zero_sha" ]]; then
		empty_tree=$(git hash-object -t tree /dev/null)
		git diff --check "$empty_tree" "$head_sha" --
		exit 0
	fi
	if ! is_sha "$before_sha"; then
		echo "invalid push before SHA" >&2
		exit 1
	fi
	git cat-file -e "${before_sha}^{commit}"
	git diff --check "${before_sha}..${head_sha}" --
	;;
*)
	echo "unsupported event" >&2
	exit 1
	;;
esac

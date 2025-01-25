#!/bin/bash

echo Running all tests

cd "$HOME/dev/personal/cryptopals/"

tempfile="$(mktemp)"
trap 'rm -f "$tempfile"' EXIT

go test -json ./... > "$tempfile"

jq -r 'select(.Action=="fail" and .Test) | [.Package, .Test]' "$tempfile"

exit 0

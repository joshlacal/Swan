#!/usr/bin/env bash
set -euo pipefail

sha256_digest() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print $1}'
  else
    echo "sha256: requires sha256sum or shasum" >&2
    exit 127
  fi
}

if [[ "${1:-}" == "--check" ]]; then
  [[ $# == 2 ]] || { echo "usage: $0 --check <manifest>" >&2; exit 2; }
  manifest="$2"
  while IFS=' ' read -r expected path; do
    [[ -n "${expected}" ]] || continue
    [[ "${expected}" =~ ^[[:xdigit:]]{64}$ && -n "${path:-}" ]] || {
      echo "sha256: malformed manifest entry in ${manifest}" >&2
      exit 1
    }
    actual="$(sha256_digest "${path}")"
    [[ "${actual}" == "${expected}" ]] || {
      echo "${path}: FAILED" >&2
      exit 1
    }
    echo "${path}: OK"
  done <"${manifest}"
else
  [[ $# == 1 ]] || { echo "usage: $0 <file>" >&2; exit 2; }
  printf '%s  %s\n' "$(sha256_digest "$1")" "$1"
fi

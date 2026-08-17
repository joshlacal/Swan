#!/bin/sh
set -eu
backup="$(Scripts/task8-disposable-backup-restore.sh)"
rotation="$(Scripts/task8-disposable-key-rotation.sh)"
case "$backup$rotation" in
  *secret*|*password*|*token*|*did:plc*) exit 1 ;;
esac
case "$backup$rotation" in
  *deferred*) printf '%s\n' 'task8 disposable drills: deferred (integration seam unavailable)' ;;
  *) exit 1 ;;
esac

#!/usr/bin/env bash
# Scoped 0.4.1 Ruby mutation pass (farm job): run.sh NAME FILE:RANGE [FILE:RANGE ...]; results -> /tmp/r041rb/NAME-*.json
set -u
for i in 1 2 3; do ruby -e "require %q(parser/current)" 2>/dev/null && break; gem install --user-install --no-document parser 2>&1 | tail -2; sleep 5; done
N=$1; shift
mkdir -p /tmp/r041rb
cd tools/pca-audit/ruby-mutate
for spec in "$@"; do
  f=${spec%%:*}; r=${spec##*:}; tag=$(basename "$f" .rb)-$r
  echo "== $spec"
  MUT_FIRST=r041 MUT_STREAM=/tmp/r041rb/$N-$tag.stream ruby mutate.rb "../../../sdks/ruby-pca/$f" --jobs 2 --timeout 600 --lines "$r" \
    > "/tmp/r041rb/$N-$tag.json" 2> >(grep -v 'warning: parser\|Please see' >&2)
  echo "rc=$? $(grep -c '"status"' /tmp/r041rb/$N-$tag.json) mutants, $(grep -c '"SURVIVED"' /tmp/r041rb/$N-$tag.json) survived"
done

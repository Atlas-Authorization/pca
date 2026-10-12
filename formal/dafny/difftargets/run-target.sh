#!/usr/bin/env bash
# run-target.sh <target> <outdir> <casefile>   -> transcript on stdout
t="$1"; O="$2"; f="$3"
case "$t" in
  cs)   dotnet "$O/cs/h.dll" "$f" ;;
  go)   "$O/go/h" "$f" ;;
  java) java -Xss64m -jar "$O/java/h.jar" "$f" ;;
  py)   python3 "$O/py/h-py/__main__.py" "$f" ;;
  js)   node "$O/js/h.js" "$f" ;;
  *) echo "unknown target $t" >&2; exit 2 ;;
esac

#!/bin/sh
# Generate the Deterministic Falcon implementation source(s) from the single
# template deterministic.c.tmpl. One file is produced per Falcon parameter n
# (e.g. deterministic1024.c for n = 1024, deterministic512.c for n = 512);
# generating them all from one template keeps their shared algorithm body
# from diverging.
#
# The lines of the template up to the __FALCON_DET_VERBATIM__ marker are the
# template's own documentation and are dropped. The lines between the
# __FALCON_DET_VERBATIM__ and __FALCON_DET_EXPAND__ markers (the #includes)
# are copied verbatim. Everything after __FALCON_DET_EXPAND__ is run through
# the C preprocessor with DET_N set to the parameter n -- e.g. 1024
# (falcon_det1024_*) or 512 (falcon_det512_*) -- which selects the function
# family and the matching parameter set.
#
# The template is tab-indented like the rest of the tree. The body is passed
# through "expand" before the C preprocessor (which would otherwise collapse
# each tab to a single space, destroying the indentation) and back through
# "unexpand" afterwards, so the generated files keep the tab indentation used
# throughout the rest of the tree.
#
# POSIX sh, plus "mktemp -d TEMPLATE" (not in POSIX, but in GNU, BSD and
# busybox mktemp).
#
# Usage: gen_deterministic.sh CC OUTDIR N...
#   CC      C compiler to use as the preprocessor, e.g. cc
#   OUTDIR  directory to write the generated files into; a relative path is
#           interpreted relative to the repository root
#   N...    Falcon parameters n to generate, e.g. "1024 512"; the Makefile
#           passes a single n to regenerate one file at a time, which keeps
#           the per-file rules race-free under "make -j"
set -eu

[ $# -ge 3 ] || { echo "usage: $0 CC OUTDIR N..." >&2; exit 2; }
CC="$1"
OUT="$2"
shift 2
SEEN_N=' '
for n in "$@"; do
	case "$n" in *[!0-9]* | '' | 0*)
		echo "$0: n must be a positive integer, not '$n'" >&2; exit 2
	esac
	case "$SEEN_N" in *" $n "*)
		echo "$0: duplicate n '$n'" >&2; exit 2
	esac
	SEEN_N="$SEEN_N$n "
done

# The template lives in the repository root, one level above this script.
# Work from there so the script behaves the same wherever it is invoked from.
cd "$(dirname "$0")/.."

IN="deterministic.c.tmpl"
BANNER='/* GENERATED from deterministic.c.tmpl -- DO NOT EDIT. Run "make gen" to regenerate. */'

# Reject directory targets before generating anything. Without this check, mv
# treats one as a destination directory, puts the generated file inside it,
# and reports success without replacing the requested path.
for n in "$@"; do
	if [ -d "$OUT/deterministic$n.c" ]; then
		echo "$0: output is a directory: '$OUT/deterministic$n.c'" >&2
		exit 2
	fi
done

# Use a directory on the destination filesystem so completed outputs can be
# moved into place atomically.
GEN_TMPDIR=$(mktemp -d "$OUT/.falcon-det-gen.XXXXXX")
trap 'rm -rf "$GEN_TMPDIR"' 0
# The signal traps exit so the EXIT trap above cleans up and the script stops
# instead of carrying on with its working directory already removed.
trap 'exit 1' HUP INT TERM

# Build deterministic<n>.c for DET_N = $1 under $GEN_TMPDIR. Call it as a plain
# statement: inside "if" or an && / || list "set -e" is suspended, and a failing
# stage would go unnoticed.
generate() {
	echo "generating deterministic$1.c from $IN"
	STAGED="$GEN_TMPDIR/deterministic$1.c"
	{
		printf '%s\n' "$BANNER"
		# Verbatim section: lines between the two markers (exclusive).
		awk '/__FALCON_DET_EXPAND__/{exit} v; /__FALCON_DET_VERBATIM__/{v=1}' "$IN"
	} > "$STAGED"
	# Expanded section: everything after the EXPAND marker. -C keeps
	# comments, no -P so blank lines survive, and grep strips the line
	# markers cpp emits. -ffreestanding stops gcc on glibc systems from
	# pre-including <stdc-predef.h>, whose comments -C would otherwise copy
	# into the output. Each stage is a separate command because POSIX sh
	# has no pipefail.
	awk 'e; /__FALCON_DET_EXPAND__/{e=1}' "$IN" > "$GEN_TMPDIR/body"
	expand -t 8 "$GEN_TMPDIR/body" > "$GEN_TMPDIR/expanded"
	"$CC" -E -C -ffreestanding -DDET_N="$1" -x c "$GEN_TMPDIR/expanded" > "$GEN_TMPDIR/preprocessed"
	grep -vE '^# [0-9]' "$GEN_TMPDIR/preprocessed" > "$GEN_TMPDIR/filtered"
	unexpand "$GEN_TMPDIR/filtered" >> "$STAGED"
}

# Generate every file before moving any into place, so a generation failure
# leaves all the existing files untouched. Install them together with one mv
# invocation; each individual replacement is atomic because GEN_TMPDIR is on
# the destination filesystem.
for n in "$@"; do
	generate "$n"
done
mv "$GEN_TMPDIR"/deterministic*.c "$OUT"

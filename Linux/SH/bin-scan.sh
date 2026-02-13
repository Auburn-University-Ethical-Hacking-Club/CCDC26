#!/usr/bin/env bash
# axon | AU
set -euo pipefail

WEBHOOK=""

XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
STATE_DIR_DEFAULTS=("/root/.bin-monitor" "/var/lib/bin-monitor" "$XDG_DATA_HOME/bin-monitor" "$HOME/.local/share/bin-monitor")
BASEFILE_NAME=".baseline.csv"
TMPDIR=""
HASH_CMD=""
STAT_CMD=""
CHATTR_CMD=""
CURL_CMD=""

usage(){
	printf "usage: %s [--init|--scan|--update|--list] [--state DIR] [--paths DIR1,DIR2,...] [--webhook URL]\n" "$(basename "$0")"
	exit 1
}

detect_tools(){
	if command -v sha256sum >/dev/null 2>&1; then
		HASH_CMD="sha256sum"
	elif command -v openssl >/dev/null 2>&1; then
		HASH_CMD="openssl"
	else
		printf "need sha256sum or openssl in PATH\n" >&2
		exit 2
	fi

	if stat --version >/dev/null 2>&1; then
		STAT_CMD="stat -c %Y"
	else
		if command -v python3 >/dev/null 2>&1; then
			STAT_CMD="python3"
		elif command -v python >/dev/null 2>&1; then
			STAT_CMD="python"
		else
			printf "need GNU stat or python for mtime\n" >&2
			exit 2
		fi
	fi

	if command -v chattr >/dev/null 2>&1; then
		CHATTR_CMD="chattr"
	else
		CHATTR_CMD=""
	fi

	if command -v curl >/dev/null 2>&1; then
		CURL_CMD="curl"
	else
		CURL_CMD=""
	fi
}

choose_state_dir(){
	local candidate
	if [[ -n "${STATE_DIR:-}" ]]; then
		mkdir -p "$STATE_DIR"
		[[ -d "$STATE_DIR" ]] || { printf "cannot create %s\n" "$STATE_DIR" >&2; exit 3; }
		echo "$STATE_DIR"
		return
	fi
	for candidate in "${STATE_DIR_DEFAULTS[@]}"; do
		[[ -z "$candidate" ]] && continue
		mkdir -p "$candidate" 2>/dev/null || true
		if [[ -d "$candidate" && -w "$candidate" ]]; then
			echo "$candidate"
			return
		fi
	done
	printf "no writable state dir; use --state DIR\n" >&2
	exit 3
}

hash_for(){
	local file="$1"
	if [[ "$HASH_CMD" == "sha256sum" ]]; then
		sha256sum -- "$file" 2>/dev/null | awk '{print $1}'
	else
		openssl dgst -sha256 -- "$file" 2>/dev/null | awk '{print $NF}'
	fi
}

mtime_for(){
	local file="$1"
	if [[ $STAT_CMD == stat* ]]; then
		stat -c %Y -- "$file" 2>/dev/null || echo 0
	else
		"$STAT_CMD" - "$file" 2>/dev/null <<'PY'
import os,sys
print(int(os.path.getmtime(sys.argv[1])))
PY
	fi
}

make_scan(){
	local outfile="$1"; shift
	local -a paths=("$@")
	: > "$outfile"
	for p in "${paths[@]}"; do
		[[ -d "$p" ]] || continue
		while IFS= read -r -d '' f; do
			[[ -r "$f" ]] || continue
			local h s m
			h=$(hash_for "$f") || continue
			s=$(stat -c %s -- "$f" 2>/dev/null || echo 0)
			m=$(mtime_for "$f")
			printf "%s|%s|%s|%s\n" "$f" "$h" "$s" "$m" >> "$outfile"
		done < <(find "$p" -xdev -type f -perm /111 -print0 2>/dev/null)
	done
	sort -u "$outfile" -o "$outfile"
}

unset_immutable_if_needed(){
	local file="$1"
	if [[ -n "$CHATTR_CMD" && -e "$file" ]]; then
		$CHATTR_CMD -i "$file" 2>/dev/null || true
	fi
}

set_immutable_if_possible(){
	local file="$1"
	if [[ -n "$CHATTR_CMD" && -e "$file" ]]; then
		$CHATTR_CMD +i "$file" 2>/dev/null || true
	fi
}

# Plain-text, safe JSON post (no tabs; escape \ " and newlines)
notify_discord(){
	local webhook="$1"; shift
	local msg="$*"
	[[ -n "$webhook" ]] || return 0
	[[ -n "$CURL_CMD" ]] || { printf "curl missing; skipping webhook\n" >&2; return 0; }

	# length headroom
	msg="$(printf '%s' "$msg" | head -c 1800)"
	# remove tabs/CRs
	msg="${msg//$'\t'/  }"
	msg="${msg//$'\r'/}"

	# escape backslashes then quotes; convert real newlines to \n
	local esc
	esc="$(printf '%s' "$msg" | sed 's/\\/\\\\/g; s/"/\\"/g; :a;N;$!ba;s/\n/\\n/g')"

	$CURL_CMD -sS -H "Content-Type: application/json" \
		--data "{\"content\":\"$esc\"}" "$webhook" >/dev/null 2>&1 || true
}

compare_baseline(){
	local baseline="$1"
	local current="$2"
	awk -F'|' '
		NR==FNR { bs[$1]=$0; next }
		{ cs[$1]=$0 }
		END {
			for (p in cs) {
				if (!(p in bs)) {
					print "ADDED|" cs[p]
				} else {
					split(bs[p],b,"|"); split(cs[p],c,"|")
					if (b[2]!=c[2] || b[3]!=c[3] || b[4]!=c[4]) {
						print "CHANGED|" p "|" b[2] "|" b[3] "|" b[4] "|" c[2] "|" c[3] "|" c[4]
					} else {
						print "UNCHANGED|" cs[p]
					}
				}
			}
			for (p in bs) {
				if (!(p in cs)) {
					print "REMOVED|" bs[p]
				}
			}
		}
	' "$baseline" "$current"
}

COMMAND="scan"
USER_PATHS="/bin,/sbin,/usr/bin,/usr/sbin,/usr/local/bin,/usr/local/sbin,/opt,/snap/bin"
STATE_DIR=""
CHANGES_ONLY=0
while [[ $# -gt 0 ]]; do
	case "$1" in
		--init) COMMAND="init"; shift ;;
		--scan) COMMAND="scan"; shift ;;
		--update) COMMAND="update"; shift ;;
		--list) COMMAND="list"; shift ;;
		--state) STATE_DIR="$2"; shift 2 ;;
		--paths) USER_PATHS="$2"; shift 2 ;;
		--webhook) WEBHOOK="$2"; shift 2 ;;
		--changes-only) CHANGES_ONLY=1; shift ;; #will not show "UNCHANGED" Binaries
		-h|--help) usage ;;
		*) printf "unknown arg: %s\n" "$1" >&2; usage ;;
	esac
done

detect_tools
STATE_DIR=$(choose_state_dir)
BASEFILE="$STATE_DIR/$BASEFILE_NAME"
TMPDIR=$(mktemp -d /tmp/binmon.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

IFS=',' read -r -a PATH_ARR <<< "$USER_PATHS"
scan_dirs=()
for d in "${PATH_ARR[@]}"; do
	[[ -z "$d" ]] && continue
	[[ -d "$d" ]] || continue
	scan_dirs+=("$d")
done
[[ ${#scan_dirs[@]} -gt 0 ]] || { printf "no valid scan paths\n" >&2; exit 4; }

CURRENT="$TMPDIR/current.csv"

case "$COMMAND" in
	init)
		mkdir -p "$STATE_DIR"
		[[ -e "$BASEFILE" ]] && unset_immutable_if_needed "$BASEFILE"
		make_scan "$CURRENT" "${scan_dirs[@]}"
		mv "$CURRENT" "$BASEFILE"
		chmod 0644 "$BASEFILE" 2>/dev/null || true
		set_immutable_if_possible "$BASEFILE"
		printf "baseline written to %s (immutable if chattr available)\n" "$BASEFILE"
		notify_discord "$WEBHOOK" "[bin-monitor] $(hostname)\nBaseline created at: $BASEFILE"
		;;
	list)
		[[ -f "$BASEFILE" ]] || { printf "no baseline at %s — run --init first\n" "$BASEFILE" >&2; exit 5; }
		cut -d'|' -f1 "$BASEFILE"
		;;
	scan)
		[[ -f "$BASEFILE" ]] || { printf "no baseline at %s — run --init first\n" "$BASEFILE" >&2; exit 5; }
		make_scan "$CURRENT" "${scan_dirs[@]}"
		RESULTS="$TMPDIR/results.txt"
		compare_baseline "$BASEFILE" "$CURRENT" > "$RESULTS"

		added_count=$(grep -c '^ADDED|' "$RESULTS" || true)
		removed_count=$(grep -c '^REMOVED|' "$RESULTS" || true)
		changed_count=$(grep -c '^CHANGED|' "$RESULTS" || true)
		unchanged_count=$(grep -c '^UNCHANGED|' "$RESULTS" || true)
		printf "STATUS SUMMARY: Added=%s Removed=%s Changed=%s Unchanged=%s\n" "$added_count" "$removed_count" "$changed_count" "$unchanged_count"

		awk -F'|' -v changes_only="$CHANGES_ONLY" ' 
			BEGIN { print "STATUS | PATH | HASH/DELTA | SIZE | MTIME" }
			$1=="ADDED"     { printf "ADDED    | %s | %s | %s | %s\n", $2,$3,$4,$5; next }
			$1=="REMOVED"   { printf "REMOVED  | %s | %s | %s | %s\n", $2,$3,$4,$5; next }
			$1=="UNCHANGED" { if (!changes_only) printf "UNCHANGED| %s\n", $2; next }
			$1=="CHANGED" {
				printf "CHANGED  | %s\n\t  baseline: %s | size:%s mtime:%s\n\t  current : %s | size:%s mtime:%s\n",
				       $2,$3,$4,$5,$6,$7,$8; next
			}
		' "$RESULTS"

		if [[ -n "$WEBHOOK" ]]; then
			snippet=$(grep -E '^(ADDED|REMOVED|CHANGED)\|' "$RESULTS" | head -n 5 | \
				awk -F'|' '
					$1=="ADDED"   {printf "• [ADDED] %s\n",$2}
					$1=="REMOVED" {printf "• [REMOVED] %s\n",$2}
					$1=="CHANGED" {printf "• [CHANGED] %s\n",$2}
				')
			# FIX: Count only real changes, not UNCHANGED
			total_changes=$(grep -Ec '^(ADDED|REMOVED|CHANGED)\|' "$RESULTS" || true)
			if (( total_changes > 10 )); then
				snippet="${snippet}...and more changes omitted."
			fi

			msg="[bin-monitor] $(hostname)
Added: $added_count  Removed: $removed_count  Changed: $changed_count

$snippet"
			notify_discord "$WEBHOOK" "$msg"
		fi
		;;
	update)
		[[ -f "$BASEFILE" ]] || { printf "no baseline at %s — run --init first\n" "$BASEFILE" >&2; exit 5; }
		unset_immutable_if_needed "$BASEFILE"
		make_scan "$CURRENT" "${scan_dirs[@]}"
		mv "$CURRENT" "$BASEFILE"
		chmod 0644 "$BASEFILE" 2>/dev/null || true
		set_immutable_if_possible "$BASEFILE"
		printf "baseline updated at %s (immutable if chattr available)\n" "$BASEFILE"
		notify_discord "$WEBHOOK" "[bin-monitor] $(hostname)\nBaseline updated at: $BASEFILE"
		;;
	*)
		printf "unknown command\n" >&2
		exit 1
		;;
esac

#!/bin/sh
# Unit tests for gsb.ko. Run as root inside the FreeBSD VM:
#   sh run_tests.sh <path/to/gsb.ko> <path/to/gsbstub>
set -u
KO=${1:?gsb.ko}
STUB=${2:?gsbstub}
pass=0 fail=0

ok()  { pass=$((pass+1)); printf 'ok   %-4s %s\n' "$1" "$2"; }
bad() { fail=$((fail+1)); printf 'FAIL %-4s %s (%s)\n' "$1" "$2" "$3"; }

run() {	# run <test#>; echo exit status (128+N when killed by signal N)
	"$STUB" "$1" >/dev/null 2>&1
	echo $?
}

check() {	# check <test#> <description> <expected statuses...>
	t=$1 d=$2; shift 2
	got=$(run "$t")
	for want in "$@"; do
		[ "$got" = "$want" ] && { ok "T$t" "$d"; return; }
	done
	bad "T$t" "$d" "got $got, want $*"
}

# T0: without the module the stub must not run at all (fail closed).
kldstat -q -n gsb && kldunload gsb
"$STUB" 1 >/dev/null 2>&1; rc=$?
[ "$rc" = 126 ] || [ "$rc" = 127 ] && ok T0 "unbranded exec refused without gsb.ko" \
    || bad T0 "unbranded exec refused without gsb.ko" "exit $rc"

kldload "$KO" || exit 1
r0=$(sysctl -n security.gsb.redirects)

check 1  "app syscall redirected; Sentry result returned"        42
check 2  "int 0x80 redirected"                                   43
check 3  "app jumping into stub syscall insn is redirected"      44
check 4  "sysenter faults, never executes a syscall"             104 110 111
check 5  "vsyscall page access faults at 0xffffffffff600000"     111
check 6  "stub-mode syscall from outside stub text redirected"   45
check 7  "mmap/mprotect/munmap over stub text refused"           46
check 8  "sigaction handler outside stub text refused"           47
check 9  "redirect without SIGSYS handler kills (SIGSYS)"        140
check 10 "thr_new start_func outside stub text refused"          48
check 11 "Linux register semantics (r10/rcx/r11) preserved"      50
check 12 "app-mode syscall from app memory redirected"           44

# T13: process runs under the GSB sysentvec.
"$STUB" 99 & pid=$!
sleep 1
sv=$(ps -o emul= -p "$pid" | sed 's/ *$//')
osrel=$(procstat -b "$pid" | awk 'NR==2{print $3}')
kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
[ "$sv" = "GSB ELF64" ] && ok T13 "sysentvec is GSB ELF64" || bad T13 "sysentvec is GSB ELF64" "emul '$sv'"
[ "$osrel" = "$(sysctl -n kern.osreldate)" ] && ok T14 "osrel taken from GSB note ($osrel)" \
    || bad T14 "osrel taken from GSB note" "osrel '$osrel'"

r1=$(sysctl -n security.gsb.redirects)
echo "-- redirects: $((r1 - r0)), passthroughs: $(sysctl -n security.gsb.passthroughs), denials: $(sysctl -n security.gsb.denials)"
echo "-- $pass passed, $fail failed"
[ "$fail" = 0 ]

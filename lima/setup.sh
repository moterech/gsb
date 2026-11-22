#!/bin/sh
# Provision the gsb-dev guest (run as root inside the VM).
set -eu

REL=15.1-RELEASE

# Toolchain and utilities. The kmod builds with base clang; Go for the Sentry port.
env ASSUME_ALWAYS_YES=yes pkg bootstrap -f
pkg install -y git go gmake bash python3 ca_root_nss

# Kernel source matching the running kernel (needed to build kmods).
if [ ! -f /usr/src/sys/conf/kmod.mk ]; then
	if fetch -o /tmp/src.txz "https://download.freebsd.org/releases/amd64/${REL}/src.txz"; then
		tar -C / -xf /tmp/src.txz
		rm -f /tmp/src.txz
	else
		git clone --depth 1 --branch "releng/${REL%-RELEASE}" https://git.freebsd.org/src.git /usr/src
	fi
fi

# DTrace for the acceptance measurements.
kldload -n dtraceall
grep -q '^dtraceall_load=' /boot/loader.conf || echo 'dtraceall_load="YES"' >> /boot/loader.conf

# The Linuxulator must stay unloaded so that results show no dependence on it.
for m in linux64 linux linux_common; do kldunload -n "$m" 2>/dev/null || true; done
sysrc -x linux_enable 2>/dev/null || true

echo "== kernel: $(uname -r)  src: $(sed -n 's/^REVISION="\(.*\)"/\1/p;s/^BRANCH="\(.*\)"/\1/p' /usr/src/sys/conf/newvers.sh | paste -sd- -)"
go version
kldstat | grep -E 'dtrace|linux' || true

# Spike: C mini-Sentry + gsb stub round trip.
CC?=		cc
STUB_CFLAGS=	-O2 -g -Wall -Werror -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-pic -fno-pie -fcf-protection=none \
		-mgeneral-regs-only
STUB_LDFLAGS=	-static -nostdlib -Wl,-no-pie -Wl,--build-id=none

all: spike_stub sentry native_sigsys

spike_stub: spike_stub.c stub_rt.S spike.h ../kmod/gsb/gsb_abi.h
	${CC} ${STUB_CFLAGS} ${STUB_LDFLAGS} -o ${.TARGET}.tmp ${.ALLSRC:M*.[cS]}
	brandelf -f 255 ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}

sentry: sentry.c spike.h
	${CC} -O2 -g -Wall -Werror -o ${.TARGET} ${.ALLSRC:M*.c}

clean:
	rm -f spike_stub spike_stub.tmp sentry native_sigsys

native_sigsys: native_sigsys.c
	${CC} -O2 -g -Wall -Werror -o ${.TARGET} ${.ALLSRC:M*.c}

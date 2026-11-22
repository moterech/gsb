# Freestanding, static, non-PIE test stub carrying the GSB brand.
CC?=		cc
CFLAGS=		-O2 -g -Wall -Werror -ffreestanding -fno-builtin \
		-fno-stack-protector -fno-pic -fno-pie -fcf-protection=none \
		-mno-sse -mno-avx -mgeneral-regs-only
LDFLAGS=	-static -nostdlib -Wl,-no-pie -Wl,--build-id=none

all: gsbstub

gsbstub: stub.c stub_asm.S ../gsb_abi.h
	${CC} ${CFLAGS} ${LDFLAGS} -o ${.TARGET}.tmp ${.ALLSRC:M*.[cS]}
	brandelf -f 255 ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}

clean:
	rm -f gsbstub gsbstub.tmp

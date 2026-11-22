KMOD=	gsb
SRCS=	gsb.c gsb_abi.h

# GENERIC has KDTRACE_HOOKS; enable the SDT probes in out-of-tree builds too.
CFLAGS+=	-DKDTRACE_HOOKS

.include <bsd.kmod.mk>

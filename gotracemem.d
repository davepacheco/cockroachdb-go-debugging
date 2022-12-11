#!/usr/sbin/dtrace -Cs

#pragma D option quiet

/* tune up switchrate (default: 1Hz) to reduce drops */
#pragma D option switchrate=16hz
/* tune up buffer size (default: 4 MiB (per CPU)) to reduce drops */
#pragma D option bufsize=48M

typedef struct mspan {
    void *next;
    void *prev;
    void *list;

    uintptr_t startAddr;
    uintptr_t npages;
    void *manualFreeList;
    uintptr_t freeindex;
    uintptr_t nelems;
    uint64_t allocCache;
    uintptr_t allocBits;
    uintptr_t gcmarkBits;
    uint32_t sweepgen;
    uint32_t divMul;
    uint16_t allocCount;
    uint8_t spanclass;
    uint8_t state;
    uint8_t needzero;
    uint16_t allocCountBeforeCache;
    uintptr_t elemsize;
    uintptr_t limit;
} mspan_t;

/*
 * For debugging, it's helpful to be able to turn off large chunks of probes.
 */
#define PROBE_MALLOCGC
#define PROBE_ALLOC_FROM_SPAN
#define PROBE_SPAN_ACTIONS
#define PROBE_SIGNALS

#define EVENT_START() \
	printf("dap: tid %d %s %s ", tid, probefunc, probename)

#define EVENT_START_MSPAN(spanptr) \
	printf("dap: tid %d %s %s mspan %p ", tid, probefunc, probename, spanptr)

#define PRINT_MSPAN_FIELD(spanptr, span, fieldlabel, field) \
	EVENT_START_MSPAN(spanptr); \
	printf("%s = %d (0x%x)\n", fieldlabel, span->field, span->field)

#define PRINT_MSPAN(spanptr, span) \
	EVENT_START_MSPAN(spanptr); \
	printf("\n"); \
	PRINT_MSPAN_FIELD(spanptr, span, "allocCount", allocCount); \
	PRINT_MSPAN_FIELD(spanptr, span, "freeindex", freeindex); \
	PRINT_MSPAN_FIELD(spanptr, span, "sweepgen", sweepgen); \
	PRINT_MSPAN_FIELD(spanptr, span, "state", state); \
	PRINT_MSPAN_FIELD(spanptr, span, "allocCache", allocCache); \
	PRINT_MSPAN_FIELD(spanptr, span, "nelems", nelems); \
	PRINT_MSPAN_FIELD(spanptr, span, "elemsize", elemsize); \
	PRINT_MSPAN_FIELD(spanptr, span, "npages", npages); \
	PRINT_MSPAN_FIELD(spanptr, span, "startAddr", startAddr); \
	PRINT_MSPAN_FIELD(spanptr, span, "limit", limit);

#define PRINT_MSPAN_ALLOC_BITS(spanptr, span) \
	EVENT_START_MSPAN(spanptr); \
	printf("allocBits:\n"); \
	this->nbytes_of_bits = (span->nelems + 7) / 8; \
	this->bits = copyin(span->allocBits, this->nbytes_of_bits); \
	tracemem(this->bits, 128, this->nbytes_of_bits); \
	this->nbytes_of_bits = 0; \
	this->bits = 0;

#define PRINT_MSPAN_MARK_BITS(spanptr, span) \
	EVENT_START_MSPAN(spanptr); \
	printf("gcmarkBits:\n"); \
	this->nbytes_of_bits = (span->nelems + 7) / 8; \
	this->bits = copyin(span->gcmarkBits, this->nbytes_of_bits); \
	tracemem(this->bits, 128, this->nbytes_of_bits); \
	this->nbytes_of_bits = 0; \
	this->bits = 0;

BEGIN
{
	printf("dap: tracing pid %d\n", $target);
}

/* top-level allocations */

pid$target::runtime*mallocgc:entry
{
	self->size = *(uint64_t*)copyin(uregs[R_RSP]+sizeof (uint64_t), sizeof (uint64_t));
	EVENT_START();
	printf("size 0x%x\n", self->size);
}

pid$target::runtime*mallocgc:return
/self->size/
{
	EVENT_START();
	/*
	 * mallocgc happens to put the return value into %rax, but this is not
	 * guaranteed by the Go internal calling convention.
	 */
	printf("size 0x%x = 0x%x\n", self->size, uregs[R_RAX]);
	self->size = 0;
}

/* gc: sweeps */

/* function: runtime.(*sweepLocked).sweep */
pid$target::runtime*sweepLocked*sweep:entry
{
	this->span_locked = *(uintptr_t *)copyin(uregs[R_RSP]+sizeof (uint64_t), sizeof (uintptr_t));
	self->sweep_spanptr = *(uintptr_t *)copyin(this->span_locked, sizeof (uintptr_t));
	this->span_locked = 0;
	this->span = (mspan_t *)copyin(self->sweep_spanptr, sizeof (mspan_t));
	PRINT_MSPAN(self->sweep_spanptr, this->span);
	PRINT_MSPAN_ALLOC_BITS(self->sweep_spanptr, this->span);
	PRINT_MSPAN_MARK_BITS(self->sweep_spanptr, this->span);
}

/* clobberfree */
pid$target::runtime*sweepLocked*sweep:b46
/self->sweep_spanptr/
{
	EVENT_START_MSPAN(self->sweep_spanptr);
	printf("clobbering 0x%x\n", uregs[R_R10]);
}

/* function: runtime.(*sweepLocked).sweep */
pid$target::runtime*sweepLocked*sweep:return
/self->sweep_spanptr/
{
	this->span = (mspan_t *)copyin(self->sweep_spanptr, sizeof (mspan_t));
	PRINT_MSPAN(self->sweep_spanptr, this->span);
	PRINT_MSPAN_ALLOC_BITS(self->sweep_spanptr, this->span);
	this->span = 0;
	self->sweep_spanptr = 0;
}

/* signal handling */

#ifdef PROBE_SIGNALS

/* see uts/intel/sys/regset.h */
#define REG_FSBASE 26

/* signal handling begins on entry to sigacthandler in libc */
pid$target::sigacthandler:entry
{
	self->handling_signal++;
	this->ucontext = (ucontext_t *)copyin(arg2, sizeof (ucontext_t));
	EVENT_START();
	printf("depth %d, sig %d, ucontext fsbase = %p, kernel view of fsbase = %p\n",
	    self->handling_signal,
	    arg0,
	    this->ucontext->uc_mcontext.gregs[REG_FSBASE],
	    curthread->t_lwp->lwp_pcb.pcb_fsbase
	);
}

/* go common signal handler function */
pid$target::runtime.*sigtrampgo:entry,
pid$target::runtime.*sigtrampgo:return
{
	EVENT_START();
	printf("depth = %d\n", self->handling_signal);
}

/*
 * signal handling ends with setcontext() syscall, which seems only to be used
 * during signal handling in our case
 */
syscall::setcontext:entry
/pid == $target && arg0 == 1/
{
	this->ucontext = (ucontext_t *)copyin(arg1, sizeof (ucontext_t));
	EVENT_START();
	printf("depth %d, ucontext fsbase = %p, kernel view of fsbase = %p\n",
	    self->handling_signal,
	    this->ucontext->uc_mcontext.gregs[REG_FSBASE],
	    curthread->t_lwp->lwp_pcb.pcb_fsbase
	);
}

syscall::setcontext:entry
/pid == $target && arg0 == 1 && self->handling_signal > 0/
{
	self->handling_signal--;
}

#endif

/*
 * allocation from mspan: fast path is nextFreeFast().  However, this is inlined
 * in two places in mallocgc().  From manual inspection of the DWARF, those two
 * places are:
 *
 *     runtime.mallocgc+0x2d0 (input = mspan = %rax)
 *     to
 *     runtime.mallocgc+0x34c (output = allocated addr = %r10)
 *
 *     and
 *
 *     runtime.mallocgc+0x476 (input = mspan = %rax)
 *     to
 *     runtime.mallocgc+0x51b (output = allocated addr = %rcx)
 */

#ifdef PROBE_ALLOC_FROM_SPAN

pid$target::runtime.*mallocgc:2d0,
pid$target::runtime.*mallocgc:34c
{
	/* nextFreeFast() entry */
	self->fast_mspan = uregs[R_RAX];
}

pid$target::runtime.*mallocgc:2d0,
pid$target::runtime.*mallocgc:34c,
pid$target::runtime.*mallocgc:476,
pid$target::runtime.*mallocgc:51b
/self->fast_mspan != 0/
{
	/* nextFreeFast() entry / return */
	this->mspan = (mspan_t *)copyin(self->fast_mspan, sizeof (mspan_t));
	PRINT_MSPAN(self->fast_mspan, this->mspan);
	PRINT_MSPAN_ALLOC_BITS(self->fast_mspan, this->mspan);
	this->mspan = 0;
}

pid$target::runtime.*mallocgc:34c
/self->fast_mspan != 0/
{
	/* nextFreeFast() return (first inline) */
	EVENT_START_MSPAN(self->fast_mspan);
	printf("nextFreeFast() returning %p", uregs[R_R10]);
	self->fast_mspan = 0;
}

/* allocation from mspan: slower path */

pid$target::runtime.*nextFreeIndex:entry
{
	self->next_free_spanptr = *(uintptr_t *)copyin(
	    uregs[R_RSP] + sizeof (uint64_t), sizeof (uintptr_t));
}

pid$target::runtime.*nextFreeIndex:entry,
pid$target::runtime.*nextFreeIndex:return
/self->next_free_spanptr/
{
	this->mspan = (mspan_t *)copyin(self->next_free_spanptr, sizeof (mspan_t));
	PRINT_MSPAN(self->next_free_spanptr, this->mspan);
	this->mspan = 0;
}

/*
 * refillAllocCache is sometimes called from nextFreeIndex and it'd be useful to
 * know when it was.
 */
pid$target::runtime.*refillAllocCache:entry
/self->next_free_spanptr/
{
	self->refill = 1;
}

pid$target::runtime.*nextFreeIndex:return
/self->next_free_spanptr/
{
	EVENT_START_MSPAN(self->next_free_spanptr);
	this->returning = *(uintptr_t *)copyin(uregs[R_RSP] + 7 * sizeof (uint64_t), sizeof (uintptr_t));
	printf("refill %d return %p\n", self->refill, this->returning);
	this->returning = 0;
	self->next_free_spanptr = 0;
	self->refill = 0;
}

#endif

/* mspan-level actions (alloc/free, cache/uncache) */

#ifdef PROBE_SPAN_ACTIONS

pid$target::runtime.*.cacheSpan:return
{
	this->ra = *(uintptr_t *)copyin(
	    uregs[R_RSP] + sizeof (uint64_t),
	    sizeof (uintptr_t)
	);
}

pid$target::runtime.*.allocSpan:return
{
	this->ra = *(uintptr_t *)copyin(
	    uregs[R_RSP] + 3 * sizeof (uint64_t),
	    sizeof (uintptr_t)
	);
}

pid$target::runtime.*.cacheSpan:return,
pid$target::runtime.*.allocSpan:return
/this->ra != 0/
{
	this->mspan = (mspan_t *)copyin(this->ra, sizeof (mspan_t));
	PRINT_MSPAN(this->ra, this->mspan);
	this->mspan = 0;
	this->ra = 0;
}

pid$target::runtime.*uncacheSpan:entry
{
	this->spanptr = *(uintptr_t *)copyin(
	    uregs[R_RSP]+sizeof (uint64_t), sizeof (uintptr_t));
	this->mspan = (mspan_t *)copyin(this->spanptr, sizeof (mspan_t));
	PRINT_MSPAN(this->spanptr, this->mspan);
	this->mspan = 0;
	this->spanptr = 0;
}

pid$target::runtime.*freeSpanLocked:entry
{
	this->spanptr = *(uintptr_t *)copyin(
	    uregs[R_RSP]+2*sizeof (uint64_t), sizeof (uintptr_t));
	this->mspan = (mspan_t *)copyin(this->spanptr, sizeof (mspan_t));
	PRINT_MSPAN(this->spanptr, this->mspan);
	PRINT_MSPAN_ALLOC_BITS(this->spanptr, this->mspan);
	this->mspan = 0;
	this->spanptr = 0;
}

#endif

/* actions at process exit */

syscall::rexit:entry
/pid == $target/
{
	printf("dap: tid %d exit: %d\n", tid, arg0);
}

syscall::write:entry
/pid == $target && arg0 <= 2/
{
	printf("dap: tid %d write fd %d %d bytes\n", tid, arg0, arg2);
}

#!/usr/sbin/dtrace -Cs

#pragma D option quiet

/* tune up switchrate (default: 1Hz) to reduce drops */
#pragma D option switchrate=2hz
/* tune up buffer size (default: 4 MiB (per CPU)) to reduce drops */
#pragma D option bufsize=16M

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

BEGIN
{
	printf("dap: tracing pid %d\n", $target);
}

pid$target::runtime*mallocgc:entry
{
	self->size = *(uint64_t*)copyin(uregs[R_RSP]+sizeof (uint64_t), sizeof (uint64_t));
}

pid$target::runtime*mallocgc:return
/self->size/
{
	printf("dap: alloc size 0x%x = 0x%x\n", self->size, uregs[R_RAX]);
	self->size = 0;
}

/* function: runtime.(*sweepLocked).sweep */
pid$target::runtime*sweepLocked*sweep:entry
{
	this->span_locked = *(uintptr_t *)copyin(uregs[R_RSP]+sizeof (uint64_t), sizeof (uintptr_t));
	self->spanptr = *(uintptr_t *)copyin(this->span_locked, sizeof (uintptr_t));
	this->span_locked = 0;
	this->span = (mspan_t *)copyin(self->spanptr, sizeof (mspan_t));

	printf("dap: span %p: %s\n", self->spanptr, "begin sweep");
	printf("dap: span %p: %s: allocCount = %d (0x%x)\n", self->spanptr, "begin sweep", this->span->allocCount, this->span->allocCount);
	printf("dap: span %p: %s: freeindex = %d (0x%x)\n", self->spanptr, "begin sweep", this->span->freeindex, this->span->freeindex);
	printf("dap: span %p: %s: sweepgen = %d (0x%x)\n", self->spanptr, "begin sweep", this->span->sweepgen, this->span->sweepgen);
	printf("dap: span %p: %s: state = %d (0x%x)\n", self->spanptr, "begin sweep", this->span->state, this->span->state);
	printf("dap: span %p: %s: allocCache = 0x%x\n", self->spanptr, "begin sweep", this->span->allocCache);
	printf("dap: span %p: %s: range [ %p, %p )\n", self->spanptr, "begin sweep", this->span->startAddr, this->span->limit);
	printf("dap: span %p: %s: nelems = %d (0x%x)\n", self->spanptr, "begin sweep", this->span->nelems, this->span->nelems);
	printf("dap: span %p: %s: elemsize = %d (0x%x)\n", self->spanptr, "begin sweep", this->span->elemsize, this->span->elemsize);
	printf("dap: span %p: %s: npages = %d\n", self->spanptr, "begin sweep", this->span->npages);
	printf("dap: span %p: allocBits:\n", self->spanptr);
	this->nbytes_of_bits = (this->span->nelems + 7) / 8;
	this->bits = copyin(this->span->allocBits, this->nbytes_of_bits);
	tracemem(this->bits, 128, this->nbytes_of_bits);
	printf("dap: span %p: gcmarkBits:\n", self->spanptr);
	this->bits = copyin(this->span->gcmarkBits, this->nbytes_of_bits);
	tracemem(this->bits, 128, this->nbytes_of_bits);
	this->bits = 0;
	this->span = 0;
}

/* clobberfree */
pid$target::runtime*sweepLocked*sweep:b46
/self->spanptr/
{
	printf("dap: span %p: clobbering 0x%x\n", self->spanptr, uregs[R_R10]);
}

/* function: runtime.(*sweepLocked).sweep */
pid$target::runtime*sweepLocked*sweep:return
/self->spanptr/
{
	this->span = (mspan_t *)copyin(self->spanptr, sizeof (mspan_t));

	printf("dap: span %p: %s\n", self->spanptr, "end sweep");
	printf("dap: span %p: %s: allocCount = %d (0x%x)\n", self->spanptr, "end sweep", this->span->allocCount, this->span->allocCount);
	printf("dap: span %p: %s: freeindex = %d (0x%x)\n", self->spanptr, "end sweep", this->span->freeindex, this->span->freeindex);
	printf("dap: span %p: %s: sweepgen = %d (0x%x)\n", self->spanptr, "end sweep", this->span->sweepgen, this->span->sweepgen);
	printf("dap: span %p: %s: state = %d (0x%x)\n", self->spanptr, "end sweep", this->span->state, this->span->state);
	printf("dap: span %p: %s: allocCache = 0x%x\n", self->spanptr, "end sweep", this->span->allocCache);
	printf("dap: span %p: %s: range [ %p, %p )\n", self->spanptr, "end sweep", this->span->startAddr, this->span->limit);
	printf("dap: span %p: %s: nelems = %d (0x%x)\n", self->spanptr, "end sweep", this->span->nelems, this->span->nelems);
	printf("dap: span %p: %s: elemsize = %d (0x%x)\n", self->spanptr, "end sweep", this->span->elemsize, this->span->elemsize);
	printf("dap: span %p: %s: npages = %d\n", self->spanptr, "end sweep", this->span->npages);
	printf("dap: span %p: allocBits:\n", self->spanptr);
	this->nbytes_of_bits = (this->span->nelems + 7) / 8;
	this->bits = copyin(this->span->allocBits, this->nbytes_of_bits);
	tracemem(this->bits, 128, this->nbytes_of_bits);
	this->bits = 0;
	this->span = 0;
	self->spanptr = 0;
}

syscall::rexit:entry
/pid == $target/
{
	printf("dap: exit: %d\n", arg0);
}

syscall::write:entry
/pid == $target && arg0 <= 2/
{
	printf("dap: write fd %d %d bytes\n", arg0, arg2);
}
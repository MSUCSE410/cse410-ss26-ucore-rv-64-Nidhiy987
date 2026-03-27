#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "stddef.h"   //Needed because TaskInfo and TimeVal are defined in user space

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}
uint64 sys_getpid()
{
    return curr_proc()->pid; // returns current process ID
}

uint64 sys_gettimeofday(TimeVal *val, int _tz) // TODO: implement sys_gettimeofday in pagetable. (VA to PA)
{
	// YOUR CODE
	// val->sec = 0;
	// val->usec = 0;

	/* The code in `ch3` will leads to memory bugs*/
	struct proc *p = curr_proc();

	// translate user VA → PA
	uint64 pa = useraddr(p->pagetable, (uint64)val);
	if (pa == 0)
		return -1;

	TimeVal kval;

	uint64 cycle = get_cycle();
	kval.sec = cycle / CPU_FREQ;
	kval.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;

	// copy kernel → user memory
	memmove((void *)pa, &kval, sizeof(TimeVal));

	return 0;

	// uint64 cycle = get_cycle();
	// val->sec = cycle / CPU_FREQ;
	// val->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	return 0;
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)

uint64 sys_task_info(TaskInfo *ti)
{
    struct proc *p = curr_proc();  

    // first make sure the user actually passed a valid pointer
    if (ti == 0)
        return -1;

    // in Project 2, we can't directly use user pointers,
    // so we translate the virtual address to a physical address
    uint64 pa = useraddr(p->pagetable, (uint64)ti);
    if (pa == 0)
        return -1;

    // fill everything in a kernel struct first
    TaskInfo kti;

    // process is currently running
    kti.status = 2;

    // copy how many times each syscall was used
    for (int i = 0; i < MAX_SYSCALL_NUM; i++) {
        kti.syscall_times[i] = p->syscall_times[i];
    }

    // compute how long the process has been running
    uint64 now = get_cycle();
    kti.time = (now - p->start_time) / (CPU_FREQ / 1000);
	//t calculates how long the process has been running in milliseconds.

    // finally copy the data back to user space
    memmove((void *)pa, &kti, sizeof(TaskInfo));

    return 0;
}


uint64 sys_mmap(uint64 addr, uint64 len, uint64 port, uint64 flag, uint64 fd)
{
    // nothing to do if length is 0
    if (len == 0) return 0;

    // basic checks to make sure the address is valid
    if (addr >= MAXVA) return -1;
    if (addr == 0) return -1;

    // must start on a page boundary
    if (addr % PGSIZE != 0) return -1;

    // only allow R/W/X bits
    if (port & ~0x7) return -1;
    if ((port & 0x7) == 0) return -1;

    struct proc *p = curr_proc();

    // map one page at a time
    for (uint64 a = addr; a < addr + len; a += PGSIZE) {

        // don’t allow mapping over something that already exists
        if (walkaddr(p->pagetable, a) != 0)
            return -1;

        // allocate a physical page
        void *mem = kalloc();
        if (!mem) return -1;

        // clear it so it's clean
        memset(mem, 0, PGSIZE);

        // build permissions
        int perm = PTE_U;
        if (port & 1) perm |= PTE_R;
        if (port & 2) perm |= PTE_W;
        if (port & 4) perm |= PTE_X;

        // connect virtual address to physical memory
        if (mappages(p->pagetable, a, PGSIZE, (uint64)mem, perm) != 0)
            return -1;
    }

    return 0;
}
uint64 sys_munmap(uint64 addr, uint64 len)
{
    struct proc *p = curr_proc();

    // must be page aligned
    if (addr % PGSIZE != 0) return -1;

    // make sure we cover full pages
    uint64 end = PGROUNDUP(addr + len);

    // go through each page and remove it
    for (uint64 a = addr; a < end; a += PGSIZE) {

        // if it's not mapped, that's an error
        if (walkaddr(p->pagetable, a) == 0)
            return -1;

        // remove mapping and free memory
        uvmunmap(p->pagetable, a, 1, 1);
    }

    return 0;
}
extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/

	if (id < MAX_SYSCALL_NUM) {
    curr_proc()->syscall_times[id]++;
	}
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;

	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	case SYS_task_info:
		ret = sys_task_info((TaskInfo *)args[0]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}

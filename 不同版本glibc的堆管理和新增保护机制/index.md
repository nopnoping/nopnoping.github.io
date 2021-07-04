# 不同版本glibc的堆管理和新增保护机制


最近阅读了《glibc内存管理ptmalloc源码分析》一书，对ptmalloc内部机制了解更深入了一层。但是书中所分析的libc版本是2.23，如今libc以及更新到2.31，且pwn中libc的版本也普遍是2.27及以上，所以就想写一篇博客纪录一下各个版本libc堆管理的差别和新增的保护机制。

<!--more-->

# Glibc2.23

## malloc和free的逻辑

这个版本的libc应该是大家最为熟悉的，在入门pwn堆题的时候，做到的题大多都是这个版本。这个版本的堆管理有挺多的漏洞，利用方法也是最多的。

首先让我们先看一下这个版本下_int_malloc的逻辑，由于这个函数的源代码太多了，在这里我仅仅只是从中提取主要部分。

````c
void * _int_malloc(size)
{
    size_t nb=req2size(size)
    if(nb <= get_max_fast()){
		//如果请求的大小小于fastbin支持的最大大小
        //那么从fast_bins中搜索，搜索到就返回
    }
    if(in_small_bin_range(nb))
    {
        //在fastbin中没有找到空闲的chunk或则请求大小大于fastbin支持的最大大小，就到这一步
        //判断申请的大小是否在small_bin范围内
        //如果在就从small_bin中搜索是否有复合的块，有就返回
    }
    else
    {
        //请求的块在largin_bin的范围内
        if(have_fastchunks(av))
            malloc_consolidate();
        //先判断fast_bins是否为空
        //不为空，则触发malloc_consolidate，将fast_bins中的堆块合并
    }
    foreeach(chunk:unsorted_bin)
    {
        //到这一步，如果请求大小在small_bin范围内，那么在fast_bins和small_bins中并未找到合适的，可能unsortedbins里面会有
        //如果大小在large_bins范围内，那么可能发生了malloc_consolidate()，并将合并后的chunk放入unsortedbins，所以unsortedbins里面可能也会有合适的chunk
        //这一步就是遍历unsortedbins里面的chunk，看是否有合适的用于分配。
        if(is_small&&only_chunk&&chunck_size>nb+MINISIZE)
        {
            //如果请求的大小在small_bins范围内，并且unsorted_bins中仅有一个堆块，这个堆块的大小大于请求大小加MINISIZE，则分配。
            //MINISIZE在不同位数系统中不一样，MINISIZE就是malloc分配的最小堆块大小，这里之所以要保证大于nb+MINISIZE是因为当将这个chunk切割后，剩下的chunk也可以用于分配。
        }
        if(size==nb)
        {
            //如果在unsortedbin中找到一个和请求大小一样的堆块，直接分配
        }
        if(in_small_range(size))
        {
            //在搜索unsortedbin的过程中，如果其大小在smallbin中，将其放入smallbin中进行管理
        }
        else
        {
            //不在smallbin中，就必定在largebin中
            //放入largebin中
        }
    }
            //到这里，我们以及把unsortedbin中的堆块，重新分配到了smallbin和largebin中，这个时候smallbin或则largebin中可能会有符合我们请求的chunk
    if(!in_small_range(nb))
    {
        //搜索largebin中，此时会按照small-first，best-fit的原则找一个合适的堆块，直接分配或则分割后分配
    }
    for(bin in bins)
    {
        //到这一步，表面在属于自己大小的idx中找不到合适的堆块，将会尝试去从比自己大的idx中找到合适的堆块
    }
    //到这里如果还没有分配成功那么就是是同Top chunk进行分配
use_top:
    if(size>=nb+MINISIZE)
    {
        //Top chunk的大小大于请求大小加MINISIZE，则从TOP chunk中分配
    }
    else if(heave_fastchunks(av))
    {
         //如果Top chunk的大小不足够用于分配，则判断fastbin中是否有chunk有则执行malloc_consolidate
        malloc_consolidate();
        //由于到了这里，fastchunks中还有堆块，则请求的堆必定是在smallbin范围内，否则在之前就以及情况fastbin了
        //之后会返回外层循环，尝试重新分配
    }
    else
    {
        //到这里如果还没有找到合适的堆块的话，那么久只有尝试申请新的堆块了。
        brk()
        //注意这里要区分主/负分配区，只有主分配去是用brk分配内存。
    }
}
````

在上面的分析中我们对于2.23版本libc堆管理有了一个较为清晰的流程，更高版本的libc中，堆管理的流程相差不大，只是在里面加入了一些新的机制，后面我只写出其新增的流程和其位于流程中的位置。

下面我再简单的描述一下_int_free的逻辑，当然这里也只是抽取主要部分，细节部分需要大家自己去阅读源码了。

```` c
staci void 
_int_free(mstate av,mchunkptr p){
    size_t size=chunksize(p);
    check_inuse_chunk(av,p);
    //检测所需要释放的堆块是否在使用
    if(size<=get_max_fast())
    {
        if(next_chunk.size<=2*SIZE_SZ||next_chunk.size>=system_mem)
        {
            error();
            //检查下一个堆块的大小是否正常
		} 
        if(old==p)
        {
            error();
            //检查fastbin表头是否和当前块相同，相同则是double_free
        }
        //将堆块放入fastbin头部
    }
    else if(!chunk_is_mapped(p))
    {
        if(!prev_inuse(p))
        {
            //如果上一块没有使用，则与其合并
            p=prev_chunk(p);
            unlink(av,p,bck,fwd);
        }
        if(nextchunk != av.top)
        {
            if(!next_insue(p))
            {
                //如果下一个堆块不是topchunk且未使用与其合并。
            }
        }
        else{
            //如果下一个堆块是topchunk，则与topchunk合并
            av.top=p;
        }
        if(size>FASTBIN_CONSOLIDATION_THRESHOLD)
        {
            //检查所需要释放的空间是否大于consolidate的阈值，如果大于则执行malloc_consolidate,并回收空间
            malloc_consolidate(av);
            systrim(heap);
        }
    }
    else{
        munmap_chunk(p)
    }
}
````

高版本的释放逻辑基本2.23类似，只不过会添加更多的保护机制，在之后的分析中我仅会列出与2.23有变化的部分，相同的部分我就不进行阐述了。

我们的堆漏洞利用，通常都是由于程序堆中存在Dangling pointer或则overflow漏洞，再加上ptmalloc在一些地方保护不严谨，其保护机制可以被我们绕过甚至利用来达到任意地址写，进而getshell。比如利用fastbin分配时检测不充分，达到任意地址分配的目的。利用unlink解链达到写地址的操作。这里我也简单罗列一下在2.23版本下，可以使用的堆利用技巧。

## 堆利用

+ house of spirit：构造一个fake_chunk并进行free，加入到fastbin中，下一次就可以分配我们的fake_chunk。
+ house_of_force：溢出到top_chunk，修改其size，令超大的分配可以从top_chunk中返回而不通过mmap痛过malloc（&top-x）大小的分配返回任意地址。
+ house_of_lore：利用smallbin和largebin在头部插入尾部取出的特性，伪造bin中某个chunk的bk指针为fake_chunk并且fake_chunk的fd字段需要为该bin的地址。然后下一次分配就是我们的chunk。
+ house_of_orange：利用堆溢出和IO_list_all来获取shell。利用unsorted bin攻击修改io_list_all，然后将small bin中的0x61大小堆块看成FILE结构，修改相应的数据。不过unsorted bin和把0x61大小的chunk放入small bin是同时进行的。
+ house_of_einherijar：修改相邻chunk的size和pre_inuse位，使堆块合并进而出现堆块重叠。
+ house_of_roman：利用fast_bin和IO_FILE来达到泄漏libc的目的。
+ house_of_rabbit：利用malloc_consolidate的时候没有检查该bin是否符合该idx。如果修改size为一个更大的值将可以发生堆块重叠。
+ Unlink：伪造堆块，使堆块释放时，执行unlink，从而修改一些地址，但是为了绕过unlink的保护，修改的地址有限制。
+ 堆重叠：修改size达到可以修改已经释放的chunk的目的进而可以进行更多的攻击
+ unsorted bin attack：利用unsortedbin的双向链表结构，篡改bk的值使任意地址储存一个较大的值。
+ large bin attack：利用malloc中将unsorted bin中的largin chunk放入large bin时没有做充足的检测进而可以修改任意地址为堆块的值。

2.23堆利用就介绍到这里，下面让我们来看一看2.27版本新增的机制和保护策略以及堆利用。

# Glibc2.27

## tcache bin机制

2.27版本比2.23多了一个tchache bin。tchache bin是在2.26版本中引入的，用来进一步提升堆管理性能。

首先我们看一下tcache bin的几个宏定义（以下代码来至libc2.27，之后将不做说明）

```` c
/* We want 64 entries.  This is an arbitrary limit, which tunables can reduce.  */
# define TCACHE_MAX_BINS		64
# define MAX_TCACHE_SIZE	tidx2usize (TCACHE_MAX_BINS-1)

/* Only used to pre-fill the tunables.  */
# define tidx2usize(idx)	(((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))

/* With rounding and alignment, the bins are...
   idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1   bytes 25..40 or 13..20
   idx 2   bytes 41..56 or 21..28
   etc.  */

/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7
````

这里挑几个重点宏定义讲一下。TCACHE_MAX_BIN定义了用于管理tcache的最大bin数量，其被定义为64，及有64个bin用于管理tcache bin。其编号idx依次从0到63，对应的chunk size从MALLOC_ALIGNMENT\*2到MALLOC_ALLIGNMENT\*64，如果是64位系统，tcache bin中最大能储存0x800的大小。HACHE_FILL_COUNT定义了给个bin最多能粗存的个数。

再来看两个重要的tcache结构

```` c
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
````

tchache_entry是一个单向列表，用来将bin中的chunk连成一个单链，其机制与fast bin类似。tcache_perthread_struct是用来管理bin的一个结构，其有一个char数组成员，用来记录给个bin已经储存了几个chunk，entries是每个不同大小bins的队头，用来遍历和管理tcache bin。tcache_perthread_struct在tcache_init()中创建，让我们一起来看一下这个函数。

```` c
static void
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof (tcache_perthread_struct);

  if (tcache_shutting_down)
    return;

  arena_get (ar_ptr, bytes);
  victim = _int_malloc (ar_ptr, bytes);
  if (!victim && ar_ptr != NULL)
    {
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }


  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later.  However, we
     typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway.  */
  if (victim)
    {
      tcache = (tcache_perthread_struct *) victim;
      memset (tcache, 0, sizeof (tcache_perthread_struct));
    }

}
````

其根据tchache_perthread_struct的大小，用malloc创建一个实例并将其赋值给全局遍历，tchache，而tchache就是tchache_perthread_struct的指针。并且tchache_init是在初始话时被调用，所以此时创建的chunk是堆块中第一个创建的chunk。（如果实现了任意地址修改，就可以修改此处的chunk，进而可以控制tcache bin的数量和指针）

接下来再介绍一下加入tcache和取出tcache的两个函数

```` c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
````

tcache_put将tcache放入bin中，仅仅只是检查了其大小是否符合tcache。tcache_get从tcache中获得一个bin，也仅仅检测了大小是否符合tcache以及bin不为空。可以看出tcache安全机制特别简单，所以引入了tcache反而使漏洞利用更简单了。

下面我们看一看引入tcache后，malloc和free做了哪些改变。

## malloc和free的逻辑

首先看一下__libc_malloc，这里我们只写出该函数中我们关心的部分。

````c
void *
__libc_malloc (size_t bytes)
{
    if (tc_idx < mp_.tcache_bins
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
    victim = _int_malloc (ar_ptr, bytes);
}
````

从函数代码中，我们可以看出，在执行int_malloc之前，程序首先去搜索tcache，查看tcache中是否有空闲的bin，如果有直接从tcache中分配，如果没有才执行int_malloc。

```` c
static void *
_int_malloc (mstate av, size_t bytes)
{
    size_t nb=req2size(bytes);
    if(nb<=get_max_fast())
    {
        //与2.23的区别在于，如果大小在fast_bin的范围内，那么如果尝试从fast_bin中获取堆块
        //获取成功后，将fast_bin中剩余的堆块放入tcache中
    }
	if(in_small_bin())
    {
        //与2.23的区别在于，获取small_bin成功后，将剩下的堆块放入tcache中
    }
    else{
        malloc_consolidate();
    }
    for(chunk::unsorted_bin)
    {
        ......
        if(chunk_size==nb)
        {
            //将chunk放入tcache中,并将return_cached置为1
        }
        ......
        if(return_cached)
        {
            //如果return_cached为1，则从tcache中分配
        }
    }
    .....
    
}
````

2.27的_int_malloc和2.23的主要区别在于2.27会将fastbin和smallbin还有unsortedbin中多余的块放入tcache中。

接下来让我们看一下free逻辑

````c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
    size_t size=chunksize(p);
    if(tcache)
    {
        //将该chunk放入tcache中
    }
    ......
}
````

2.27的free与之前主要的区别在于先检查是否处于tcache范围，且tcache未存满，如果没有存满则直接put进去，之后的操作于2.23如出一辙。

## 堆利用

+ tcache_dup：tcache的释放没有进行double free检测，如果存在UAF漏洞可直接对tcache进行double free 进而实现任意地址分配。
+ tcache_poisoning：类似于修改fast bin的fd字段。当程序存在溢出漏洞时，可以修改tcache的next字段，达到任意地址分配的目的。
+ tcache_house_of_spirit：类似于fast bin的house_of_spirit，但是tcache的检测比fastbin更为简单，只需要释放的chunk满足size要求即可，并不会对下一个chunk进行检测。
+ house_of_bot_cake：该方法的利用需要有UAF漏洞。释放7个chunk进而填满tcache，再释放两个相同的chunkA和B使其consolidate，再分配一个相同大小的chunk，让tcache有空余，再利用UAF再次释放chunkB，进而可以实现overlapping。
+ tcache_stashing_unlink_attack：利用分配small bin时会将多余的块放入tcache的机制，恶意修改bk的值，以达到修改某个地址为一个很大的值的目的。类似于unsorted bin attack。
+ fastbin_reverse_into_tcache：该利用方法和上一个利用方法原理类似，利用了分配fastbin时，会将多余的chunk放入tcache中。做法是先将tcache填满，再释放7个chunk，并修改fast表头的fd指针为我们想修改的地址。之后malloc8个chunk，在分配第8个chunk时，将会把fast bin中的chunk放入tcache中，从而修改目标地址。

# Glibc2.29

libc2.29没有修改malloc和free的逻辑也没有新增像tcache一样的机制，只是修改了一些在malloc和free chunk时的检测机制，下面让我们一起来看一看2.29相较于之前的版本，检测机制做出了什么样的修改。

## tcache

我们知道2.27版本的tcache安全保护机制十分的脆弱，很容易就能被利用，所以在2.29版本中，对tcache结构体加入了新的字段 key。

```` c
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;
````

加这个字段的目的主要是用来检测double free。

```` c
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;	//new

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;	//new
  return (void *) e;
}

````

在加入tcache_bin时将key字段赋值为tcahce的地址，而在取出时，会将该字段清零。为什么这么做呢我们看一下int_free中新增的检测机制就清楚了。

## int_free新增检测机制

Int_free中新增了对tcache释放时，key字段的检验，下面是伪代码。

```` c
void * _int_free()
{
	if(e->key==tcache)
	{
		error("double free!");
	}
}
````

如果当前释放的chunk，其key字段为tcache的话，那么判断其为double free

### unlink

在free中除了新增了对tcache的检测，还增强了unlink的检测机制。

```` c
if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))	//new
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }
````

在进行unlinlk解链前，会检查该chunk的大小是否和presize相同。增加了null of byte的利用难度。

## int_malloc新增检测机制

在2.29int_malloc中新增了关于unsorted bin的检测

```` c
 if (__glibc_unlikely (size <= 2 * SIZE_SZ)
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < 2 * SIZE_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
````

检测了当前chunksize的合法性，nextchunksize的合法性以及双相链表的完整性。加入了这几个检测机制后，unsorted bin attack攻击将很难继续使用。

### use_top

在int_malloc中对use_top增加了检测机制。

```` c
if (__glibc_unlikely (size > av->system_mem))//0x21000
        malloc_printerr ("malloc(): corrupted top size");
````

在使用top chunk时对top chunk的大小进行了检验，使得house of force再也不能使用，从此载入史册。

## 堆利用

2.29与2.27相比，unsorted_bin_attack，house of force，tcache_dump这三个漏洞利用技术，无法再使用。

# Glibc2.30

2.30版本的libc与2.29没有太大的变化，但是对int_malloc中将unsorted bin中的内容放入large bin中时做了更多的检测，使得large bin attack再也无法使用，成为历史。

```` c
    victim->fwufad_nextsize = fwd;
    victim->bk_nextsize = fwd->bk_nextsize;
    if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
        malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
    fwd->bk_nextsize = victim;
    victim->bk_nextsize->fd_nextsize = victim;
    }
bck = fwd->bk;
if (bck->fd != fwd)
    malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
````

在将unsortd bin放入large bin时会检验fwd链表的完整性，使得largin attack通不过检测，攻击不成功。large bin从此退出利用舞台，载入历史。

# Glibc2.31

libc2.31版本在堆块管理和安全机制上和2.30没有什么太大的变化。

# 参考

[ptmalloc与glibc堆漏洞利用](https://evilpan.com/2020/04/12/glibc-heap-exp/#tcache)

[how2heap](https://github.com/shellphish/how2heap)

[glibc-2.29新增的保护机制学习总结](https://www.anquanke.com/post/id/194960#h2-2)

[Heap Exploit v2.31 | 最新堆利用技巧，速速查收](https://zhuanlan.zhihu.com/p/136983333)

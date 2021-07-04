# 修改程序为指定libc版本 & pwndbg安装


如何在ubuntu16上修改程序为libc2.27？如何安装pwndbg以及pwndbg的调试姿势？

<!--more-->

# 修改程序libc版本

在做pwn题时，经常遇到各种版本的libc，常见的是2.27，2.23。不同版本的libc，其机制又不同，比如2.27版本的libc其引入了tcachebin机制，而2.23是没有这个机制的。因此如果靶机环境是2.27，那么你用2.23做题就无法得到正确payload。这个时候就需要修改程序的libc。

libc和程序是通过动态连接器连接在一起的，其详细信息的信息写在程序的LD_RERLOAD中因此我们可以直接修改LD_PERLOAD为目标libc。

## 直接修改LD_PERLOAD

这种修改方式十分简单粗暴，但也十分容易出错。直接修改时，也需要修改ld.so的版本。低版本的ld.so是无法加载高版本的libc的，所以如果只是简单的修改了libc.so而没有修改ld.so就会引起段错误。

```` bash
LD_PRELOAD=./libc.so.6 ./pwn
段错误 (核心已转储)
````

我们需要将ld.so和libc.so一起修改。即在LD_PERLOAD后面添加libc的路径，在第二行添加ld的路径。

```` bash
LD_PRELOAD=/path/to/libc.so.6;
/path/to/ld.so ./pwn
````

也可以在pwntools启动程序中，进行配置

```` python
p=process(['/path/to/ld.so','./pwn'],env={'LD_PERLOAD':'/path/to/libc.so.6'})
````

但是这种方式修改后gdb调试时，是没有libc相应调试信息的。

这里我们推荐另外一种方式，下载glbc-all-in-one并编译所需版本的glibc，利用patchelf工具修改程序的链接器和glibc。

## patchelf修改

### 下载glibc-all-in-one

glibc-all-in-one是github上一个开源项目，帮助我们更容易的调试，下载和编译所需libc版本。

```` bash
git clone https://github.com/matrix1001/glibc-all-in-one.git
cd glibc-all-in-one
chmod a+x build download extract
````

在这里简单翻译下glibc-all-in-one github项目上的教程

#### download

检查支持的包

```` 
➜  glibc-all-in-one cat list
2.23-0ubuntu10_amd64
2.23-0ubuntu10_i386
2.23-0ubuntu11_amd64
2.23-0ubuntu11_i386
2.23-0ubuntu3_amd64
2.23-0ubuntu3_i386
2.27-3ubuntu1_amd64
2.27-3ubuntu1_i386
2.28-0ubuntu1_amd64
2.28-0ubuntu1_i386
2.29-0ubuntu2_amd64
2.29-0ubuntu2_i386
````

下载

```` 
➜  glibc-all-in-one ./download 2.23-0ubuntu10_i386
Getting 2.23-0ubuntu10_i386
  -> Location: https://mirror.tuna.tsinghua.edu.cn/ubuntu/pool/main/g/glibc/libc6_2.23-0ubuntu10_i386.deb
  -> Downloading libc binary package
  -> Extracting libc binary package
  -> Package saved to libs/2.23-0ubuntu10_i386
  -> Location: https://mirror.tuna.tsinghua.edu.cn/ubuntu/pool/main/g/glibc/libc6-dbg_2.23-0ubuntu10_i386.deb
  -> Downloading libc debug package
  -> Extracting libc debug package
  -> Package saved to libs/2.23-0ubuntu10_i386/dbg
➜  glibc-all-in-one ls libs/2.23-0ubuntu10_i386
. .. .debug  ld-2.23.so  libc-2.23.so  libpthread.so.0   ......
➜  glibc-all-in-one ls libs/2.23-0ubuntu10_i386/.debug
ld-2.23.so  libc-2.23.so   ......
````

需要的glibc没有在列表中？

你可以自己下载glibc，然后使用extract。

'http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/' 可以下载2.19到2.26版本的Ubuntu glibc。

```` 
./extract ~/libc6_2.26-0ubuntu2_i386.deb /tmp/test
./extract ~/libc6-dbg_2.26-0ubuntu2_i386.deb /tmp/test_dbg
````

#### complile

支持版本:2.19,2.23-2.29

支持架构:i686,amd64

注意：老版本的glibc的编译可能会出问题。

注意：改变GLIBC_DIR可以修改编译后glibc的地址

```` 
sudo ./build 2.27 amd64 #数字为你需要的libc版本，amd64为你需要的架构
````

### patch下载和使用

当我们获得所需版本的libc和ld后，可以利用patchelf工具来修改程序。

patchelf同样是github上的一个开源项目，它用于修改程序的ld和libc，这里简单讲解一下安装方法和使用方法

#### 安装

```` 
git clone https://github.com/NixOS/patchelf.git
./bootstrap.sh
./configure
make
sudp make install
````

#### patchelf使用方法

+ 修改程序的动态链接加载器ld

````
patchelf --set-interpreter /lib/my-ld-linux.so.2 my-program
````

+ 修改程序和库的路径

```` 
patchelf --set-rpath /opt/my-libs/lib:/oter-libs my-program
````

+ 缩减程序和库的路径

```` 
patchelf --shrink-rpath my-program
````

+ 移除一个已声明的依赖动态库(就是移除动态链接库路径)

```` 
patchelf --remove-needed lib.so myprogram
````

+ 添加一个已经声明的依赖动态库

```` 
patchelf --add-needed libfoo.so.1 my-program
````

+ 替代一个已声明的以来动态库

```` 
patchelf --replace-needed liboriginal.so.1 libreplacement.so.1 my-program
````

+ 改变动态库的符号名

```` 
patchelf --set-soname libnewname.so.3.4.5 path/to/libmylibrary.so.1.2.3
````

### 修改

现在所需工具我们已经安装好了，我们只需要利用patchelf将ld和libc修改为我们用glibc-all-in-one编译好的ld和libc即可。

```` 
patchelf --set-interpreter /glibc/2.27/amd64/lib/lib-2.27.ld ./pwn
patchelf --replace-needed libc.so.6 /glibc/2.27/amd64/lib/libc-2.27.so ./pwn
````

利用ldd测试，即可发现修改成功

![image-20200518230924843](https://raw.githubusercontent.com/TroyeCriss/blog_img/master/img/20200518230951.png)

ok现在我们可以修改程序为指定libc了，并且all-in-one里面的glibc保留了编译信息，在我们调试时，将会给我们提供很大的帮助，再这里再简单介绍一下pwndbg工具的使用。

# pwndbg安装和使用

## 安装

pwndbg是一个gdb插件，给pwn选手调试程序时提供了更多更方便的调试命令，如heap，bins等命令，可以更方便的查看堆的信息。

pwndbg是github项目因此我们可以利用git来下载。

```` 
git clone https://github.com/pwndbg/pwndbg.git
cd pwndbg
./setup.sh
````

这里需要注意一下，由于大多数包都是通过pip来安装的，如果不将pip配置为国内镜像源的话，那么非常容易因为网络的原因造成错误，前功尽弃。这里我们配置一下pip的国内镜像。

修改~/.pip/pip.config(如果没有相应文件夹和文件，就新建一个)

```` 
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
[install]
trusted-host=mirrors.aliyun.com
````

## 使用方法

这里就不过多介绍pwndbg的使用方法了，详情请浏览pwndbg github上的介绍和参看。

# 参考

[pwn题加载任意版本libc](https://at0de.com/2020/02/18/pwn%E9%A2%98%E5%8A%A0%E8%BD%BD%E4%BB%BB%E6%84%8F%E7%89%88%E6%9C%AClibc/](https://at0de.com/2020/02/18/pwn题加载任意版本libc/)

[关于不同版本glibc强行加载的方法（附上代码)](https://bbs.pediy.com/thread-225849.htm)

[关于不同版本 glibc 更换的一些问题](https://bbs.pediy.com/thread-254868.htm)

[glibc-all-in-one](https://github.com/matrix1001/glibc-all-in-one)

[pwndbg](https://github.com/pwndbg/pwndbg)

[pwn调试：gdb+pwndbg食用指南](https://blog.csdn.net/Breeze_CAT/article/details/103789233)





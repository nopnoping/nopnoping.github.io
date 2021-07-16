# 最酷pwn环境搭建(vscode+docker)


**引言**

“工欲善其事，必先利其器”。有一个高效便捷的pwn环境，对于做题而言，能起到锦上添花，事半功倍的作用。

之前用vmware或则virtual box搭建的ubuntu虚拟机，感觉过于笨重，启动不仅缓慢，而且随着使用时间一长，占用的磁盘空间也日渐增加。随后又尝试过用wsl2搭建pwn环境，但是在编写代码时遇到困难。vim虽是神之编辑器，但学习曲线过于陡峭，学习成本太高，于是放弃死磕，转向了vs code。

vs code编辑器不仅有命令行窗口，而且插件功能十分强大。那我们是否可以在vs code里面编写代码，用其命令行启动虚拟机来进行调试？这里虚拟机可以采用wsl2或docker。最终我采用了docker作为虚拟环境，其中最主要的原因是vs code可以通过插件来连接docker作为编程环境，进而在编写代码时能有更好的提示。

## vs code插件

vs code的安装这里就不阐述了，在[官方](https://code.visualstudio.com/)找到所需系统的安装包，下载安装即可，这里说明一下为搭建本文环境需要的一些插件。

+ Docker
+ Remote-containers
+ Remote-WSL

## docker环境

docker的环境为了方便，直接使用了别人预先搭好的一个docker pwn环境[skysider/pwndocker](https://hub.docker.com/r/skysider/pwndocker)，然后对其中进行了一下几点更改。

+ 更新了pwntools的版本（v4.5.0在连接tmux时会报错，更新至v4.5.1）
+ [美化tmux](https://github.com/gpakosz/.tmux)

更改后的环境，我上传到了docker hub中，也可直接下载，而不需要再进行更改。[更改后的docker环境](https://hub.docker.com/r/luexp/dockerpwn)

## 食用姿势

首先利用wsl2中的linux虚拟机来启动docker环境。启动的方法在 skysider/pwndocker 中有介绍。为了后续启动便利，创建一个可复用启动脚本。

*注意：这里一定要用linux虚拟机来启动docker环境，否则docker column可能会无法连接上本地文件夹*

```bash
#/bin/sh
docker run -d \
    --rm \
    -h pwngame \
    --name pwngame \
    -v $(pwd):/ctf/work \
    -p 23946:23946 \
    --cap-add=SYS_PTRACE \
    luexp/dockerpwn
```

在做题文件夹下，打开vs code，然后在命令行中启动wsl2，运行启动脚本，打开docker环境。

![image-20210716141220137](https://gitee.com/nopnoping/img/raw/master/img/image-20210716141220137.png)

**注：这里想在wsl2中使用docker 需要在docker desktop中设置wsl2。**

![image-20210716141107717](https://gitee.com/nopnoping/img/raw/master/img/image-20210716141107717.png)

利用vs code的Remote-Container插件，连接docker环境。在vscode左侧导航栏出，点进Docker图标，然后Attach到自己打开的环境上。

![image-20210716141455771](https://gitee.com/nopnoping/img/raw/master/img/image-20210716141455771.png)

就可以开始愉快的调试程序啦！

![image-20210716141703448](https://gitee.com/nopnoping/img/raw/master/img/image-20210716141703448.png)

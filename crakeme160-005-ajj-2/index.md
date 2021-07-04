# CrakeMe160(005)-ajj.2


我只想做你的太阳 你的太阳 在你的心里呀 在你的心底呀    ——太阳

<!--more-->

# 前言

这是吾爱破解160crakeme系列里面的第5题，这道题的作者设置了层层关卡，其验证机制简直反人类，只能说这个机制是用来专门考验reverse人员的，那让我们一起来看一看一道题吧。

# 破解

## 去壳

程序加了UPX壳，可以手动去壳，也可以用脱壳机。在尝试手动脱壳过程中,dump程序后，程序运行出错，于是就用脱壳机脱壳了。

UPX脱壳机可以在爱盘里面找到，脱壳完毕我们就开始破解了。

## DeDe分析控件

程序是由Delphi编写的，所以可以用DeDe反编译，得到程序的控件和事件信息。

![image-20200605161102539](https://i.loli.net/2020/06/05/cZVHrbOtFofmya5.png)

![image-20200605161114245](https://i.loli.net/2020/06/05/pHfOEja21c4MwZk.png)

## 搜索关键字

搜索关键词，查找关键代码。这里我在IDA中搜索'"注册"得到下面的结果。

![image-20200605160050964](https://i.loli.net/2020/06/05/4KrE8MdBvmCi1xY.png)

“注册了”字符应该是注册成功之后显示的，我们去查找哪儿引用了这个字符。成功的找到了验证注册成功的代码。

![image-20200605160333498](https://i.loli.net/2020/06/05/16tErSBAkh8qNf9.png)

要求ebx+304不等于C34，ebx+308不等于230D，ebx+310等于F94，ebx+31C不等于3E7,ebx+318和ebx+314相等，我们按照难易程度和顺序依次来分析，分析的顺序如下：

+ ebx+31C不等于3E7
+ ebx+304不等于C34
+ ebx+308不等于230D
+ ebx+310等于F94
+ ebx+318和ebx+314相等

利用的分析手段是，常量跟踪。下面的分析以其在ebx中的偏移为标题。

## 31C

在IDA中搜索31C常量并添加筛选条件。

![image-20200605160921354](https://i.loli.net/2020/06/05/jbTWQULZEVsgtOD.png)

跟踪第二条指令

![image-20200605160949646](https://i.loli.net/2020/06/05/jv4tr1H9fxP28as.png)

当Button1被点击时，就会触发这个事件，并将31C赋值为3E7，因此只要我们不点击注册按钮，就可以通过31C的验证。

## 304

同理用IDA搜索并筛选304常量

![image-20200605161431922](https://i.loli.net/2020/06/05/V5Yw8IhiBHDNsAl.png)

这里涉及的事件函数是_TForm1_FormCreate，让我们一起来分析这个时间函数的内容。

![image-20200605161827419](https://i.loli.net/2020/06/05/CyH9ViwjRtYr6gM.png)

![image-20200605161835424](https://i.loli.net/2020/06/05/fmcjlwNtao1GMqH.png)

这里会去读取“X:\ajj.126.c0m\j\o\j\o\ok.txt”这个路径下的ok.txt文件，方便起见我们可以把X修改为D，按照路径创建ok.txt.

![image-20200605162022472](https://i.loli.net/2020/06/05/yOcastrUuBEF9VL.png)

![image-20200605162029994](https://i.loli.net/2020/06/05/MpvdCLJIOtr8xVf.png)

这里会比较ok.txt文件里面的内容是否等于这个字符串，用WinHex去编辑ok.txt使其内容等于这里的验证字符串。

通过上面的验证后，304不会被赋值为C34

## 308

分析方法同上，IDA搜索加筛选。

![image-20200605165220302](https://i.loli.net/2020/06/05/JO9YWsvikuPjyH4.png)

与之相关的事件函数由，Panel1DbClick和Button1MouseDown

![image-20200605165514906](https://i.loli.net/2020/06/05/c3WTq5lA98xH6Db.png)

对左右键进行了判断，如果是左键点击，将对308赋值340D，如果是右键点击，将会加3。308的初始值为28E。

我们再看一下Panel1Dbclick里面的内容。

![image-20200605165753656](https://i.loli.net/2020/06/05/Wbok4dsiQvAwcMD.png)

当308的值为29D时，会对2F0处的空间进行操作，而2F0就是Edit2，这里作用是激活Edit2的编辑功能。而要使308为29D我们需要右键点击按钮（29D-28E）/3=5次。然后双击Pannel，注意不要点到图片。

## 310

310是该程序最复杂的地方。查找关键代码的方法同上。

![image-20200605170215484](https://i.loli.net/2020/06/05/t5ugn3ZzDGRTQYM.png)

这里主要涉及FormMouseMove事件函数，我们看一下该函数的关键内容。

![image-20200605170317995](https://i.loli.net/2020/06/05/BVfoAl5rZh1tiCI.png)

![image-20200605170947649](https://i.loli.net/2020/06/05/gox35QltVup9fWh.png)

当检测到鼠标发生移动后，就会执行这个事件函。该函数首先判断当前显示的图片是否是2E0及Image3，如果是，则检测其x是否大于0E2，y是否大于13C，是则给310赋值10。

后面又检测2DC及Image2，其x是否小于17，y是否大于12C，是则判断310是否等于10，是则继续判断30C的值是否等于9，如果不等于则会将310处赋值为F94，也就是我们的目标值。

所以如果要将310处赋值为F94我们还需要使得30C处的值不等于9，我们来看一下如何修改30C处的值。

![image-20200605171105716](https://i.loli.net/2020/06/05/dUseZCVDa5BMW2k.png)

Form组件创建时，给30C赋初值为9，而再Edit2DblClick中会修改30C中的值。

Edit2DblClick中会检测Edit2中的值，是否长度为8，且第2个字符为’_‘，第6个字符为’，‘，并且Edit1中的字符长度为3的倍数，则会对30C赋值，从而使得其不等于9，通过上面的验证。

## 318和314

方法同理，逆向分析结果是左右键点击不同的图片时，318会增加不同的结果，最后通过组合使得318的结果等于314及可以通过验证，最终破解成功。

# 参考

[CrackMe005全破详解](https://www.52pojie.cn/thread-855172-1-1.html)

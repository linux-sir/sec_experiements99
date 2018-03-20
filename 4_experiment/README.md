# 目标
- GDB+GEF 基本用法
- 栈的作用，函数调用，局部变量的过程
- 强化从静态代码到动态运行之间的思维转换。
- 

# 环境
- Ubuntu 14.04 i386


# 知识准备

## 栈在函数调用过程中的作用
- 深入到栈中，没有了变量的概念，完全靠栈指针ESP和桢指针EBP来操作其中的单元。
- 每调用一层函数，便产生一个栈桢。栈桢的创建和恢复对应着函数的调用和返回过程
- ESP作为整个栈的指针，始终指向栈顶单元，EBP作为栈桢的指针，始终指向当前栈桢的起点（另一端当然就是栈顶ESP）
- 栈桢的范围是从EBP到ESP之间的栈内存空间
- 调用一个函数过程中，函数的参数，返回地址并不在当前栈桢中(函数参数是调用前的准备，是父函数的工作，所以会保存在父函数的栈桢中，返回地址是创建新栈桢前需要保存的，所以不会出现在当前函数的栈桢中了。)



# 实验过程






## 实验1：通过栈中局部变量的位置关系，间接修改变量　

局部变量在栈桢中的位置关系。


### 代码editbystack.c


```
#include <stdio.h>
int main(int argc, char *argv[])
{
    int a = 10;
    char b[5];
    *(int *)(&b + 1) = 20;
    printf("a = %d\n",a);
    return 0;
}
```

说明：　在Ｍａｉｎ函数中声明的局部变量存放在栈中。

### 编译代码


```
gcc -g -o test editbystack.c  -fno-stack-protector
```

注：要去掉编译器的栈保护功能，若无-fno-stack-protector参数，则编译器会拒绝此类危险操作。


### 运行结果：

```
magc@magc-PC:~/workspace/remote_32/sec_experiements99/4_experiment$ ./test 
a = 20

```
从运行结果来看，变量a的内容被莫名其妙地修改掉了。

### 原理解释：

通过Ｃ语言的知识，比较难以理解a是怎么被修改的，让我们下潜到汇编层一看究竟吧。

使用objdump反编译main 函数，其对应的汇编语言如下：

```
0804841d <main>:
 804841d:       55                      push   %ebp
 804841e:       89 e5                   mov    %esp,%ebp
 8048420:       83 e4 f0                and    $0xfffffff0,%esp
 8048423:       83 ec 20                sub    $0x20,%esp　　　　　　　#esp向低地址移动32个字节，用来存入局部变量　
 8048426:       c7 44 24 1c 0a 00 00    movl   $0xa,0x1c(%esp)　　　　＃将10存入esp向高地址偏移0x1c位置处（此处对应变量a)
 804842d:       00
 804842e:       8d 44 24 17             lea    0x17(%esp),%eax      # 获取esp偏移0x17位置的地址
 8048432:       83 c0 05                add    $0x5,%eax            # 将此地址增加５个字节，其实正好到0x1c位置了,即对应a的位置
 8048435:       c7 00 14 00 00 00       movl   $0x14,(%eax)　　　　　# 向上述位置存放0x14 ,其实正好存到了a变量位置上面
 804843b:       8b 44 24 1c             mov    0x1c(%esp),%eax
 804843f:       89 44 24 04             mov    %eax,0x4(%esp)
 8048443:       c7 04 24 f0 84 04 08    movl   $0x80484f0,(%esp)
 804844a:       e8 a1 fe ff ff          call   80482f0 <printf@plt>
 804844f:       b8 00 00 00 00          mov    $0x0,%eax
 8048454:       c9                      leave
 8048455:       c3                      ret
 8048456:       66 90                   xchg   %ax,%ax
 8048458:       66 90                   xchg   %ax,%ax
 804845a:       66 90                   xchg   %ax,%ax
 804845c:       66 90                   xchg   %ax,%ax
 804845e:       66 90                   xchg   %ax,%ax

```
==其实深入到汇编层，已经没有了变量的概念，完全变成了通过ESP，EBP来操作栈中内存单元的过程==，根据汇编层的指令，就很容易看到此深层次的处理过程，详见注释内容。


## 实验2：栈是实现函数调用的重要装置

### 背景知识
- 深入到栈中，没有了变量的概念，完全靠栈指针ESP和桢指针EBP来操作其中的单元。
- 每调用一层函数，便产生一个栈桢。栈桢的创建和恢复对应着函数的调用和返回过程
- ESP作为整个栈的指针，始终指向栈顶单元，EBP作为栈桢的指针，始终指向当前栈桢的起点（另一端当然就是栈顶ESP）


### 代码示例文件

```
int fun1(int a, char c)
{
    return c*a;
}

int fun2(int b)
{
    int c = 2;
    fun1(b + c,'d');
}
int main(void)
{
    
    int d = 10;
    fun2(d);
    return 0;
}

```
说明：在Main函数中调用了两个函数fun1和fun2,通过分析对应的汇编，使用GDB+GEF插件调试函数调用过程。



### 关键点的栈示意图

#### main函数开始前：

![image](http://on44nkxjb.bkt.clouddn.com/18-3-20/48074157.jpg)

#### 开始main函数栈桢：

![image](http://on44nkxjb.bkt.clouddn.com/18-3-20/24993072.jpg)

栈桢创建后，意味着开始执行Main函数。


#### 为处理局部变量开辟内存空间：

通过理面语句开辟栈空间：

```
   0x804842d <main+3>:	sub    esp,0x14
```
注：==通过向上移动ESP，为局部变量预留出空间来存放，访问就通过ESP或 EBP偏移来实现，另一方面，也不影响其它需要压栈的操作。==


![image](http://on44nkxjb.bkt.clouddn.com/18-3-20/70762104.jpg)

#### 调用fun2函数：

call fun2 相当于：

```
push %eip        # 保存下一个指令地址到栈中，作为将来调用子函数结束后的返回地址
mov %eip fun2    # 开始执行fun2函数指令

```
示意图：
![image](http://on44nkxjb.bkt.clouddn.com/18-3-20/66012353.jpg)

#### fun2函数的栈桢：



```
#创建新的栈桢分两步

0x8048403 <fun2>:	push   ebp       #保存旧的栈桢起点，以便恢复
0x8048404 <fun2+1>:	mov    ebp,esp   # 设置新的栈桢起点位置
```
![image](http://on44nkxjb.bkt.clouddn.com/18-3-20/91663741.jpg)



#### call fun1函数

![image](http://on44nkxjb.bkt.clouddn.com/18-3-20/35069079.jpg)

#### fun1函数的栈桢

![image](http://on44nkxjb.bkt.clouddn.com/18-3-20/64749359.jpg)


#### fun1函数的返回

函数的返回分为两步：
- 1. leave 恢复父函数的栈桢

相当于下面两句汇编：

```
mov %ebp ,%esp   # 将栈指针ESP指向当前的栈底EBP处，准备弹出此处保存的上一个栈桢地址
pop %ebp         # 从栈中取出上一个栈桢地址，使EBP恢复父函数的栈桢起点，另一方面，ESP增大一个位置，正好指向函数返回地址的单元，为后面ret作好准备。

```
运行结果如下图所示：
![image](http://on44nkxjb.bkt.clouddn.com/18-3-20/16441954.jpg)

- 2. ret 跳回父函数fun2的指令

ret指令相当于：

```
pop %eip  # 前面leave已经使父函数的地址处在栈顶了，这里赋给EIP，便能顺利跳转回父函数了。
```

返回到父函数fun2的栈示意图如下：

![image](http://on44nkxjb.bkt.clouddn.com/18-3-20/67789867.jpg)

注：==可以看出，与call fun1前的栈桢是一致的，可见栈桢恢复正常==


#### fun2函数的返回

细节可参照上面，直接上图：

![image](http://on44nkxjb.bkt.clouddn.com/18-3-20/43686523.jpg)

返回到父函数main的栈桢示意图：

![image](http://on44nkxjb.bkt.clouddn.com/18-3-20/76735725.jpg)

注：与之前的栈桢也是一致的。


#### main函数的返回

细节可参照上面，直接上图：

![image](http://on44nkxjb.bkt.clouddn.com/18-3-20/12473876.jpg)



## 证明：调用一个函数过程中，函数的参数，返回地址并不在当前栈桢中

### 本质　：
我们所传的函数的参数实际上保存在调用该函数的函数的栈帧中。例如Q调用了P那么P的参数实际保存在Q的栈帧中

### 原理：
函数参数是调用前的准备，是父函数的工作，所以会保存在父函数的栈桢中，返回地址是创建新栈桢前需要保存的，所以不会出现在当前函数的栈桢中了


注：通过内嵌汇编方式，以当前EBP为基点，找原参数位置

借用上面示例的栈桢图：

![image](http://on44nkxjb.bkt.clouddn.com/18-3-20/32089938.jpg)






# 参考
- http://blog.csdn.net/qiu265843468/article/details/17844419
- http://blog.csdn.net/xy010902100449/article/details/51376032
- http://blog.csdn.net/shelsea_x/article/details/43706229
- http://blog.csdn.net/Matthew_w/article/details/51558858v
- http://blog.csdn.net/Monamokia/article/details/51615395
- http://blog.csdn.net/bytxl/article/details/47255619

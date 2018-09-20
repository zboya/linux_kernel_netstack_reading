# linux内核协议栈源码阅读
**有任何理解错误的地方，还望指出**

## linux官网
* [www.kernel.org/doc/](https://www.kernel.org/doc/html/latest/)
* [github.com/torvalds/linux](https://github.com/torvalds/linux)

## 目标
理解tcp/ip的协议栈，结合RFC和代码加深理解。

## 微信群
想一起阅读的小伙伴可以加我微信`sheepbao-520`,加入阅读群，备注`阅读linux kernel`

## github地址
https://github.com/sheepbao/linux_kernel_netstack_reading

### 目前的进度
* 2018-08-09 大概阅读了socket层的代码
* 2018-08-17 大概阅读了二层收发包的代码
* 2018-08-22 阅读网络设备的初始化和网络设备收发的大概流程，阅读vlan处理的注释
* 2018-08-26 对ip_output进行注释，大概看完ip发送的流程
* 2018-09-05 大概阅读邻居子系统
* 2018-09-12 阅读tcp接收数据的处理
* 2018-09-18 阅读tcp发送数据的处理（未完）

### 时间
每周三晚9:00-10:00

### linux版本
linux kernel 4.17

### 准备工作
* 有一台能上网的电脑
* 安装zoom软件，并注册
* 装一个阅读linux源码的编译器或者ide，推荐vscode
* 下载linux 4.17的源码

### 可以先阅读的资料
* [深入理解LINUX网络技术内幕](https://book.douban.com/subject/4015134/)  
* [Linux内核源码剖析:TCP/IP实现](https://book.douban.com/subject/5914256/)

### 活动步骤
线上阅读主要用来督催进度，及解决难点，需要线下自己多看多思考

* 线上用zoom共享屏幕，阅读linux kernel源码，一起讨论添加注释，尽量让每个人都理解
* 提交结果到github
* 有任何不理解的地方可以提issue，大家一起讨论

### 阅读的方式
整体从上层往下层读，先读socket层，然后传输层，网络层，链路层。

1. 选好一个主题，并查询资料阅读该主题的相关背景
2. 大概浏览阅读相关源码
3. 仔细阅读源码实现原理
4. 最后再整理整个流程

### 暂定的主题
1. socket的实现
2. udp的实现（先看udp，因为相对简单）
3. tcp的实现
4. ip层的实现
5. 邻居子系统的实现
5. ethernet层的实现


### 相似的项目
感谢以下的项目及作者，让我能够更快的理解协议栈代码  
https://github.com/y123456yz/Reading-and-comprehense-linux-Kernel-network-protocol-stack  

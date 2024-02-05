
2024-2-5:

最近这几天读了该项目的代码,学习了该项目驱动注入的思想,并在代码内写上了辅助解读的注释.

该项目通过HOOK ZwContinue函数实现DLL注入,另一篇关于HOOK ZwContinue函数实现驱动注入的文章:  https://bbs.125.la/thread-14745435-1-1.html

前言:

1. 进程的大概创建流程: 由CreateProcess启动一个进程->加载ndtll->创建主线程->初始化进程结构->加载系统的各种dll->ZwTestAlert->ZwContinue
2. ZwContinue函数: 该函数的作用是创建新线程,创建一个进程,必定会调用该函数,该函数的执行优先于目标程序任何代码,所以通过HOOK该函数可以也可以一定程度上避免检测.



该项目驱动注入的核心思想:

1. 通过PsSetLoadImageNotifyRoutine函数,注册监控模块加载的回调函数,监控进程加载ntdll.dll的时机(PS: 许多函数需要在ntdll.dll加载后才可以使用).
2. 通过PsSetCreateProcessNotifyRoutine函数,注册监控进程创建的回调函数,主要作用是向注入列表 添加/删除 PID.
3. 通过HOOK ZwContinue函数走入payload逻辑,在payload内调用 MemLoadShellcode_x64/MemLoadShellcode_x86 中的函数将被注入DLL加载至内存.


注入流程: 
1. 监控到ntdll.dll的加载(PS:ZwContinue函数也在ntdll.dll里).
2. 找到当前进程的ZwContinue函数的地址,HOOK该函数跳转到我们的payload.
3. 在 payload 内调用 MemLoadShellcode_x64/MemLoadShellcode_x86 中的函数,实现加载被注入DLL.


测试:

测试Ydark注入成功,该程序有反调试(PS:虽然不知道反调试程度怎么样).

使用Ydark查看被注入进程的模块信息,没有找到被我们注入的DLL信息,成功隐藏.





# DriverInjectDll

## Introduction
 
Using Driver Global Injection dll, it can hide DLL modules. You need to determine the process name you want in DllMain

## Develop

#### DriverInjectDll
driver program

#### Input_dll
Tell the driver to inject DLL binary data

#### Loader
Shelcode for Memory Loaded DLL

#### MyDll
TODO: Judging Injected Process Name in DLLMain

# Build
vs2008-vs2017

wdk7-wdk10

# How Use
step1: install and start driver program

step2: run Input_dll.exe

# screen snapshot 
![avatar](./snapshot1.jpg)

## Support

Win7-Win10 x64

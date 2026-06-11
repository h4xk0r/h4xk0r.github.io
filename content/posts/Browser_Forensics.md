+++
date = '2026-06-02T19:39:17+08:00'
draft = false
title = 'Browser_Forensics'

+++

# 基于chrome获取浏览器凭证

### 常见的凭证类型

````
1. 用户名密码
2. cookie
3. token
4. 证书
5. ......
````

## 浏览器存储凭证的位置(新版)

```
%LOCALAPPDATA%\Google\Chrome\User Data\Default
```

| 文件            | 作用                                        |
| --------------- | ------------------------------------------- |
| Login Data      | 保存网站登录信息(AES-GCM加密的密码记录)     |
| Cookies         | Cookie 数据库(新版本在Default\Network下)    |
| History         | 浏览历史                                    |
| Web Data        | 自动填充数据                                |
| Local State     | 网站本地存储数据(DPAPI加密的AES Master Key) |
| Session Storage | 会话存储                                    |

### 前置知识

**Master Key :** 用来加密其他需要加密的数据,是一个随机生成的对称密钥,长度一般是`256bit`(随windows版本变化). 一般在首次创建windows账户时生成, 存放位置`%APPDATA%\Microsoft\Protect\`

```
用户登录密码
       ↓
派生
       ↓
DPAPI Master Key
       ↓
保护其他密钥(chrome AES Key)
       ↓
保护应用数据(网站密码)
```

**DPAPI(Data Protection Application Programming Interface):** 是windows系统对数据加解密的一种接口,程序可以通过调用`CryptProtectData`加密数据，`CryptUnprotectData`解密数据

**注:** DPAPI ≠ Master Key

DPAPI的两种模式:

-  User Scope : 绑定当前用户,只有当前用户可以解
- Machine Scope : 绑定电脑, 只有同机用户可按权限访问

## 加密流程

#### chrome80+之前

```
password
    ↓
CryptProtectData()   (DPAPI)
    ↓
直接存入 Login Data
```

#### chrome80+之后,整体结构

```
password
    ↓
AES-GCM
    ↓
encrypted_password
    ↓
Login Data



AES Master Key
      ↓
DPAPI
      ↓
Local State
```

运行步骤

```
1. 生成AES Master Key

chrome 启动
    ↓
生成随机256位密钥
    ↓
AES Master Key

2. 用 DPAPI 加密 Master Key

AES Master Key
      ↓
CryptProtectData()
      ↓
DPAPI密文
写入Local State文件

3. 用户保存密码(alice:Password123)
读取AES Master Key,执行AES-GCM加密

4. AES-GCM加密校验数据
Password123
      ↓
AES-GCM
      ↓
Ciphertext
Nonce
Tag
组成[Version][Nonce][Ciphertext][Tag],这就是数据库中的password_value字段

5. 写入Login Data
将网址,用户名,密码写入文件中的origin_url	username_value	password_value字段
```

参考文章

```
https://github.com/muxq/DPAPI
```


+++
date = '2026-02-28T22:41:23+08:00'
draft = false
title = 'JS'
+++

本人代码能力不是很好，对很多网站框架和文件理解不是很深，所以看js文件的时候难免有些困难，所以有了这篇文章



### JS审计技巧

遇到source.map(.map)可以直接还原源码



首先是一些用来搜索的正则：

- `api/| /v[0-9]|/admin|/internal|/private`
- `key:|secret:|token:|password:|apikey|sk_ |pk_ |AKIA`（AWS）
- `fetch|axios|XMLHttpRequest|$.post|$.ajax`
- `localStorage|sessionStorage|cookie`
- `if\s*\(\s*user\.role|isAdmin|level|permission`
- `innerHTML|eval|document\.write`（XSS sink）



#### 看完上面这些，还要看什么？

1. **密钥**

   如: `const KEY = "xxx"`、`process.env.VITE_xxx`（Vite 常见泄露）、`client_secret`。

如config.chunk.js 里：

```javascript
const stripeConfig = {
  publishableKey: "pk_live_51Hb...xxxx",   // Stripe 真实密钥
  clientSecret: "sk_test_51Hb...xxxx"
};
```

```javascript
var fallbackSecret = "supersecret2025!@#";  // 备用密钥
```

2. **API**

可以用上面的正则去搜

3. **逻辑/授权检查**

如:  `if (user.isAdmin)`、`if (role === 'vip')`、`if (canEdit)`。

```javascript
if (user.vipLevel >= 3) {
  showDownloadButton();   // 前端判断
} else {
  hideIt();
}
```

4. **加密/签名**

如`CryptoJS`、`encrypt`、`sign`、`md5`、`rsa` 函数。

```javascript
password: CryptoJS.AES.encrypt(pwd, 'hardcoded_key_123').toString()
```

逆向出密钥，就能批量撞库或伪造登录



#### 不用看的JS

1. 第三方库完整代码jquery-3.6.0.min.js、lodash.min.js、react.production.min.js 全文件。 → 只看最上面注释的版本号（查 CVE），其余不看。

2. 一些框架的打包，如React/Vue/Next.js 的

   ```javascript
   _createElementVNode, useState, render() { ... }
   ```

3. 还有一些轮番图片等



### 步骤：

1. 正则匹配的看完

2. Network看加载

   ```
   F12 → Network → 过滤 js
   刷新页面 / 登录 / 点击关键功能（支付、查看用户列表）
   看哪个 JS 在你操作后才加载 → 那就是核心业务文件
   
   不看的：页面一打开就加载的 vendor.*.js（第三方库，如 React、lodash）
   ```

3. 可以把JS全部下载下来然后搜索：

   ```
   一个简单的搜索
   grep -l -E "fetch|axios|api/|token|secret|isAdmin" *.js
   ```

   按大小排序看大的文件，就有可能是业务逻辑

注： 先检查有没有source.map ,如果有可以直接还原

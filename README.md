# PHP_API_Security_by_Improved_NoCSRF

### 改良NoCSRF实现对PHP后端接口的安全验证
    自己造的轮子，用于对前后端分离中后端接口的安全加固，如果有缺陷，还请指出，共同讨论改良！

改良和改造[NoCSRF](http://bkcore.com/blog/code/nocsrf-php-class.html)，实现对PhalAPI接口框架等前后端分离架构接口的安全加密认证。

    不想看分析思路的可以直接跳到“实现过程”及上传的源码，参照进行部署。
    
#### 目录：
* NoCSRF的介绍
* 配置到框架（以单次请求为示例）
* 多次请求的处理
* 解决方案
* 实现过程
* 结语

-------

#### NoCSRF
>国外大神开发的一个包，用于防范Web页面中的[CSRF](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29)攻击。

    代码一共有120行，思路很清晰，有兴趣可以进行拜读NoCSRF.php。

思路类似于常见的接口签名的实现：
1. 将`请求头`和`IP`进行SHA1后，与20位随机码及时间戳连接，最后进行Base64处理。
2. 每次请求接口前，生成上述`$token`存储到`Session`中
3. 携带`$token`请求接口。
4. 后台验证时候逐步进行：
    * `Session`中`$token`存在性检查
    * `$_POST`数组中`$token`存在性检查
    * 请求来源检查(`请求头`和`IP`进行SHA1，与`$token`中的值进行对比)
    * 验证`Session`和`$_POST`中的`$token`是否相同
    * 验证该`$token`是否过期(比对时间戳)
5. 验证通过后，执行接口操作，否则抛出异常。
6. 销毁`$token`。

只要`$token`生成并存储的位置选择合理（每次页面加载前，PHP网页头部），基本不存在伪造的可能。因为`$token`生成时就放入了`Session`数组当中，存储在`服务器硬盘`或`Redis`等缓冲区中，同时`$token`作为表单请求，后台将二者进行多重验证。

    后面会介绍到，这个包只适用于一个页面对后端只有一次接口调用，多次请求需要进行改良。
    
-------

#### 配置到框架（以单次请求为示例）
>配置前参见官网简单请求的示例：[(PHP) NoCSRF](http://bkcore.com/blog/code/nocsrf-php-class.html)

1. 在框架命名空间中注册：
    ```php
    // nocsrf.php放入到/src/App/Common/
    <?php
    namespace App\Common;
    ///。。。
    class NOCSRF{
    
    }
    ?>
    ```
    
2. 页面头部生成Token： 
    ```php
    <?php
        require_once("../vendor/autoload.php");//自动加载类
        use App\Common\NoCSRF;
        
        session_start();
        $token = NoCSRF::generate('csrf_token');
    ?>
    ```
3. 表单携带Token：
    ```html
    <form name="csrf_form" action="#" method="post">
	   <input type="hidden" name="csrf_token" value="<?php echo $token; ?>">
	...Other form inputs...
        <input type="submit" value="Send form">
    </form>
    ```
如果是Ajax，直接放入到变量当中，记得加上引号: `var token = '<?php echo $token; ?>';`。
* 后端验证：(对于每一个需要验证的接口，在构造函数内执行，`./src/App/Api/xxx.php`)

```php
<?php
    namespace App\Api;
    
    use PhalApi\Api;
    
    use App\Common\NoCSRF;
    use PhalApi\Exception;

    class Login extends Api{
        public function __construct(){
            session_start();
        
            try {
    			// Run CSRF check, on POST data, in exception mode, with a validity of 10 minutes, in one-time mode.
    			NoCSRF::check( $MainKey, $_POST, true, 60*10, false );
    			// form parsing, DB inserts, etc.
    		  }
        		catch ( Exception $e ) {
        			exit('Need token!');
        			// CSRF attack detected
        		}
        } 
        
        public function getRules(){
        //.....
        }
        
        //...Other functions...
    }
?>
```
以上内容针对：**页面加载一次只请求后台一个接口**的情形，比如登录。

-------

#### 多次请求的处理
对于一个页面**同时请求多个**接口，上述显然不适合。因为页面每次加载只会生成一个`$token`，而这个`$token`用于验证后，就会被后台销毁掉，同时请求的其他接口就会失效，而抛出`Need Toekn！`。
##### 思路1：（不可行）
>Ajax请求接口的时候再`<?php echo NoCSRF::generate('csrf_token');?>`

比如下方例子，理论上可行，有请求就生成`token`，但实际上只有最后一次生成的`token`有效。因为PHP网页也算作脚本，页面每次刷新，页面内所有的PHP代码都会自动执行，所以`前方的token`会`在后方的token`生成后被销毁。

```javascript
function f1(){
    $.ajax({
        url: "xxxxx",
        type: "POST",
        data: {
            'csrf_token': '<?php echo NoCSRF::generate('csrf_token');?>'
        },
        success: function(res, status, xhr) {
            console.log(res);
        },
    })
}

function f2(){
    $.ajax({
        url: "xxxxx",
        type: "POST",
        data: {
            'csrf_token': '<?php echo NoCSRF::generate('csrf_token');?>'
        },        
        success: function(res, status, xhr) {
            console.log(res);
        },
    })
}
```

##### 思路2：（可行但漏洞显而易见）
>生成`token`单独作为接口发布，每次需要就先请求再获取。

于是有了以下方案：
* 生成token的接口`./src/App/Api/Token.php`

```php
<?php

namespace App\Api;

use PhalApi\Api;
use App\Common\NoCSRF;
use PhalApi\Exception;

class Token extends Api{
	public function getRules(){
		return array(
			'index' => array(),
		);
	}

	public function index(){
		session_start();
		return NoCSRF::generate('csrf_token');
	}
}
```
* Ajax调取接口，封装成函数

```javascript
function getCSRF(){
    let csrf_token = "";
    $.ajax({
        type: "GET",
        cache: false,
        async: false,
        url: "/xxx/xxx/?s=Token/Index",//Tokenj接口的URL
        success: function(res) {
            csrf_token = res.data;
        }, error: function(XMLHttpRequest, textStatus, errorThrown) {
            console.log(XMLHttpRequest.status);
            console.log(XMLHttpRequest.readyState);
            console.log(textStatus);
            console.log(errorThrown);
            csrf_token = "";
        }
    });
    return csrf_token;
}
```
* 每次需要就执行:

```javascript
function refresh(){
    $.ajax({
        url: "xxxxx",
        type: "POST",
        data: {
            'csrf_token': getCSRF(),
            'otherData' : 'xxx',
        },        
        success: function(res, status, xhr) {
            console.log(res);
        },
    })
}
```
后面发现，直接用Postman请求`/xxx/xxx/?s=Token/Index`，获取到`token`，再携带这个`token`请求其他接口，依然能访问成功。
>思考发现，这时的`token`仍然是在服务器端生成，无状态的HTTP请求直接拿过去，再反回来请求，依然是可行，只起到了验证时效性验证的功能，`token`与客户端没有唯一性联系，这种方案脱离了NoCSRF包本身的设计思路。

-------

#### 解决方案：
>每次生成`token`的过程'`NoCSRF::generate('csrf_token');`'，其中的'`csrf_token`'是自定义的，那么不妨把这个`key`利用起来，使之成为唯一且动态变化的值。

![普通请求](https://images.gitee.com/uploads/images/2019/0320/153441_fd4a7b08_1847665.png)

>在每个页面首部生成`Token1`，作为后面接口生成的`token`的`token_key`，请求是下面的样子：

![改良后的请求](https://images.gitee.com/uploads/images/2019/0320/150720_05ff6009_1847665.png)

>由于`Token1`是在页面首部（自身脚本，相当于与客户端绑定）生成的，不存在被伪造的可能 (原因见文章第一部分的介绍) ，故身份具有唯一性，拥有token的网页才可以访问接口。

-------

#### 实现过程：
>注册接口: 每次页面加载会生成`Token1`，并请求此接口验证身份，当作`token_key`。
>token接口: 请求此接口会得到`token_key: token2`(上图)样式的`Token`用于业务接口的验证。
>常规接口: 业务接口，比如“获取列表”。

* 每个页面生成`Token1`并前往注册，注册成功`Token1`采纳，否则为空：(存储在session中)

```php
<?php
    require_once("../vendor/autoload.php");
    use App\Common\NoCSRF;
    
    session_start();
    $token = NoCSRF::generate('csrf_token');
    $_SESSION['token_key'] = $token;//token_key或者Token1
?>

<html>
<body>
<script>
    var token_key = "";
    $.ajax({
        url: "/xxx/public/?s=Token/Login",//身份注册接口
        type: "POST",
        cache: false,
        async: false,
        data:{
            "csrf_token": "<?php echo $token?>",
        },
        success: function(res) {
            token_key = "<?php echo $token?>";
        }, error: function(error) {
            console.log(error);
            token_key = "";
        }
    });
</script>
</body>
</body>
```
* 注册接口：`./src/App/Api/Token.php`（这里的key仍然是‘`csrf_token`’）

```php
public function Login(){//页面头部的注册
	session_start();
	try {
		NoCSRF::check( 'csrf_token', $_POST, true, 60*10, false );
	}
	catch ( Exception $e ) {
		unset($_SESSION['token_key']);//验证不通过就销毁
		exit('Need token!');
	}
}
```

* 拥有`token_key`后获取组合`token`: （此处开始，`token`以`token_key`作为键值）

```php
    // ./src/App/Api/Token.php
	public function index(){
		session_start();
		$token_key = $_SESSION['token_key'];
		//generate函数的参数不再是'csrf_token'而是$token_key
		return NoCSRF::generate($token_key);
	}
	
	//Ajax请求Token，这一步无变化
	function getCSRF(){
        let csrf_token = "";
        $.ajax({
            type: "GET",
            cache: false,
            async: false,
            url: "/xxx/xxx/?s=Token/Index",             
            success: function(res) {
                csrf_token = res.data;
            }, error: function(error) {
                console.log(error);
                csrf_token = "";
            }
        });
        return csrf_token;
    }

	//请求业务接口，这里需要将Token1/token_key作为key，其中token_key就是页面首部生成，通过身份注册的
	<script>
    let json_data = {
        'data1' : 'xxx',
    };
    //注意，变量作为key传输必须用下方写法，不能用上面json格式写法，否则key直接为'token_key'.
    json_data[token_key] = getCSRF();
    
    $.ajax({
        url: "/xxx/xxx/?s=Order/GetList",
        type: "POST",
        data: json_data,        
        success: function(res, status, xhr) {
            console.log(res);
            //
        },
    })
   </script>
```

* 业务接口验证（对于每一个需要验证的接口，在构造函数内执行，`./src/App/Api/Order.php`）：

```php
public function __construct(){
	session_start();
	
	//验证$_SESSION中是否存在'token_key'
	if(!isset($_SESSION['token_key'])){
		exit('Need token!');
	}
	$token_key = $_SESSION['token_key'];
	
	//注意下方check函数的第一个参数不再是'csrf_token'而是$token_key
	try {
		NoCSRF::check( $token_key, $_POST, true, 60*10, false );
	}
	catch ( Exception $e ) {
		exit('Need token!');
	}	
}
	
public function getRules(){
   //...
}
	
/// ...Other functions...
```

-------

### 完结
至此，整个从前端请求和后端接口验证过程结束。至于如何部署到Phalapi框架或其他框架里面，相信看完整个过程就可以上手，也可以直接查看上传的示例。

本方案只针对采用前后端分离框架开发的微服务项目中，接口安全验证的防护。Web开发中涉及到方方面面的安全性问题：明文传输、数据库明文存储、XSS、渗透、社工等，要想让项目固若金汤，开发过程中都勇于去面对这些问题，寻找方案进行加固。

    《鸟哥的Linux私房菜-服务器架设篇》和《大型网站技术架构》推荐阅读

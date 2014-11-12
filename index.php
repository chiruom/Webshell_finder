index.php 
<?php
header('Content-type:text/html;charset=gbk3212');
include("reservoir.php");//特征库


$realpath = realpath('./');
$selfpath = $_SERVER['PHP_SELF'];
$selfpath = substr($selfpath, 0, strrpos($selfpath,'/'));
define('REALPATH', str_replace('//','/',str_replace('\\','/',substr($realpath, 0, strlen($realpath) - strlen($selfpath)))));
define('MYFILE', basename(__FILE__));
define('MYPATH', str_replace('\\', '/', dirname(__FILE__)).'/');
define('MYFULLPATH', str_replace('\\', '/', (__FILE__)));
define('HOST', "http://".$_SERVER['HTTP_HOST']);

?>
<head>
<style type="text/css">
body{ font-family:微软雅黑;} 

</style>
</head>
<title>服务器恶意脚本检测</title>
<body style="font-family:微软雅黑" >

<font size="5" ><b style="background-color:White">服务器恶意脚本检测</b></font><br>
<a href="http://chiruom.blog.163.com/blog/?action=home"><font color="black" >首页</font></a> | <a href="http://chiruom.blog.163.com/blog/?action=scan"><font color="black" >扫描</font></a> |<a href="http://chiruom.blog.163.com/blog/?action=about"><font color="black" >关于</font></a> <br><br>

<?php

$action = isset($_GET['action'])?$_GET['action']:"home";
$setting=array();



if($action=="scan"){
$setting = getSetting();
$dir = isset($_POST['path'])?$_POST['path']:MYPATH;
$dir = substr($dir,-1)!="/"?$dir."/":$dir;
?>
<form name="scanf" method="post" action="">
扫描路径:<input type="text" name="path" id="path" style="width:600px" value="<?php echo $dir?>"/> &nbsp;<br>
文件后缀:<input type="text" name="checkuser" id="checkuser" style="width:300px;" value="<?php echo $setting['user']?>"><br>
<label for="checkall">所有文件</label>
<input type="checkbox" name="checkall" id="checkall" <?php if($setting['all']==1) echo "checked"?>><br>
<label for="checkhta">设置文件</label>
<input type="checkbox" name="checkhta" id="checkhta" <?php if($setting['hta']==1) echo "checked"?>><br>
<input type="submit" name="btnScan" id="btnScan" value="开始扫描">

</form>
<?php 
}

elseif($action=="about")
{
echo "四川大学大学生创新训练计划<br>";
echo "电子信息学院 信息安全<br>";
echo "指导老师 方勇<br><br>";
echo "刘梓溪 1142053001<br>";
echo "李亚威 1142053025<br>";
echo "张仁栋 1142053007<br>";
echo "张航 1142053005<br>";
}
elseif($action=="download" && isset($_GET['file']) && trim($_GET['file'])!="")
{
$file = $_GET['file'];
ob_clean();
if (@file_exists($file)) {
header("Content-type: application/octet-stream");
header("Content-Disposition: filename=\"".basename($file)."\"");
echo file_get_contents($file);
}
exit();
}

elseif($action=="home"){
echo "<img src='http://chiruom.blog.163.com/blog/img.jpg'/><br>";
echo "四川大学大学生创新训练计划作品<br>";
}

if($_POST[btnScan]){
$Ssetting = array();
$Ssetting['user']=isset($_POST['checkuser'])?$_POST['checkuser']:"php | php? | phtml";
$Ssetting['all']=isset($_POST['checkall'])&&$_POST['checkall']=="on"?1:0;
$Ssetting['hta']=isset($_POST['checkhta'])&&$_POST['checkhta']=="on"?1:0;
setcookie("t00ls_s", base64_encode(serialize($Ssetting)), time()+60*60*24*365,"/");
//
$start=time();
$is_user = array();
$is_ext = "";
$list = "";

if(trim($setting['user'])!="")
{
$is_user = explode("|",$setting['user']);
if(count($is_user)>0)
{
foreach($is_user as $key=>$value)
$is_user[$key]=trim(str_replace("?","(.)",$value));
$is_ext = "(\.".implode("($|\.))|(\.",$is_user)."($|\.))";
}
}
if($setting['hta']==1)
{
$is_hta=1;
$is_ext = strlen($is_ext)>0?$is_ext."|":$is_ext;
$is_ext.="(^\.htaccess$)";
}
if($setting['all']==1 || (strlen($is_ext)==0 && $setting['hta']==0))
{
$is_ext="(.+)";
}

$php_code = getCode();
if(!is_readable($dir))
$dir = MYPATH;
$count=$scanned=0;
scan($dir,$is_ext);
$end=time();
$spent = ($end - $start);
?>

<div style="padding:10px; background-color:#ccc">扫描: <?php echo $scanned?> 文件 | 发现: <?php echo $count?> 处可疑代码 | 耗时: <?php echo $spent?> 秒</div>
<table width="100%" border="0" cellspacing="0" cellpadding="0">
<tr class="head">

<td width="48%">文件</td>
<td width="19%">更新时间</td>
<td width="10%">结论</td>
<td width="10%">危险指数</td>
<td width="10%">细节</td>
<td>动作</td>
</tr>
<?php echo $list?>
</table>
<?php

}



function scan($path = '.',$is_ext){
global $php_code,$count,$scanned,$list;
$ignore = array('.', '..' );
$replace=array(" ","\n","\r","\t");
$dh = @opendir( $path );

while(false!==($file=readdir($dh))){
if( !in_array( $file, $ignore ) ){ 
if( is_dir( "$path$file" ) ){
scan("$path$file/",$is_ext); 
} else {
if ($file=="reservoir.php")
continue;
$current = $path.$file;//
if(MYFULLPATH==$current) continue;
if(!preg_match("/$is_ext/i",$file)) continue;
if(is_readable($current))
{
$scanned++;
$content=file_get_contents($current);
$content= str_replace($replace,"",$content);
$weight=0;
$sum_reason="";
$detail="";
foreach($php_code as $key => $value)
{ 
//global $weight;
//echo $value;
//echo " ";
//echo "$weight";
//echo " <br>";
if(preg_match("/$value/i",$content))
{

$count++;
$j = $count % 2 + 1;
$filetime = date('Y-m-d H:i:s',filemtime($current));
$reason = explode("->",$key);
$weight=$weight+$reason[2];//权重相加（可以替换为其他算法）
//$sum_reason=$sum_reason." ".$reason[0]."<br>";
$detail=$detail.$reason[0]."——".$reason[1]."——".$reason[2]."<br>";

}
}
//特征库匹配完毕
//判断是否为恶意脚本↓
if($weight>100){
//echo "weight is ".$weight;
//echo "<br>"; 
$url = str_replace(REALPATH,HOST,$current);
preg_match("/$value/i",$content,$arr);
$list_clour="IndianRed";
if ($weight<250)
$list_clour="Orange";
$result="危险";
if ($weight<250)
$result="可疑";
$list.="
<tr bgcolor=".$list_clour." bordercolor='White ' class='alt$j' onmouseover='this.className=\"focus\";' onmouseout='this.className=\"alt$j\";'>

<td><a href='http://chiruom.blog.163.com/blog/$url' target='_blank'><font color='Black'>$current</font></a></td>
<td>$filetime</td>
<td>$result</td>
<td>$weight</td>
<td><a href='http://chiruom.blog.163.com/blog/detail.php?filename=".$current."&&filetime=".$filetime."&&detail=".$detail."'>点击查看</a></td>
<td><a href='http://chiruom.blog.163.com/blog/?action=download&file=$current' target='_blank'><font color='Black'>下载</font></a></td>
</tr>";


}

}
}
}
}
closedir( $dh );
} 
function getSetting()
{
$Ssetting = array();
if(isset($_COOKIE['3s']))
{
$Ssetting = unserialize(base64_decode($_COOKIE['3s']));
$Ssetting['user']=isset($Ssetting['user'])?$Ssetting['user']:"php | php? | phtml | shtml";
$Ssetting['all']=isset($Ssetting['all'])?intval($Ssetting['all']):0;
$Ssetting['hta']=isset($Ssetting['hta'])?intval($Ssetting['hta']):1;
}
else
{
$Ssetting['user']="php | php? | phtml | shtml";
$Ssetting['all']=0;
$Ssetting['hta']=1;
setcookie("3s", base64_encode(serialize($Ssetting)), time()+60*60*24*365,"/");
}
return $Ssetting;
}

?>
</body>

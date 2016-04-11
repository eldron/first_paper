var x0=0,y0=0,x1=0,y1=0;
var offx=6,offy=6;
var moveable=false;
var hover='#99CCFF',normal='#6699CC';//color;
var index=10000;//z-index;
//开始拖动;
function startDrag(obj)
{
         if(event.button==1)
         {
                 //锁定标题栏;
                 obj.setCapture();
                 //定义对象;
                 var win = obj.parentNode;
                 var sha = win.nextSibling;
                 //记录鼠标和层位置;
                 x0 = event.clientX;
                 y0 = event.clientY;
                 x1 = parseInt(win.style.left);
                 y1 = parseInt(win.style.top);
                 //记录颜色;
                 normal = obj.style.backgroundColor;
                 //改变风格;
                 obj.style.backgroundColor = hover;
                 win.style.borderColor = hover;
                 obj.nextSibling.style.color = hover;
                 sha.style.left = x1 + offx;
                 sha.style.top   = y1 + offy;
                 moveable = true;
         }
}
//拖动;
function drag(obj)
{
         if(moveable)
         {
                 var win = obj.parentNode;
                 var sha = win.nextSibling;
                 win.style.left = x1 + event.clientX - x0;
                 win.style.top   = y1 + event.clientY - y0;
                 sha.style.left = parseInt(win.style.left) + offx;
                 sha.style.top   = parseInt(win.style.top) + offy;
         }
}
//停止拖动;
function stopDrag(obj)
{
         if(moveable)
         {
                 var win = obj.parentNode;
                 var sha = win.nextSibling;
                 var msg = obj.nextSibling;
                 win.style.borderColor      = normal;
                 obj.style.backgroundColor = normal;
                 msg.style.color            = normal;
                 sha.style.left = obj.parentNode.style.left;
                 sha.style.top   = obj.parentNode.style.top;
                 obj.releaseCapture();
                 moveable = false;
         }
}
//获得焦点;
function getFocus(obj)
{
         if(obj.style.zIndex!=index)
         {
                 index = index + 2;
                 var idx = index;
                 obj.style.zIndex=idx;
                 obj.nextSibling.style.zIndex=idx-1;
         }
}
//最小化;
function min(obj)
{
         var win = obj.parentNode.parentNode;
         var sha = win.nextSibling;
         var tit = obj.parentNode;
         var msg = tit.nextSibling;
         var flg = msg.style.display=="none";
         if(flg)
         {
                 win.style.height   = parseInt(msg.style.height) + parseInt(tit.style.height) + 2*2;
                 sha.style.height   = win.style.height;
                 msg.style.display = "block";
                 obj.innerHTML = "0";
         }
         else
         {
                 win.style.height   = parseInt(tit.style.height) + 2*2;
                 sha.style.height   = win.style.height;
                 obj.innerHTML = "2";
                 msg.style.display = "none";
         }
}
//关闭;
function cls(obj)
{
         var win = obj.parentNode.parentNode;
         var sha = win.nextSibling;
         win.style.visibility = "hidden";
         sha.style.visibility = "hidden";
}
//创建一个对象;
function xWin(id,did,vid,w,h,l,t,tit,msg,msgId,contentId)
{
         index = index+2;
         this.id       = id;
         this.did=did;
         this.vid=vid;
         this.width    = w;
         this.height   = h;
         this.left     = l;
         this.top      = t;
         this.zIndex   = index;
         this.title    = tit;
         this.message = msg;
         this.obj      = null;
         this.bulid    = bulid;
         this.bulid(msgId,contentId);
}
//初始化;
function bulid(msgId,contentId)
{
         var str = ""
                 + "<div id=" + this.id + " "
                 + "style='"
                 + "z-index:" + this.zIndex + ";"
                 + "width:" + this.width + ";"
                 + "left:" + this.left + ";"
                 + "top:" + this.top + ";"
                 + "background-color:" + normal + ";"
                 + "color:" + normal + ";"
                 + "font-size:10px;"
                 + "font-family:Verdana;"
                 + "position:absolute;"
                 + "cursor:default;"
                 + "border:0px solid " + normal + ";"
                 + "min-height:" + this.height + "px;height:auto !important;height:" + this.height + "px;"
                 + "' " 
                 + "onmousedown='getFocus(this)'>"
                         + "<iframe style='position:absolute;width:100%;height:100%;z-index:-1;'></iframe>"
                         + "<div id="+this.did+" "
                         + "style='"
                         + "background-color:" + normal + ";"
                         + "width:" + (this.width) + ";"
                         + "height:20;"
                         + "color:white;"
                         + "border:2px solid " + normal +";border-bottom:0px;"
                         + "' "
                         + "onmousedown='startDrag(this)' "
                         + "onmouseup='stopDrag(this)' "
                         + "onmousemove='drag(this)' "
                         + "ondblclick='min(this.childNodes[1])'"
                         + ">"
                                 + "<span style='width:" + (this.width-2*12-4) + ";padding-left:3px;'>" + this.title + "</span>"
                                 + "<span style='width:12;border-width:0px;color:white;font-family:webdings;' onclick='min(this)'>0</span>"
                                 + "<span style='width:12;border-width:0px;color:white;font-family:webdings;' onclick='cls(this)'>r</span>"
                         + "</div>"
                                 + "<div id="+msgId+" style='"
                                 + "width:100%;"
                                 + "min-height:" + (this.height-20-4)+ "px;height:auto !important;height:" + (this.height-20-4) + "px;"
                                 + "background-color:white;"
                                 + "line-height:14px;"
                                 + "word-break:break-all;"
                                 + "padding:3px;"
                                 + "border-left:2px solid " + normal +";border-right:2px solid " + normal +";"
                                 + "'>" + this.message + "</div>"
                                 + "<div id="+contentId+" style='"
                                 + "width:100%;"
                                 + "background-color:white;"
                                 + "line-height:14px;"
                                 + "word-break:break-all;"
                                 + "padding:3px;"
                                 + "border-left:2px solid " + normal +";border-right:2px solid " + normal +";border-bottom:2px solid " + normal +";"
                                 + "'>" +""+ "</div>"
                 + "</div>"
                 + "<div  id="+this.vid+" "+" style='"
                 + "width:" + this.width + ";"
                 + "min-height:" + this.height + "px;height:auto !important;height:" + this.height + "px;"
                 + "top:" + this.top + ";"
                 + "left:" + this.left + ";"
                 + "z-index:" + (this.zIndex-1) + ";"
                 + "position:absolute;"
                 + "background-color:black;"
                 + "filter:alpha(opacity=40);"
                 + "'><iframe style='filter:alpha(opacity=0);position:absolute;width:100%;height:100%;z-index:-1;'></iframe>by wildwind</div>";
 
 		if(document.all)
        {
            document.body.insertAdjacentHTML('beforeEnd',str);
        }
        else
        {
            document.body.innerHTML+=str;

        }
 
        // document.body.insertAdjacentHTML("beforeEnd",str);
}
function cancel(){
  var div = document.getElementById("Msgcontent");   
  div.parentNode.removeChild(div); //删除
   var div = document.getElementById("vMsgcontent");   
  div.parentNode.removeChild(div); //删除
}
function cancelsend(){
  var div = document.getElementById("editors");   
  div.parentNode.removeChild(div); //删除
   var div = document.getElementById("veditors");   
  div.parentNode.removeChild(div); //删除
}

function done1(){
$('bbmcontent').innerHTML='';
new loadData();
}
function selectEditor(){
var authorIds='';
var authorNames='';
 var ckb=document.getElementById('allEditors').getElementsByTagName("input");
  for(i=0;i<ckb.length;i++)   
  {   
	if(ckb[i].checked){
	authorIds=authorIds+ckb[i].value+";";
	var idAnames=document.getElementById('a'+ckb[i].value).value;
	var index=idAnames.indexOf("|*|");
	var name=idAnames.substring(index+3);
	authorNames=authorNames+name+";";
	}
  }   
  document.getElementById("authorNames").value=authorNames;
  document.getElementById("authorIds").value=authorIds;
  document.getElementById('editors').style.display="none";
  document.getElementById('veditors').style.display="none";
  document.getElementById('deditors').style.display="none";
  document.getElementById('allEditors').style.display="none";
  document.getElementById('editorContent').style.display="none";
  var div = document.getElementById("deditors");   
  div.parentNode.removeChild(div); //删除
   var div = document.getElementById("veditors");   
  div.parentNode.removeChild(div); //删除
}
function check1(id){
    $('bbm').value=false;
    if($('viewbbm').checked)$('bbm').value=true;
    new bbmHandler(id);
}
function saveAuthor(aid,aname){
 if($('c'+aid).checked){
    document.getElementById('a'+aid).value=aid+'|*|'+aname;
 }else{
  document.getElementById('a'+aid).value='';
 }
}
function selectAllEditor(){
var authorIds='';
var authorNames='';
  var sendbbm = document.getElementsByName('names');
  var n = sendbbm.length;
  if(n>0){
     var arrayObj;
	 for(var i=0; i<n; i++){
		arrayObj=sendbbm[i];
		arrayObj.checked=true;
	 }
  }
}
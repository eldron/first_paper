
function flowDetail(detailClassName){
  var eles = document.getElementsByClassName(detailClassName);
  for(var i=0;i<eles.length;i++){
    Element.toggle(eles[i]);
  }
}

function allFlowDetail(){
  var eles = document.getElementsByClassName('flowdetail');
  for(var i=0;i<eles.length;i++){
    Element.toggle(eles[i]);
  }
}

function popupDialog(url,width,height,scrollbars,Resizable){ 
    //showx = event.screenX - event.offsetX - 4 - 10 ; // + deltaX;  这段代码只对IE有效，已经不用了 
    //showy = event.screenY - event.offsetY -168; // + deltaY; 这段代码只对IE有效，已经不用了 
     
        var isMSIE= (navigator.appName == "Microsoft Internet Explorer");  //判断浏览器 

        if (isMSIE) {           
            retval = window.showModalDialog(url, window, "dialogWidth:"+width+"px; dialogHeight:"+height+"px; dialogLeft:"+x+"px; dialogTop:"+y+"px; status:no; directories:yes;scrollbars:" + scrollbars + ";Resizable:yes;" ); 
       } else { 
    } 
} 

function doReviewFlow(manuId,nextPhaseId,nextPhaseHandlerType){
  if(document.all){  //IE
    if (nextPhaseHandlerType==0){
	var url1=GlobalVar.contextPath+'/manuscript/ManuFlowSubmit!dispose.action';
	var pars1='ajaxType=object&ajaxData=notAuthority|isNotAuthority();h1|getH1();&manuId='+manuId+'&phaseId='+nextPhaseId;

    var myAjax = new Ajax.Executor(
       url1,
       {method: 'post', parameters: pars1,displayLoading:true,onComplete:function(){
         var notAuthority=Ajax.Executor.ReturnObject['notAuthority'];
         if(Ajax.Executor.ReturnObject['h1']!=null&&Ajax.Executor.ReturnObject['h1']!=""){
         	var h1=Ajax.Executor.ReturnObject['h1'];
         }
         if(notAuthority==true){
         	alert(h1);
         	return;
         }else{
			var url = GlobalVar.contextPath+'/manuscript/ManuFlowSubmit.action';
			var pars = 'manuId='+manuId+'&phaseId='+nextPhaseId;
			pars+='&handlerType='+nextPhaseHandlerType;
			showPopWin(url+'?'+pars, 710, 570, null,true,true);
         }
       } 
      });
      /*parameterStr="resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:800px; dialogHeight:600px; center:yes;status:no;";

	 var dialogAnswer = window.showModalDialog(url+'?'+pars, "",parameterStr);
	    if(dialogAnswer.select=='OK'){
	      window.location.reload();
	    }*/
	    //showPopWin(url+'?'+pars, 710, 570, null,true,true);
    }else if(nextPhaseHandlerType==4){
      /*parameterStr="resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:800px; dialogHeight:660px; center:yes;status:no;";

	 var dialogAnswer = window.showModalDialog(url+'?'+pars, "",parameterStr);
	    if(dialogAnswer.select=='OK'){
	      window.location.reload();
	  }*/
	  var url=GlobalVar.contextPath+'/manuscript/ManuFlowSubmit!dispose.action';
	var pars='manuId='+manuId+'&phaseId='+nextPhaseId;
	pars+='&ajaxType=object&ajaxData=notAuthority|isNotAuthority();h1|getH1();';  
    var myAjax = new Ajax.Executor(
       url,
       {method: 'post', parameters: pars,displayLoading:true,onComplete:function(){
         var notAuthority=Ajax.Executor.ReturnObject['notAuthority'];
         if(Ajax.Executor.ReturnObject['h1']!=null&&Ajax.Executor.ReturnObject['h1']!=""){
         	var h1=Ajax.Executor.ReturnObject['h1'];
         }
         if(notAuthority==true){
         	alert(h1);
         	return;
         }else{
			var url = GlobalVar.contextPath+'/manuscript/ManuFlowSubmit.action';
			var pars = 'manuId='+manuId+'&phaseId='+nextPhaseId;
			pars+='&handlerType='+nextPhaseHandlerType;
			showPopWin(url+'?'+pars, 710, 580, null,true,true);
         }
       } 
      });
    }else{
    	var url = GlobalVar.contextPath+'/manuscript/ManuFlowSubmit.action';
			var pars = 'manuId='+manuId+'&phaseId='+nextPhaseId;
			pars+='&handlerType='+nextPhaseHandlerType;
      window.location=url+'?'+pars;
    }
   }else{
   if (nextPhaseHandlerType==0){
  var url=GlobalVar.contextPath+'/manuscript/ManuFlowSubmit!dispose.action';
	var pars='manuId='+manuId+'&phaseId='+nextPhaseId;
	pars+='&ajaxType=object&ajaxData=notAuthority|isNotAuthority();h1|getH1();';  
    var myAjax = new Ajax.Executor(
       url,
       {method: 'post', parameters: pars,displayLoading:true,onComplete:function(){
         var notAuthority=Ajax.Executor.ReturnObject['notAuthority'];
         if(Ajax.Executor.ReturnObject['h1']!=null&&Ajax.Executor.ReturnObject['h1']!=""){
         	var h1=Ajax.Executor.ReturnObject['h1'];
         }
         if(notAuthority==true){
         	alert(h1);
         	return;
         }else{
			var url = GlobalVar.contextPath+'/manuscript/ManuFlowSubmit.action';
			var pars = 'manuId='+manuId+'&phaseId='+nextPhaseId;
			pars+='&handlerType='+nextPhaseHandlerType;
			showPopWin(url+'?'+pars, 710, 570, null,true,true);
         }
       } 
      });
    }else if (nextPhaseHandlerType==4){
    	var url = GlobalVar.contextPath+'/manuscript/ManuFlowSubmit.action';
			var pars = 'manuId='+manuId+'&phaseId='+nextPhaseId;
			pars+='&handlerType='+nextPhaseHandlerType;
     showPopWin(url+'?'+pars, 710, 580, null,true,true);
    }else{
    	var url = GlobalVar.contextPath+'/manuscript/ManuFlowSubmit.action';
			var pars = 'manuId='+manuId+'&phaseId='+nextPhaseId;
			pars+='&handlerType='+nextPhaseHandlerType;
      window.location=url+'?'+pars;
      return;
    }
    var url = GlobalVar.contextPath+'/manuscript/ManuFlowSubmit.action';
			var pars = 'manuId='+manuId+'&phaseId='+nextPhaseId;
			pars+='&handlerType='+nextPhaseHandlerType;
    var x = parseInt(screen.width / 2.0) - (width / 2.0);  
    var y = parseInt(screen.height / 2.0) - (height / 2.0);
//	netscape.security.PrivilegeManager.enablePrivilege('UniversalBrowserWrite');

    var dialogAnswer = window.open(url+'?'+pars, "mcePopup", "top=" + y + ",left=" + x + ",width=" + width + ",height=" + height + ",dialog=yes,modal=yes,Resizable=yes,status=no,scrollbars=yes" ); 
    eval('try { win.resizeTo(width, height); } catch(e) { }'); 
    dialogAnswer.focus();
   
   }
  
  
/**
   window.open(url+'?'+pars);
**/
}

function doWithdraw(manuId,phaseNumber,notwithdraw){
  if(phaseNumber!=1000){
  var url = GlobalVar.contextPath+'/manuscript/ManuFlowWithdraw.action';
  var pars = 'manuId='+manuId+'&phaseNumber='+phaseNumber;
  if(document.all){   //IE
	  var dialogAnswer = window.showModalDialog(url+'?'+pars, "","resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:250px; dialogHeight:350px; center:yes;status:no;");
	//   window.open(url+'?'+pars);
	  if(dialogAnswer.select=='OK'){
	    window.location.reload();
	  }
  }else{
    var width=250;
    var height=350;

    var x = parseInt(screen.width / 2.0) - (width / 2.0);  
    var y = parseInt(screen.height / 2.0) - (height / 2.0);
//	netscape.security.PrivilegeManager.enablePrivilege('UniversalBrowserWrite');

    var dialogAnswer = window.open(url+'?'+pars, "mcePopup", "top=" + y + ",left=" + x + ",width=" + width + ",height=" + height + ",dialog=yes,modal=yes,Resizable=yes,status=no,scrollbars=yes" ); 
    eval('try { win.resizeTo(width, height); } catch(e) { }'); 
    dialogAnswer.focus();
  }
  }else{
    alert(notwithdraw);
  }
}

function doDistribute(manuId){
  var url = GlobalVar.contextPath+'/manuscript/DistributeManuscript.action';
  var pars = 'manuId='+manuId;
  var dialogAnswer = window.showModalDialog(url+'?'+pars, "","resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:900px; dialogHeight:480px; center:yes;status:no;");
 //  window.open(url+'?'+pars);
  if(dialogAnswer.select=='OK' || dialogAnswer.select == 'CANCEL' || dialogAnswer.url=='reload'){
    window.location.reload();
  }
}

function manuscriptTransfer(manuId,trId){
  var previewShow='false';
  var mailShow='fasle';
  var url = GlobalVar.contextPath+'/manuscript/manuscriptTransfer.action';
  var pars = 'manuId='+manuId+'&trId='+trId;
  pars = pars+'&previewShow='+previewShow;
  pars = pars+'&mailShow='+mailShow;
  var dialogAnswer = window.showModalDialog(url+'?'+pars, "","resizable=yes;toolbar=yes;menubar;location=yes;  scroll=no; scrollbars=yes;dialogWidth:400px; dialogHeight:250px; center:yes;status:no;");
 //  window.open(url+'?'+pars);
  if(dialogAnswer.select=='OK'){
    mailShow=dialogAnswer.mailShow;
    previewShow=dialogAnswer.previewShow;
    if(mailShow && previewShow){
    	var url = GlobalVar.contextPath+'/manuscript/manuscriptTransfer!previewSh.action';
    	var pars = 'manuId='+manuId;
    	var dialogAnswer1 = window.showModalDialog(url+'?'+pars, "","resizable=yes;toolbar=yes;menubar;location=yes;  scroll=no; scrollbars=yes;dialogWidth:700px; dialogHeight:700px; center:yes;status:no;");
    	if(dialogAnswer1.select=='OK'){
    		window.location.reload();
    	}
    	}else if(mailShow && !previewShow){
    		var url = GlobalVar.contextPath+'/manuscript/manuscriptTransfer!sendmail.action?manuId='+manuId;
    		window.location.href=url;
    		window.location.reload();
    	}else{
    		window.location.reload();
    	}
  }
}


function editReviewFlow(id){
var url = GlobalVar.contextPath+'/manuscript/ManuFlow.action';
var iTop = (window.screen.availHeight-30-740)/2; //获得窗口的垂直位置;
var iLeft = (window.screen.availWidth-10-1020)/2; //获得窗口的水平位置;
//alert('11');
var pars = 'id='+id;
var dialogAnswer = window.open(url+'?'+pars,"dialogAnswer","height=740,width=1020,status=yes,toolbar=no,menubar=no,location=no,scrollbars = yes,resizable=yes,top="+iTop+",left="+iLeft);
//用showModalDialog打的子窗体页面上如果有下载连接的时候发送的请求有毛病，具体说不清楚，所以改为open
//window.open(url+'?'+pars);

  //if(dialogAnswer.select=='OK'){
   // window.dialogArguments.location.reload();
  //}
}

function updateManuscriptDetail(id){
  var url = GlobalVar.contextPath+'/manuscript/ManuscriptView.action';
  var pars = 'ajax=true&id='+id;
  var myAjax = new Ajax.Updater('right_div', url, {method: 'post', parameters: pars});
}


function manuflow_edit(){
	var url = GlobalVar.contextPath+'/manuscript/ManuFlowSave.action';
    	var pars = '';
    	pars = pars + 'flowId='+$('manuflow.id').value;
    	pars = pars + '&ajaxType=object&ajaxFunc=manuflow_response_handler&ajaxData=hasActionErrors|hasActionErrors();hasFieldErrors|hasFieldErrors();actionErrors|actionErrors;fieldErrors|fieldErrors;';
    	pars = pars + '&'+Form.serialize($('manuflow'));
    	var myAjax = new Ajax.Executor(url,{method: 'post', parameters: pars,displayLoading:true});
}

function manuflow_response_handler(data){
    if(data['hasActionErrors']==true || data['hasFieldErrors']==true ){
        var errors = data['actionErrors'];
        var errorsDiv = $('manuflow_formerrors');
        var ul = document.createElement('ul');
        errorsDiv.appendChild(ul);

        if(errors.length>0){
    	  for (var prop in errors) {
    	    var li = document.createElement('li');
    	    li.appendChild(document.createTextNode(errors[prop]));
    	    ul.appendChild(li);
		  }
		}
		errors = data['fieldErrors'];
    	for (var prop in errors) {
    	  var errorsArray = errors[prop];
    	  for (var idx in errorsArray) {
    	    var li = document.createElement('li');
    	    li.appendChild(document.createTextNode(errorsArray[idx]));
    	    ul.appendChild(li);
    	  }
		}
    }else{
      window.location.reload();
    }
  }

function openFile(url){
   window.open(url,'');
}

function deleteContentFile(deleteconfig,fileId){
    if(confirm(deleteconfig)){
		var url = GlobalVar.contextPath+'/manuscript/ManuscriptContentFileDelete.action';
		var pars = 'ajaxType=object&ajaxData=hasActionErrors|hasActionErrors();&id='+fileId;
		var myAjax = new Ajax.Executor(
		    url,
		    {method: 'post', parameters: pars,displayLoading:true,onComplete:function(){deleteFileResponseHandler();}});
	}
}

function deleteFileResponseHandler(){
  
	  if(Ajax.Executor.ReturnObject['hasActionErrors']==true){
	  }else{
	    window.location.reload();
	  }
 
}

function paperMailAndPrint(manuId){
   var url = GlobalVar.contextPath+'/manuscript/PaperMailAndPrint.action?manuId='+manuId;
//   paper_main = window.open(url,'paperMain','resizable=yes,height=50,width=500,left=10,top=0');
   paper_main = window.open(url,'paperMain','resizable=yes,menubar,scrollbars=yes,status=yes,height=700,width=1000,left=10,top=10');

   paper_main.manuId = manuId;
//   paper_detail = window.open('','paperDetail','resizable=yes,menubar,height=500,width=800,left=10,top=130');
}

function printRreviewPaper(flowId){
	var url = GlobalVar.contextPath+'/manuscript/ManuFlowOperate!printRreviewPaper.action';
	var pars = 'flowId='+flowId;
//   window.open(url+'?'+pars);	
	var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    	"resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:1200px; dialogHeight:900px; center:yes;status:no;");
}

function viewCurrFlowOpinion(flowId){
	var url = GlobalVar.contextPath+'/manuscript/ManuFlowOperate!viewCurrFlowOpinion.action';
	var pars = 'flowId='+flowId;
	var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    	"resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:1200px; dialogHeight:900px; center:yes;status:no;");
}

function viewCurrFlowOpinionToAuthorOrigin(flowId){
	var url = GlobalVar.contextPath+'/manuscript/ManuFlowOperate!viewCurrFlowOpinionToAuthorOrigin.action';
	var pars = 'flowId='+flowId;
	var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    	"resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:1200px; dialogHeight:900px; center:yes;status:no;");
}

function handSendUrgeMail(flowId){
	var url = GlobalVar.contextPath+'/manuscript/ManuFlowOperate!handSendUrgeMail.action';
	var pars = 'flowId='+flowId;
//   window.open(url+'?'+pars);		
	var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    	"resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:1200px; dialogHeight:900px; center:yes;status:no;");
}

function handSendMailToAuthor(Id){
	var url = GlobalVar.contextPath+'/manuscript/ManuFlowOperate!handSendMailToAuthor.action';
	var pars = 'Id='+Id;
	var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    	"resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:1200px; dialogHeight:900px; center:yes;status:no;");
}
// 2008-08-11 anjunchao add send mail to manuscript authors
function handSendMailToManuscriptAuthor(Id,manuId){
	var url = GlobalVar.contextPath+'/manuscript/ManuFlowOperate!handSendMailToManuscriptAuthor.action';
	var pars = 'AuthorId='+Id;
	pars =pars+'&manuId='+manuId;
	 window.open(url+'?'+pars);
}

function handSendUrgeSMS(flowId){
    var url = GlobalVar.contextPath+'/manuscript/ManuFlowOperate!handSendUrgeSMS.action';
    var pars = 'flowId='+flowId;
    var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    	"resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:450px; dialogHeight:350px; center:yes;status:no;");
}

function sendThankMail(flowId){
	var url = GlobalVar.contextPath+'/manuscript/ManuFlowOperate!sendThankMail.action';
	var pars = 'flowId='+flowId;
	var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    	"resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:1200px; dialogHeight:900px; center:yes;status:no;");
}

function viewHandlerReviewHistory(flowId){
	var url = GlobalVar.contextPath+'/manuscript/ManuFlowOperate!viewHandlerReviewHistory.action';
	var pars = 'flowId='+flowId;
	var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    	"resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:1200px; dialogHeight:900px; center:yes;status:no;");
}

function printFlowAllOpinion(flowId){
	var url = GlobalVar.contextPath+'/manuscript/ManuFlowOperate!printFlowAllOpinion.action';
	var pars = 'flowId='+flowId;
	var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    	"resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:1200px; dialogHeight:900px; center:yes;status:no;");
}

function overContentByFlowcontent(flowId,overconfirm,empty){
  //if(confirm(overconfirm)){
  if(empty!='1'){
  alert(empty);
  return false;
  }
    var wid;
	var pid
	if(document.getElementById("oid")!=null && document.getElementById("oid").value!=null){
	  	 wid=document.getElementById("oid").value;
	  }
	if(document.getElementById("pid")!=null && document.getElementById("pid").value!=null){
	  	 pid=document.getElementById("pid").value;
	  }
	var url = GlobalVar.contextPath+'/manuscript/ManuFlowOperate!overContentByFlowcontent.action';
	var pars = 'flowId='+flowId +'&wid='+wid+'&pid='+pid;
	var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    	"resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogWidth:400px; dialogHeight:150px; center:yes;status:no;");
    if(dialogAnswer.select=='OK'){
  	   window.location.reload();
    }	
  //}
}


function deleteAccessoryFile(deleteconfig,fileId){
    if(confirm(deleteconfig)){
		var url = GlobalVar.contextPath+'/manuscript/FlowAccessoryFile!delete.action';
		var pars = 'ajaxType=object&ajaxData=hasActionErrors|hasActionErrors();&id='+fileId;
		var myAjax = new Ajax.Executor(
		    url,
		    {method: 'post', parameters: pars,displayLoading:true,onComplete:function(){deleteFileResponseHandler();}});
	}
}
function deleteAuthorAccessoryFile(deleteconfig,fileId){
	if(confirm(deleteconfig)){
		var url = GlobalVar.contextPath+'/manuscript/FlowAuthorAccessoryFile!delete.action';
		var pars = 'ajaxType=object&ajaxData=hasActionErrors|hasActionErrors();&id='+fileId;
		var myAjax = new Ajax.Executor(
		    url,
		    {method: 'post', parameters: pars,displayLoading:true,onComplete:function(){deleteFileResponseHandler();}});
	}
}

function sendMessage(manuid,personId,st,rt){
  var url = GlobalVar.contextPath+'/message/Message!tp.action';
  var pars = 'manuscriptId='+manuid+'&personId='+personId+'&st='+st+'&rt='+rt;
  var wid=(screen.availWidth-150)+"px";
  var hei=(screen.availHeight/2)+"px";
  var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    "resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogLeft:100px;dialogTop:100px;dialogWidth:"+wid+"; dialogHeight:"+hei+"; center:yes;status:no;");
   //window.open(url+'?'+pars);
  if(dialogAnswer.select=='OK'){
  	window.location.reload();
  }
}
function addManuCost(manuId){
  var url = GlobalVar.contextPath+'/cost/ManuFee!add.action';
  var pars = 'manuId='+manuId;
  var wid=(screen.availWidth-150)+"px";
  var hei=(screen.availHeight-150)+"px";
  var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    "resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogLeft:100px;dialogTop:100px;dialogWidth:"+wid+"; dialogHeight:"+hei+"; center:yes;status:no;");
   //window.open(url+'?'+pars);
  if(dialogAnswer.select=='OK'){
//    window.location.reload();
	updateManuFeeDiv();
  }
}
function deleteManuCost(deleteconfig,id,manuId){
  if(confirm(deleteconfig)){
	var url = GlobalVar.contextPath+'/cost/ManuFee!delete.action';
	var pars = 'id='+id+'&manuId='+manuId;

  var wid="1px";
  var hei="1px";
  var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    "resizable=no;toolbar=no;menubar;location=no;scrollbars=no;dialogLeft:1px;dialogTop:1px;dialogWidth:"+wid+"; dialogHeight:"+hei+"; center:no;status:no;");

  if(dialogAnswer.select=='OK'){
	  updateManuFeeDiv();
  }

return;
      var myAjax = new Ajax.Updater(
      'tab_fee_page',
      url,
      {method: 'post', parameters: pars,displayLoading:true});
return;

	var myAjax = new Ajax.Executor(
    	url,
    	{method: 'post', parameters: pars,displayLoading:true});
	window.location.reload();
  }
}

function editManuCost(id){
  var url = GlobalVar.contextPath+'/cost/ManuFee.action';
  var pars = 'id='+id;
  var wid=(screen.availWidth-250)+"px";
  var hei=(screen.availHeight-200)+"px";
  var dialogAnswer = window.showModalDialog(url+'?'+pars, "",
    "resizable=yes;toolbar=yes;menubar;location=yes;scrollbars=yes;dialogLeft:100px;dialogTop:100px;dialogWidth:"+wid+"; dialogHeight:"+hei+"; center:yes;status:no;");
   //window.open(url+'?'+pars);
  if(dialogAnswer.select=='OK'){
//  	window.location.reload();
	updateManuFeeDiv();
  }
}

function doFee(costType,manuId){
  var url = GlobalVar.contextPath+'/manuscript/ManuCost.action';
  var pars = 'ajaxType=html&manuId='+manuId+'&costType='+costType;
  var sUrl = url +'?'+ pars;
  var handleSuccess = function(o){
	if(o.responseText !== undefined){
                YAHOO.journal.manuscript.dlg.setBody(o.responseText);
                YAHOO.journal.manuscript.dlg.render();
                YAHOO.journal.manuscript.dlg.show();
	}
  }

  var handleFailure = function(o){
	if(o.responseText !== undefined){
	}
  }

  var callback =
  {
    success:handleSuccess,
    failure:handleFailure,
    argument: { foo:"foo", bar:"bar" }
  };
  var request = YAHOO.util.Connect.asyncRequest('GET', sUrl, callback);
}

function cancelFee(){
  Element.show('fee_list');
  Element.hide('fee_content');
}

function postFee(){
    var url = GlobalVar.contextPath+'/manuscript/ManuCost.action';
    var pars = Form.serialize($('manu_cost'));
    pars = pars
    + '&ajaxType=object&ajaxData=hasActionErrors|hasActionErrors();hasFieldErrors|hasFieldErrors();actionErrors|actionErrors;fieldErrors|fieldErrors;';
    var myAjax = new Ajax.Executor(
    url,
    {method: 'post', parameters: pars,displayLoading:true,onComplete:function(){postFeeResponseHandler();}});
}

function postFeeResponseHandler(){
    if(Ajax.Executor.ReturnObject['hasActionErrors']==true || Ajax.Executor.ReturnObject['hasFieldErrors']==true ){
        var errors = Ajax.Executor.ReturnObject['actionErrors'];
        errors = Ajax.Executor.ReturnObject['fieldErrors'];
    }else{
      cancelFee();
    }
}

YAHOO.namespace("journal.manuscript");

function init() {
  function submitCallback(obj) {
		var response = obj.responseText;
		eval(response);
  }

  var handleCancel = function() {
    this.cancel();
  }
  var handleSubmit = function() {
    this.submit();
  }

  YAHOO.journal.manuscript.dlg = new YAHOO.widget.Dialog("dlg", { modal:true, visible:false, width:"450px", fixedcenter:true, constraintoviewport:true, draggable:true});

  var listeners = new YAHOO.util.KeyListener(document, { keys : 27 }, {fn:handleCancel,scope:YAHOO.journal.manuscript.dlg,correctScope:true} );
  YAHOO.journal.manuscript.dlg.cfg.queueProperty("keylisteners", listeners);
  YAHOO.journal.manuscript.dlg.cfg.queueProperty("buttons", [ { text:"Submit", handler:handleSubmit, isDefault:true },
                                                        { text:"Cancel", handler:handleCancel } ]);
  YAHOO.journal.manuscript.dlg.cfg.queueProperty("onsuccess", submitCallback);
}
YAHOO.util.Event.addListener(window, "load", init);



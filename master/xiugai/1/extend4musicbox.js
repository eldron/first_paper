WebmailHelper.goMusicBox = function(sUrl){
	sUrl = sUrl || 'http://music.163.com/musicbox?ref=mail#http://t.mail.163.com/proxy.htm';
	WebmailHelper.evalScript("$I('util.CustomAppManager').startApp({url: '"+ sUrl +"',name: 'music_outlink',appId: 38000})");
};

WebmailHelper.setMusicBox = function(oParam){
	var h = (oParam.height || 20) + "px";
	var w = (oParam.width || 20) + "px";
	WebmailHelper.evalScript("document.getElementById('ifrmMusic').style.height = '"+ h +"';");
	WebmailHelper.evalScript("document.getElementById('ifrmMusic').style.width = '"+ w +"';");
};
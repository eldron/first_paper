(function(){
    if(!window.gAd){
        window.gAd = {};
    }
    var blank = {
        type: 0
    };
    window.gAd.biz = {
        welBanner : fAdWelBanner,
        composeBanner : fAdComposeBanner,
        readFlash : fAdReadFlash,
        close : fAdClose,
        compose: fCompose,
        letter: fLetter,
        composeTips: fComposeTips,
        logout: fLogout
    };

    // 写信成功左下角大图背景广告 620x330
    function fCompose(){
        var o = [];
        o[0] = blank;
		o[1] = '<a style="display:inline-block" href="http://g.163.com/a?CID=35584&Values=167292814&Redirect=http://c.admaster.com.cn/c/a55544,b607044,c369,i0,m101,h" target="_blank"><img src="http://img1.126.net/channel5/019989/620330_150724.jpg" width="620" height="330" alt=""></a>';
		o[2] = '<a style="display:inline-block" href="http://g.163.com/a?CID=36710&Values=548197325&Redirect=http://c.admaster.com.cn/c/a57784,b673428,c369,i0,m101,h" target="_blank"><img src="http://img1.126.net/channel5/020089/620330_150728.jpg" width="620" height="330" alt=""></a>';
		return o;
    }

    // 假信（霸王邮）
    function fLetter(){
        var o = [];
        o[0] = blank;
		//o[1] = '<div style="background-color: #f7f7f7;padding: 0 25px 0 12px;overflow-y: hidden;height: 32px;line-height: 32px;border: 1px solid #f1f1f1;font-size: 12px;position: relative;color: #999;"><span style="float: right;">[<a href="http://g.163.com/a?CID=35439&Values=1208127263&Redirect=http://www.ef.com.cn/online/lp/cn/2014yr/ee/130929_lp_gud.aspx?ctr=cn&lng=cs&ptn=nete&etag=E128196" class="gIbx-ext-txtLink" style="color:#999;" target="_blank">英孚教育</a>]</span><a href="http://g.163.com/a?CID=35439&Values=1208127263&Redirect=http://www.ef.com.cn/online/lp/cn/2014yr/ee/130929_lp_gud.aspx?ctr=cn&lng=cs&ptn=nete&etag=E128196" class="gIbx-ext-txtLink" target="_blank">跳槽后，英语不够用？订阅每日英语，提高词汇量和听力>></a><div style="position: absolute;right: 0;top: 0;width: 25px;height: 22px;overflow: hidden;padding-top: 5px;"><a href="javascript:void(0)" style="color: #bfbfbf;margin-left: 1px;float: left;width: 16px;height: 16px;overflow: hidden;display: inline-block;+display: inline;+zoom:1;vertical-align: middle;" hidefocus="hidefocus" onclick="gAd.util.closeInbox(this);" title="关闭"><b class="nui-ico nui-ico-close" style="margin-top: 5px;margin-left: 5px;vertical-align: top;"></b></a></div></div>';
        return o;
    }

    // 写信成功小黄条
    function fComposeTips(){
        var o = [];
        o[0] = blank;
		o[1] = '<div style="padding:4px 12px;margin:12px 0;color:#CE0000" class="nui-assistBlock nui-block nui-txt-s18 nui-txt-bold"><a href="http://g.163.com/a?CID=35803&Values=1486835370&Redirect=http://mobile.163.com/special/p8max/" target="_blank" style="color:#D90000">激发创意梦想，华为P8max全球震撼首发</a></div>';
		o[2] = blank;
		o[3] = blank;		
		return o;
    }

	// 退出页 巨幅广告995x350
    function fLogout(){
        var o = [];
		o[0] = blank;	  
        //o[1] = '<div style="width:995px;height:350px;margin: 0 auto;"><a href="http://g.163.com/a?CID=36164&Values=2282087229&Redirect=http://mlt01.com/c.htm?pv=1&sp=0,1246354,1269959,65356,0,1,1&target=http://www.archfans.com/" target="_blank"><img src="http://img1.126.net/channel5/020285/995350_150724.jpg"></a></div>';
		return o;
    }


    // 欢迎页右侧banner 190x360
    function fAdWelBanner(){
        var o = [];        
		o[0] = blank;
		o[1] = blank;
		o[2] = blank;
		o[3] = '<embed src="http://img1.126.net/channel5/020439/190360_150731.swf" quality="high" pluginspage="http://www.macromedia.com/shockwave/download/index.cgi?P1_Prod_Version=ShockwaveFlash  type=application/x-shockwave-flash" width="190px" height="360px" wmode="opaque"></embed>';
		return o;
    }

    // 写信成功右下角 260x330
    function fAdComposeBanner(){
        var o = [];
         o[0] = '<iframe src="http://g.163.com/r?site=netease&affiliate=freemail163&cat=sendmsg&type=pip260x330&location=1" width="260" height="330" frameborder="no" border="0" marginwidth="0" marginheight="0" scrolling="no"></iframe>';
		return o;
    }

    // 读信右上角flash 135x98
    function fAdReadFlash(){
        var o = [];
        o[0] = blank;
		//o[2] = 'http://img1.126.net/channel5/017931/13598_140929.swf';
        return o;
    }

    // 浏览器关闭弹框 720x300
    function fAdClose(){
        var o = [];
        o[0] = blank;
		
		//o[2] = 'http://img1.126.net/channel12/mail/yitou163.htm';
		return o;
    }

})();

// END 201507310956
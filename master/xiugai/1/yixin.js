!function(a){function b(a){function b(a){try{var b=JSON.parse(a.responseText),c=b.info;if(c)for(var f=0,g=c.length;g>f;f++){var h=c[f];d?i[h.key]=h:i[h]=!0}e()}catch(j){}}var c=a.keys,d=!!a.detail,e=a.callback;f.isArray(c)||(c=[c]);for(var i=h.infos,j=[],k=[],l={},m=!1,n=0,o=c.length;o>n;n++){var p=c[n].toLowerCase(),q=h.parse(p),r=q.mobile,s=q.email,t=q.name,u=q.netease,v=i[t],w=!v&&v!==!1,x=d&&v===!0;(w||x)&&((r||u)&&(m=!0,l[t]||(r?k.push(r):j.push(s),l[t]=!0)),w&&(i[p]=!1))}m?g.request({method:g.POST,url:"/yixinproxy/"+(d?"yxDetail":"queryYx")+".do?uid="+$S("orgUid")+"&sid="+$S("sid"),body:{uids:JSON.stringify(j),mobiles:JSON.stringify(k)},call:b}):e()}function c(a){var b=h.infos;a=a.toLowerCase();var c=h.parse(a);return b[c.name]}function d(a,b){var c=h.infos;a=a.toLowerCase();var d=h.parse(a);b||(b={}),c[d.name]=b}function e(a){var b=h.types,c=b[a];if(!c){c=b[a]={};var d=a.split("@");if(1===d.length)c.mobile=a;else{c.email=a;var e=d[0];/^1[345678]\d{9}$/i.test(e)&&(c.mobile=e);for(var f=d[1],g=["163.com","126.com","yeah.net","vip.163.com","vip.126.com","vip.188.com","188.com"],i=0,j=g.length;j>i;i++)if(g[i]===f){c.netease=!0;break}}c.name=c.mobile?c.mobile:c.email}return c}var f=a.Object,g=a.Ajax,h=a.createClass($N("product.Yixin"));f.extend(h,{publicAccount:{league:{},corp:{}},infos:{},types:{},request:b,get:c,set:d,parse:e})}($,window);
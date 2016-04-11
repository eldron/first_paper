(function() {
	Object.BREAK = "break";
	Object.CONTINUE = "continue";
	Object.CLASSERROR = "not found class";
	Object.EMPTYFUNC = function() {};
	Object.createClass = x;
	Object.getClass = t;
	Object.extend = u;
	Object.mix = p;
	Object.inherit = A;
	Object.isFunction = F;
	Object.isArray = z;
	Object.compare = s;
	Object.clone = v;
	Object.isEmpty = C;
	Object.each = w;
	Object.count = y;
	Object.has = q;
	Object.toArray = D;
	Object.emptyFunction = r;
	function x(e, a, j) {
		var b = function() {
			if (this.initialize) {
				var m;
				return this.initialize.apply(this, arguments)
			}
		};
		if (arguments.length > 0) {
			var f = a ? (e + "." + a) : e;
			var c = window;
			var d = f.split(".");
			for (var g = 0,
			k = d.length; g < k; g++) {
				var h = d[g];
				if (g == k - 1) {
					c[h] = b
				} else {
					switch (typeof c[h]) {
					case "undefined":
						c[h] = {};
						break;
					case "number":
					case "string":
					case "boolean":
						c[h] = new c[h].constructor(c[h]);
						break;
					case "object":
					case "function":
						break;
					default:
					}
					c = c[h]
				}
			}
		}
		return b
	}
	function t(e, a) {
		try {
			var b;
			var f = a ? (e + "." + a) : e;
			var d = f.split(".");
			var c = window;
			for (var g = 0,
			k = d.length; g < k; g++) {
				var h = d[g];
				if (g == k - 1) {
					b = c[h]
				} else {
					c = c[h]
				}
			}
			if (!b) {
				throw Object.CLASSERROR
			}
			return b
		} catch(j) {
			throw Object.CLASSERROR
		}
	}
	function u(a, e, d) {
		for (var c in e) {
			if (c == "prototype") {
				continue
			}
			try {
				if (!d || !this.has(a, c)) {
					a[c] = e[c]
				}
			} catch(b) {}
		}
		try {
			if (e.toString != e.constructor.prototype.toString) {
				if (!d) {
					a.toString = e.toString
				}
			}
		} catch(b) {}
		return a
	}
	function p(a, f, d, b, e) {
		if (!a.superClass) {
			a.superClass = {}
		}
		for (var c in f) {
			if (Object.isFunction(f[c])) {
				if (!a.superClass[c]) {
					a.superClass[c] = f[c]
				} else {
					var g = a.superClass[c];
					a.superClass[c] = function() {
						var h = [].shift.call(arguments);
						g.apply(a, arguments);
						f[h].apply(a, arguments)
					}.bind(a, c)
				}
			} else {
				a.superClass[c] = f[c]
			}
			if (!a[c]) {
				a[c] = f[c]
			}
		}
		if (d) {
			Object.extend(a, d)
		}
		if (f.toString != f.constructor.prototype.toString) {
			a.superClass.toString = function() {
				f.toString.apply(a, arguments)
			}
		}
		if (b && a.prototype && f.prototype) {
			this.inherit(a, f, e || {})
		}
		return a
	}
	function A(b, e, d) {
		var a = function() {};
		a.prototype = e.prototype;
		b.prototype = new a();
		b.prototype.constructor = b;
		b.superConstructor = e;
		b.superClass = e.prototype;
		if (e._onInherit) {
			try {
				e._onInherit(b)
			} catch(c) {}
		}
		if (d) {
			Object.extend(b.prototype, d)
		}
	}
	function F(a) {
		return this.prototype.toString.call(a) === "[object Function]"
	}
	function z(a) {
		return this.prototype.toString.call(a) === "[object Array]"
	}
	function s(a, c) {
		if (typeof(a) == typeof(c)) {
			if (typeof(a) != "object") {
				return a === c
			} else {
				if (a === c) {
					return true
				} else {
					if (this.isArray(a) && this.isArray(c)) {
						if (a.length != c.length) {
							return false
						}
						for (var d = 0,
						e = a.length; d < e; d++) {
							if (!this.compare(a[d], c[d])) {
								return false
							}
						}
						return true
					} else {
						if (!this.isArray(a) && !this.isArray(c)) {
							for (var b in a) {
								if (c[b] == undefined) {
									return false
								}
								if (!this.compare(a[b], c[b])) {
									return false
								}
							}
							return true
						} else {
							return false
						}
					}
				}
			}
		} else {
			return false
		}
	}
	function v(d) {
		if (d == null || typeof(d) != "object") {
			return d
		} else {
			if (d.constructor != Object && d.constructor != Array) {
				return d
			} else {
				if (d.constructor == Date || d.constructor == RegExp || d.constructor == Function || d.constructor == String || d.constructor == Number || d.constructor == Boolean) {
					return new d.constructor(d)
				} else {
					try {
						var b = new d.constructor();
						for (var c in d) {
							b[c] = Object.clone(d[c])
						}
						return b
					} catch(a) {
						return d
					}
				}
			}
		}
	}
	function C(a) {
		if (this.isArray(a)) {
			return this.length == 0
		} else {
			for (var b in a) {
				return false
			}
			return true
		}
	}
	function w(a, c) {
		if (this.isArray(a)) {
			a.each(c)
		} else {
			try {
				for (var d in a) {
					try {
						c(d, a[d])
					} catch(b) {
						if (b != this.CONTINUE) {
							throw b
						}
					}
				}
			} catch(b) {
				if (b != this.BREAK) {
					throw b
				}
			}
		}
	}
	function y(a) {
		var b = 0;
		if (this.isArray(a)) {
			b = a.length
		} else {
			for (var c in a) {
				b++
			}
		}
		return b
	}
	function q(a, c) {
		var d = false;
		for (var b in a) {
			if (b == c) {
				d = true;
				break
			}
		}
		return d
	}
	function D(a) {
		var c = [];
		if (a.length) {
			for (var b = 0,
			d = a.length; b < d; b++) {
				c.push(a[b])
			}
		}
		return c
	}
	function r() {
		return this.EMPTYFUNC
	}
})(); (function() {
	var c = "netease.mail.base";
	var d = Object.createClass(c, "Const");
	Object.extend(d, {});
	window.undefined = window.undefined
})(); (function() {
	Object.extend(Array.prototype, {
		findObject: o,
		clone: r,
		each: p,
		_match: k,
		has: j,
		replace: q,
		remove: m,
		extend: n
	});
	function k(a, c, d, b) {
		if (arguments.length != 4) {
			d = Object.isFunction(c);
			b = c instanceof RegExp
		}
		var e = false;
		if (d) {
			if (c(a)) {
				e = true
			}
		} else {
			if (b) {
				if (a.toString().search(c) > -1) {
					e = true
				}
			} else {
				if (a == c) {
					e = true
				}
			}
		}
		return e
	}
	function o(b, a) {
		var c;
		this.each(function(e, d) {
			if (typeof(d) == "object") {
				if (d[b] == a) {
					c = d;
					throw Object.BREAK
				}
			}
		});
		return c
	}
	function r() {
		return this.slice(0)
	}
	function p(d) {
		for (var b = 0,
		c = this.length; b < c; b++) {
			try {
				d(b, this[b])
			} catch(a) {
				if (a === Object.BREAK) {
					break
				} else {
					if (a === Object.CONTINUE) {
						continue
					} else {
						throw a
					}
				}
			}
		}
	}
	function j(b) {
		var d = this;
		var e = false;
		var c = Object.isFunction(b);
		var a = b instanceof RegExp;
		d.each(function(g, f) {
			if (d._match(f, b, c, a)) {
				e = true;
				throw Object.BREAK
			}
		});
		return e
	}
	function q(a, e, c) {
		var d = this;
		var b = Object.isFunction(a);
		var f = a instanceof RegExp;
		d.each(function(h, g) {
			if (d._match(g, a, b, f)) {
				d[h] = e;
				if (!c) {
					throw Object.BREAK
				}
			}
		})
	}
	function m(e, g, b) {
		var h = this;
		var f = Object.isFunction(e);
		var d = e instanceof RegExp;
		for (var a = 0,
		c = h.length; a < c; a++) {
			if (h._match(h[a], e, f, d)) {
				if (b) {
					delete h[a]
				} else {
					h.splice(a, 1);
					a--;
					c--
				}
				if (!g) {
					break
				}
			}
		}
	}
	function n(a, b) {
		this.each(function(d, c) {
			Object.extend(c, a, b)
		})
	}
})(); (function() {
	Object.extend(Date.prototype, {
		dateAdd: g,
		period: k,
		getWeek: h,
		iFormat: j,
		format: f
	});
	function g(a) {
		return new Date(this.valueOf() + a * 3600 * 24 * 1000)
	}
	function k(u, b) {
		var c = [],
		m;
		var t = this;
		var d = new Date(t.getFullYear(), t.getMonth(), t.getDate() + 1);
		var a, e;
		if (!b) {
			c[c.length] = {
				name: "未来",
				start: new Date(d.getTime()),
				end: new Date(10000, 0, 1)
			}
		}
		for (var r = 0,
		s = t.getDay(); r <= s; r++) {
			if (u > -1 && r > u) {
				break
			}
			if (r == 0) {
				m = "今天"
			} else {
				if (r == 1) {
					m = "昨天"
				} else {
					m = "星期" + this.getWeek( - r)
				}
			}
			c[c.length] = {
				name: m,
				start: new Date(d.dateAdd( - 1)),
				end: new Date(d.getTime() - 1)
			};
			d = new Date(d.dateAdd( - 1))
		}
		a = new Date( - 10000, 0, 1);
		e = (new Date(d));
		c[c.length] = {
			name: "更早",
			start: a,
			end: e
		};
		if (b) {
			if (c[0].name == "今天") {
				c[0].end = new Date(10000, 0, 1)
			}
		}
		return c
	}
	function h(b) {
		var c = ["日", "一", "二", "三", "四", "五", "六"];
		var a = this.getDay();
		if (b) {
			a += b % 7 + 7;
			a %= 7
		}
		return c[a]
	}
	function j(a) {
		var a = a ? a: new Date();
		var b = a - this;
		if (!b || b < 60000) {
			return Math.max(1, parseInt(b / 1000)) + "秒前"
		}
		if (b && b < 3600000) {
			return Math.max(1, parseInt(b / 60000)) + "分前"
		}
		if (this.getFullYear() === a.getFullYear() && this.getMonth() === a.getMonth()) {
			if (this.getDate() === a.getDate()) {
				return this.format("今天 HH:mm")
			}
			if (this.getDate() === a.getDate() - 1) {
				return this.format("昨天 HH:mm")
			}
		}
		return this.format("yyyy-MM-dd HH:mm")
	}
	function f(n) {
		var o, c, p, b, a, d;
		o = this.getFullYear();
		c = this.getMonth() + 1;
		p = this.getDate();
		b = this.getHours();
		a = this.getMinutes();
		d = this.getSeconds();
		sWeek = this.getWeek();
		if (n) {
			return n.replace(/y+|m+|d+|h+|s+|H+|M+|w+/g, e)
		} else {
			return o + (c < 10 ? "-0": "-") + c + (p < 10 ? "-0": "-") + p + (b < 10 ? " 0": " ") + b + (a < 10 ? ":0": ":") + a + (d < 10 ? ":0": ":") + d
		}
		function e(m) {
			switch (m) {
			case "yyyy":
				return o;
			case "yy":
				return o.toString().slice( - 2);
			case "MM":
				return c.format(2);
			case "M":
				return c;
			case "dd":
				return p.format(2);
			case "d":
				return p;
			case "HH":
				return b.format(2);
			case "H":
				return b;
			case "hh":
				return (b > 12 ? b - 12 : b).format(2);
			case "h":
				return b > 12 ? b - 12 : b;
			case "mm":
				return a.format(2);
			case "m":
				return a;
			case "ss":
				return d.format(2);
			case "s":
				return d;
			case "w":
				return sWeek;
			default:
				return m
			}
		}
	}
})(); (function() {
	Object.extend(Function.prototype, {
		bind: b
	});
	function b() {
		var a = this;
		var f = [];
		for (var g = 0; g < arguments.length; g++) {
			f.push(arguments[g])
		}
		var h = f.shift();
		return function() {
			var c = [];
			for (var d = 0; d < arguments.length; d++) {
				c.push(arguments[d])
			}
			return a.apply(h, f.concat(c))
		}
	}
})();
var JSON;
if (!JSON) {
	JSON = {}
} (function() {
	function f(n) {
		return n < 10 ? "0" + n: n
	}
	if (typeof Date.prototype.toJSON !== "function") {
		Date.prototype.toJSON = function(key) {
			return isFinite(this.valueOf()) ? this.getUTCFullYear() + "-" + f(this.getUTCMonth() + 1) + "-" + f(this.getUTCDate()) + "T" + f(this.getUTCHours()) + ":" + f(this.getUTCMinutes()) + ":" + f(this.getUTCSeconds()) + "Z": null
		};
		String.prototype.toJSON = Number.prototype.toJSON = Boolean.prototype.toJSON = function(key) {
			return this.valueOf()
		}
	}
	var cx = /[\u0000\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,
	escapable = /[\\\"\x00-\x1f\x7f-\x9f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,
	gap, indent, meta = {
		"\b": "\\b",
		"\t": "\\t",
		"\n": "\\n",
		"\f": "\\f",
		"\r": "\\r",
		'"': '\\"',
		"\\": "\\\\"
	},
	rep;
	function quote(string) {
		escapable.lastIndex = 0;
		return escapable.test(string) ? '"' + string.replace(escapable,
		function(a) {
			var c = meta[a];
			return typeof c === "string" ? c: "\\u" + ("0000" + a.charCodeAt(0).toString(16)).slice( - 4)
		}) + '"': '"' + string + '"'
	}
	function str(key, holder) {
		var i, k, v, length, mind = gap,
		partial, value = holder[key];
		if (value && typeof value === "object" && typeof value.toJSON === "function") {
			value = value.toJSON(key)
		}
		if (typeof rep === "function") {
			value = rep.call(holder, key, value)
		}
		switch (typeof value) {
		case "string":
			return quote(value);
		case "number":
			return isFinite(value) ? String(value) : "null";
		case "boolean":
		case "null":
			return String(value);
		case "object":
			if (!value) {
				return "null"
			}
			gap += indent;
			partial = [];
			if (Object.prototype.toString.apply(value) === "[object Array]") {
				length = value.length;
				for (i = 0; i < length; i += 1) {
					partial[i] = str(i, value) || "null"
				}
				v = partial.length === 0 ? "[]": gap ? "[\n" + gap + partial.join(",\n" + gap) + "\n" + mind + "]": "[" + partial.join(",") + "]";
				gap = mind;
				return v
			}
			if (rep && typeof rep === "object") {
				length = rep.length;
				for (i = 0; i < length; i += 1) {
					k = rep[i];
					if (typeof k === "string") {
						v = str(k, value);
						if (v) {
							partial.push(quote(k) + (gap ? ": ": ":") + v)
						}
					}
				}
			} else {
				for (k in value) {
					if (Object.hasOwnProperty.call(value, k)) {
						v = str(k, value);
						if (v) {
							partial.push(quote(k) + (gap ? ": ": ":") + v)
						}
					}
				}
			}
			v = partial.length === 0 ? "{}": gap ? "{\n" + gap + partial.join(",\n" + gap) + "\n" + mind + "}": "{" + partial.join(",") + "}";
			gap = mind;
			return v
		}
	}
	if (typeof JSON.stringify !== "function") {
		JSON.stringify = function(value, replacer, space) {
			var i;
			gap = "";
			indent = "";
			if (typeof space === "number") {
				for (i = 0; i < space; i += 1) {
					indent += " "
				}
			} else {
				if (typeof space === "string") {
					indent = space
				}
			}
			rep = replacer;
			if (replacer && typeof replacer !== "function" && (typeof replacer !== "object" || typeof replacer.length !== "number")) {
				throw new Error("JSON.stringify")
			}
			return str("", {
				"": value
			})
		}
	}
	if (typeof JSON.parse !== "function") {
		JSON.parse = function(text, reviver) {
			var j;
			function walk(holder, key) {
				var k, v, value = holder[key];
				if (value && typeof value === "object") {
					for (k in value) {
						if (Object.hasOwnProperty.call(value, k)) {
							v = walk(value, k);
							if (v !== undefined) {
								value[k] = v
							} else {
								delete value[k]
							}
						}
					}
				}
				return reviver.call(holder, key, value)
			}
			text = String(text);
			cx.lastIndex = 0;
			if (cx.test(text)) {
				text = text.replace(cx,
				function(a) {
					return "\\u" + ("0000" + a.charCodeAt(0).toString(16)).slice( - 4)
				})
			}
			if (/^[\],:{}\s]*$/.test(text.replace(/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g, "@").replace(/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g, "]").replace(/(?:^|:|,)(?:\s*\[)+/g, ""))) {
				j = eval("(" + text + ")");
				return typeof reviver === "function" ? walk({
					"": j
				},
				"") : j
			}
			throw new SyntaxError("JSON.parse")
		}
	}
} ()); (function() {
	Object.extend(Number.prototype, {
		getBit: j,
		setBit: f,
		format: k,
		random: g,
		convert: h
	});
	function j(c) {
		var a = this;
		if (typeof c != "number" || isNaN(c)) {
			c = 0
		}
		var b = Math.pow(2, c);
		if ((a & b) > 0) {
			return 1
		} else {
			return 0
		}
	}
	function f(c, d) {
		var a = this;
		if (typeof c != "number" || isNaN(c)) {
			c = 0
		}
		if (typeof d != "number" || isNaN(d)) {
			return a
		}
		if (a.getBit(c) != d) {
			var b = Math.pow(2, c);
			if (d == 0) {
				return a ^ b
			} else {
				return a | b
			}
		}
		return a
	}
	function k(a) {
		var b = this.toString();
		if (a > b.length) {
			var c = a - b.length;
			for (var d = 0; d < c; d++) {
				b = "0" + b
			}
		}
		return b
	}
	function g() {
		var a = 0;
		if (this > 0) {
			a = Math.round((this - 1) * Math.random())
		}
		return a
	}
	function h(d, c) {
		d = d || 2;
		var a = Math.pow(10, d);
		var e = ["B", "K", "M", "G", "T", "P", "E"];
		var n = [];
		e.each(function(o, p) {
			n[o] = Math.pow(1024, o)
		});
		var b = "";
		if (this == 0) {
			b = "0"
		} else {
			var m = this;
			n.each(function(q, p) {
				var r = m / p;
				if (c == e[q] || (!c && r < 1024) || q + 1 == n.length) {
					b = Math.round(r * a) / a + e[q];
					throw Object.BREAK
				}
			})
		}
		return b
	}
})(); (function() {
	Object.extend(String.prototype, {
		stripTags: p,
		escapeHTML: t,
		unescapeHTML: u,
		decodeHTML: q,
		encodeHTML: C,
		toInt: z,
		trim: x,
		check: o,
		len: A,
		left: y,
		isNumber: s,
		has: v,
		urlAdd: r,
		exec: w
	});
	function p() {
		return this.replace(/<\/?[^>]+>/gi, "")
	}
	function t() {
		var a = document.createElement("div");
		var b = document.createTextNode(this);
		a.appendChild(b);
		return a.innerHTML
	}
	function u() {
		var a = document.createElement("div");
		a.innerHTML = this.stripTags();
		return a.childNodes[0].nodeValue
	}
	function q() {
		var a = this;
		a = a.replace(/&lt;/gi, "<");
		a = a.replace(/&gt;/gi, ">");
		a = a.replace(/&quot;/gi, '"');
		a = a.replace(/&amp;/gi, "&");
		a = a.replace(/&nbsp;/gi, " ");
		return a
	}
	function C() {
		var a = this;
		a = a.replace(/&/gi, "&amp;");
		a = a.replace(/</gi, "&lt;");
		a = a.replace(/>/gi, "&gt;");
		a = a.replace(/\"/gi, "&quot;");
		a = a.replace(/ /gi, "&nbsp;");
		return a
	}
	function z() {
		return parseInt(this, 10)
	}
	function x() {
		return this.replace(/(^\s*)|(\s*$)/g, "").replace(/(^　*)|(　*$)/g, "")
	}
	function o(a) {
		if (!a) {
			a = /[,%\'\"\/\\;|\<\>\^]/
		}
		if (this.search(a) == -1) {
			return false
		} else {
			return true
		}
	}
	function A() {
		var b = 0;
		for (var a = 0; a < this.length; a++) {
			if (this.charCodeAt(a) > 255) {
				b += 2
			} else {
				b++
			}
		}
		return b
	}
	function y(b, a) {
		var d = 0;
		var e = 0;
		if (a === true) {
			a = 2
		} else {
			if (! (a > 0)) {
				a = 0
			}
		}
		if (this.len() <= b) {
			return this
		}
		b = b - a;
		while (e < b) {
			if (this.charCodeAt(d) > 255) {
				e += 2
			} else {
				e++
			}
			d++
		}
		var c = this.substring(0, d);
		for (var d = 0; d < a; d++) {
			c += "."
		}
		return c
	}
	function s() {
		return (this.search(/^\d+$/g) == 0)
	}
	function v(a, b) {
		if (b) {
			return this.search(a) > -1
		} else {
			return this.indexOf(a) > -1
		}
	}
	function r(a) {
		if (a) {
			return this + (this.has("?") ? "&": "?") + a
		} else {
			return this
		}
	}
	function w(a) {
		return new netease.mail.base.Template(this).evaluate(a.data, a.defaultData, a.fix)
	}
})(); (function() {
	var u = "netease.mail.base";
	var C = Object.createClass(u, "Ajax");
	var w = Object.getClass(u);
	Object.extend(C, {
		_xmlHttpPoll: [],
		_iframePoll: [],
		_scriptPoll: [],
		_cssPoll: [],
		XMLHTTP: "xmlHttp",
		IFRAME: "iframe",
		SCRIPT: "script",
		CSS: "css",
		GET: "get",
		POST: "post",
		UNINITIALIZED: 0,
		LOADING: 1,
		LOADED: 2,
		INTERACTIVE: 3,
		COMPLETED: 4,
		_emptyFunc: Object.EMPTYFUNC,
		_getXmlHttp: A,
		_getIframe: D,
		_getResource: y,
		_xmlHttpRequest: F,
		_xmlHttpResponse: q,
		_iframeRequest: x,
		_iframeResponse: t,
		_resourceRequest: v,
		_resourceResponse: p,
		request: z,
		response: r,
		jsonp: s
	});
	function A() {
		var b = this;
		var c, d, a;
		var e = b._xmlHttpPoll;
		for (c = 0, d = e.length; c < d; c++) {
			a = e[c];
			if (a.readyState == C.UNINITIALIZED || a.readyState == C.COMPLETED) {
				return a
			}
		}
		a = e[d] = w.Util.tryThese(function() {
			return new ActiveXObject("MSXML2.XMLHttp.6.0")
		},
		function() {
			return new ActiveXObject("MSXML2.XMLHttp.3.0")
		},
		function() {
			return new XMLHttpRequest()
		},
		function() {
			return new ActiveXObject("MSXML2.XMLHttp.5.0")
		},
		function() {
			return new ActiveXObject("MSXML2.XMLHttp.4.0")
		},
		function() {
			return new ActiveXObject("Msxml2.XMLHTTP")
		},
		function() {
			return new ActiveXObject("MSXML.XMLHttp")
		},
		function() {
			return new ActiveXObject("Microsoft.XMLHTTP")
		}) || null;
		return a
	}
	function D(c) {
		var h = this;
		var j, b, d;
		var g = h._iframePoll;
		for (j = 0, b = g.length; j < b; j++) {
			var f = g[j];
			if (!f.parentNode) {
				g.splice(j, 1);
				j--;
				b--;
				continue
			}
			if (!f.loading) {
				d = f;
				break
			}
		}
		if (!d) {
			if (!c) {
				c = window
			}
			var e = c.document;
			d = g[b] = e.createElement("IFRAME");
			d.style.display = "none";
			e.body.appendChild(d)
		}
		d.src = "about:blank";
		try {
			var e = d.contentWindow.document;
			e.open("text/html", "replace");
			e.write("<body></body>");
			e.close()
		} catch(a) {}
		return d
	}
	function y(f, d, m) {
		var j = this;
		var o, H, b;
		var n, a, f, e, g, h;
		if (f == j.SCRIPT) {
			n = "SCRIPT";
			a = undefined;
			f = "text/javascript";
			e = j._scriptPoll
		} else {
			n = "LINK";
			a = "stylesheet";
			f = "text/css";
			e = j._cssPoll
		}
		if (g) {
			for (o = 0, H = e.length; o < H; o++) {
				var c = e[o];
				if (!c.loading) {
					c.parentNode.removeChild(c);
					e.splice(o, 1);
					o--;
					H--
				}
			}
		}
		if (!d) {
			d = window
		}
		var k = d.document;
		var b = e[H] = k.createElement(n);
		b.type = f;
		b.rel = a;
		if (m) {
			m(b)
		}
		var G = k.getElementsByTagName("head")[0];
		G.appendChild(b);
		return b
	}
	function F(e) {
		var k = this;
		var n, G;
		var c = e.url || "";
		var m = e.sync || false;
		var j = e.method || k.GET;
		var b = e.body || "";
		var f = e.head || [];
		var g = e.rnd || false;
		if (g) {
			c = c.urlAdd((new Date()).getTime())
		}
		if (j == k.POST) {
			f = f.concat([{
				name: "Content-type",
				value: "application/x-www-form-urlencoded"
			}])
		}
		var d = k._getXmlHttp();
		try{
			d = new XDomainRequest();
		}catch(e){}

		d.open(j, c, !m);
		if (!m) {
			d.onreadystatechange = k.response.bind(k, d, e)
		}
		for (n = 0, G = f.length; n < G; n++) {
			var o = f[n];
			d.setRequestHeader(o.name, o.value)
		}
		if (typeof b != "string") {
			var h = b;
			var a = [];
			h.each(function(I, H) {
				a.push(I + "=" + encodeURIComponent(H))
			});
			b = a.join("&")
		}
		b = b.replace(/[\x00-\x08\x0b\x0e-\x1f]/g, "");
		d.send(j == k.POST ? b: null);
		if (m) {
			k.response(d, e)
		}
		return d
	}
	function q(a, b) {
		var f = this;
		try {
			var e = b.stateChange;
			if (e) {
				e(a)
			}
			if (a.readyState == C.COMPLETED) {
				try {
					a.onreadystatechange = null
				} catch(c) {
					a.onreadystatechange = f._emptyFunc
				}
				var d = b.call;
				if (d) {
					d(a)
				}
			}
		} catch(c) {}
		return true
	}
	function x(d) {
		var j = this;
		var b = d.url || "";
		var h = d.method || j.GET;
		var c = d.body || "";
		var f = j._getIframe();
		var e = d.rnd || false;
		if (e) {
			b = b.urlAdd((new Date()).getTime())
		}
		var a = d.target || "";
		f.loading = true;
		w.Event.one(f, "load", j.response.bind(j, f, d));
		if (h == j.GET) {
			f.src = b.urlAdd(c)
		} else {
			var k = f.contentWindow.document;
			var m = "formRequest";
			k.body.innerHTML = '<form name="' + m + '" id="' + m + '" action="' + b + '" method="' + h + '" target="' + a + '"></form>';
			if (typeof c == "string") {
				var o = c.split("&");
				o.each(function(L, M) {
					var I = M.split("=");
					if (I.length == 2) {
						var K = I[0];
						var H = decodeURIComponent(I[1]);
						n(K, H)
					}
				})
			} else {
				var g = c;
				Object.each(g,
				function(H, G) {
					n(H, G)
				})
			}
			k.forms[m].submit()
		}
		return f;
		function n(I, G) {
			var H = k.createElement("INPUT");
			H.name = I;
			H.value = G;
			H.type = "hidden";
			k.forms[m].appendChild(H)
		}
	}
	function t(d, a) {
		try {
			d.loading = false;
			var b = a.call;
			if (b) {
				b(d)
			}
		} catch(c) {}
		return true
	}
	function v(a) {
		var e = this;
		var f = a.url || "";
		var c = a.charset || "utf-8";
		var g = a.rnd || false;
		if (g) {
			f = f.urlAdd((new Date()).getTime())
		}
		if (a.paddingFunc) {
			var d = a.paddingParam;
			if (!d) {
				d = "callback"
			}
			var h = "padding" + (new Date()).getTime();
			e[h] = a.paddingFunc;
			f = f.urlAdd(d + "=" + u + ".Ajax." + h)
		}
		var b = e._getResource(a.requestType, a.window,
		function(k) {
			oScriptOrLink = k;
			var j = e.response.bind(e, k, a);
			w.Event.one(k, "load", j);
			w.Event.listen(k, "readystatechange", j);
			k.charset = c;
			k.src = k.href = f;
			k.loading = true
		});
		return b
	}
	function p(a, b) {
		if (a.loading && (!a.readyState || a.readyState === "loaded" || a.readyState === "complete")) {
			a.loading = false;
			var c = b.call;
			if (c) {
				c(a)
			}
			if (a.readyState) {
				w.Event.unlistenAll(a)
			}
		}
		return true
	}
	function z(a) {
		var c = this;
		var d, e;
		try {
			d = a.requestType
		} catch(b) {}
		if (!d) {
			d = a.requestType = c.XMLHTTP
		}
		switch (d) {
		case c.IFRAME:
			e = c._iframeRequest(a);
			break;
		case c.SCRIPT:
		case c.CSS:
			e = c._resourceRequest(a);
			break;
		default:
			e = c._xmlHttpRequest(a)
		}
		return e
	}
	function r(b, a) {
		var c = this;
		var d = a.requestType;
		var e = false;
		switch (d) {
		case c.IFRAME:
			e = c._iframeResponse(b, a);
			break;
		case c.SCRIPT:
		case c.CSS:
			e = c._resourceResponse(b, a);
			break;
		default:
			e = c._xmlHttpResponse(b, a)
		}
		return e
	}
	function s(c, a, b) {
		var d = this;
		d.request({
			requestType: d.SCRIPT,
			url: c,
			paddingFunc: a,
			paddingParam: b
		})
	}
})(); (function() {
	var o = "netease.mail.base";
	var m = Object.createClass(o, "Browser");
	Object.extend(m, {
		_os: "unknown",
		_appName: "unknown",
		_version: "unknown",
		_screenWidth: null,
		_screenHeight: null,
		_hasFlash: null,
		_flashVersion: null,
		_isInited: false,
		_init: s,
		getInfo: w,
		getVersion: u,
		isIE: q,
		ie: r,
		firefox: v,
		chrome: p,
		safari: t,
		opera: n
	});
	function s() {
		if (!this._isInited) {
			var a = window.navigator.userAgent;
			var b = "";
			var d = "";
			var c = "";
			var f = "";
			if ((/windows|win32/i).test(a)) {
				b = "windows"
			} else {
				if ((/linux/i).test(a)) {
					b = "linux"
				} else {
					if ((/macintosh/i).test(a)) {
						b = "macintosh"
					} else {
						if ((/rhino/i).test(a)) {
							b = "rhino"
						} else {
							if ((/ipad/i).test(a)) {
								b = "ipad"
							} else {
								if ((/iphone/i).test(a)) {
									b = "iphone"
								} else {
									if ((/ipod/i).test(a)) {
										b = "ipod"
									} else {
										if ((/android/i).test(a)) {
											b = "android"
										} else {
											if ((/adobeair/i).test(a)) {
												b = "adobeair"
											} else {
												try {
													b = navigator.platform.toLowerCase()
												} catch(e) {}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			this._os = b;
			try {
				g()
			} catch(e) {}
			this._appName = d.trim().toLowerCase();
			this._version = c.trim().toLowerCase();
			this._screenWidth = window.screen.width;
			this._screenHeight = window.screen.height;
			try {
				h()
			} catch(e) {}
			this._hasFlash = !!f;
			this._flashVersion = f;
			this._isInited = true
		}
		function g() {
			var j;
			j = a.match(/MSIE\s([^;]*)/);
			if (j && j[1]) {
				d = "MSIE";
				c = j[1];
				return
			}
			j = a.match(/Firefox\/([^\s]*)/);
			if (j && j[1]) {
				d = "Firefox";
				c = j[1];
				return
			}
			j = a.match(/Chrome\/([^\s]*)/);
			if (j && j[1]) {
				d = "Chrome";
				c = j[1];
				return
			}
			j = a.match(/Version\/([^\s]*).+Safari/);
			if (j && j[1]) {
				d = "Safari";
				c = j[1];
				return
			}
			j = a.match(/Opera.+Version[\s\/]([^\s]*)/);
			if (j && j[1]) {
				d = "Opera";
				c = j[1];
				j = a.match(/Opera Mini[^;]*/);
				if (j) {
					d = j[0]
				}
				return
			}
			j = a.match(/AppleWebKit\/([^\s]*)/);
			if (j && j[1]) {
				d = "AppleWebKit";
				c = j[1];
				return
			}
		}
		function h() {
			if (d == "MSIE") {
				var j = new ActiveXObject("ShockwaveFlash.ShockwaveFlash");
				if (j) {
					f = j.getVariable("$version").split(" ")[1]
				}
			} else {
				if (navigator.plugins && navigator.plugins.length > 0) {
					var j = navigator.plugins["Shockwave Flash"];
					if (j) {
						var k = j.description.split(" ");
						for (var x = 0,
						y = k.length; x < y; x++) {
							if (parseInt(k[x]) > 0) {
								f = k[x];
								break
							}
						}
					}
				}
			}
		}
	}
	function w() {
		this._init();
		return {
			os: this._os,
			appName: this._appName,
			version: this._version,
			screenWidth: this._screenWidth,
			screenHeight: this._screenHeight,
			hasFlash: this._hasFlash,
			flashVersion: this._flashVersion
		}
	}
	function u() {
		this._init();
		var b = this._version;
		var c = b.split(".");
		for (var d = 0,
		a = c.length; d < a; d++) {
			c[d] = parseInt(c[d], 10)
		}
		return c
	}
	function q() {
		this._init();
		return this._appName == "msie"
	}
	function r() {
		this._init();
		var a = this._version;
		return this._appName == "msie" ? a: undefined
	}
	function v() {
		this._init();
		var a = this._version;
		return this._appName == "firefox" ? a: undefined
	}
	function p() {
		this._init();
		var a = this._version;
		return this._appName == "chrome" ? a: undefined
	}
	function t() {
		this._init();
		var a = this._version;
		return this._appName == "safari" ? a: undefined
	}
	function n() {
		this._init();
		var a = this._version;
		return this._appName == "opera" ? a: undefined
	}
})(); (function() {
	var g = "netease.mail.base";
	var f = Object.createClass(g, "Cookie");
	Object.extend(f, {
		get: e,
		set: h
	});
	function e(b, o) {
		var c = b + "=";
		var a = "";
		var d = document.cookie;
		if (d.length > 0) {
			var n = d.indexOf(c);
			if (n != -1) {
				n += c.length;
				var m = d.indexOf(";", n);
				if (m == -1) {
					m = d.length
				}
				a = d.substring(n, m);
				if (!o) {
					a = unescape(a)
				}
			}
		}
		return a
	}
	function h(c, a, k, m, b) {
		var d = [];
		if (c && a) {
			d[d.length] = c + "=" + escape(a)
		}
		if (k) {
			d[d.length] = "path=" + k
		}
		if (m) {
			d[d.length] = "domain=" + m
		}
		if (b) {
			d[d.length] = "expires=" + b
		}
		document.cookie = d.join(";")
	}
})(); (function() {
	var j = "netease.mail.base";
	var g = Object.createClass(j, "Data");
	Object.extend(g, {
		_cache: {},
		_index: 0,
		_invalid: {
			embed: true,
			object: true,
			applet: true
		},
		_name: "_j",
		_check: n,
		get: h,
		set: k,
		remove: m
	});
	function n(c) {
		var b = true;
		var a = c.nodeName;
		if (a && this._invalid[a.toLowerCase()]) {
			b = false
		}
		return b
	}
	function h(e, b) {
		if (!this._check(e)) {
			return
		}
		var d = e[this._name];
		var a = this._cache;
		var c;
		if (!d || !a[d]) {
			return
		}
		var c = a[d];
		return c[b]
	}
	function k(f, c, a) {
		if (typeof c !== "string") {
			return
		}
		if (!this._check(f)) {
			return
		}
		var e = f[g._name];
		var b = g._cache;
		var d;
		if (!e) {
			e = ++g._index
		}
		if (!b[e]) {
			f[g._name] = e;
			b[e] = {}
		}
		d = b[e];
		d[c] = a
	}
	function m(f, b) {
		if (!this._check(f)) {
			return
		}
		var e = f[g._name];
		if (e) {
			var a = g._cache;
			var d = a[e];
			if (b) {
				if (d) {
					delete d[b];
					if (Object.isEmpty(d)) {
						this.remove(f)
					}
				}
			} else {
				try {
					delete f[g._name]
				} catch(c) {
					f[g._name] = ""
				}
				delete a[e]
			}
		}
	}
})(); (function() {
	var au = "netease.mail.base";
	var at = Object.createClass(au, "Element");
	var S = Object.getClass(au);
	Object.extend(at, {
		create: aq,
		inside: ak
	});
	Object.extend(at.prototype, {
		doms: null,
		dom: null,
		setAttr: aw,
		setStyle: az,
		addClass: T,
		removeClass: aj,
		toggleClass: an,
		setClass: al,
		replaceClass: N,
		find: O,
		findParent: af,
		next: ap,
		pre: av,
		append: W,
		previous: ay,
		after: aa,
		before: Z,
		wrap: aD,
		replace: ac,
		empty: aB,
		remove: ah,
		reset: X,
		position: ax,
		html: ab,
		listen: ae,
		unlisten: am,
		one: ai,
		show: Q,
		hide: aA,
		toggle: ag,
		get: ar,
		set: R,
		clean: ad,
		each: aC,
		merge: Y,
		initialize: ao
	});
	function ao(a) {
		if (a && !Object.isArray(a)) {
			a = [a]
		}
		this.doms = a || [];
		if (this.doms.length > 0) {
			this.dom = this.doms[0]
		}
	}
	function aq(c, a, f) {
		if (!Object.isArray(c)) {
			c = [c]
		}
		if (a && !Object.isArray(a)) {
			a = [a]
		}
		var d = [];
		for (var b = 0,
		g = c.length; b < g; b++) {
			var e = (f || document).createElement(c[b].toUpperCase());
			if (a && a[b]) {
				e.id = a[b]
			}
			d[d.length] = e
		}
		return new at(d)
	}
	function ak(a, b) {
		while (a) {
			if (a == b) {
				return true
			}
			a = a.parentNode
		}
		return false
	}
	function aw(c) {
		var b;
		for (b in c) {
			this.each(a)
		}
		function a(e, d) {
			d[b] = c[b]
		}
	}
	function az(c) {
		var a;
		for (a in c) {
			this.each(b)
		}
		function b(e, d) {
			d.style[a] = c[a]
		}
	}
	function T(a) {
		if (a && typeof a === "string") {
			var b = (a || "").split(/\s+/);
			this.each(function(h, e) {
				if (e.nodeType === 1) {
					if (!e.className) {
						e.className = a
					} else {
						var f = " " + e.className + " ",
						d = e.className;
						for (var c = 0,
						g = b.length; c < g; c++) {
							if (f.indexOf(" " + b[c] + " ") < 0) {
								d += " " + b[c]
							}
						}
						e.className = d.trim()
					}
				}
			})
		}
	}
	function aj(a) {
		if ((a && typeof a === "string") || a === undefined) {
			var b = (a || "").split(/\s+/);
			this.each(function(d, e) {
				if (e.nodeType === 1 && e.className) {
					if (a) {
						var f = (" " + e.className + " ").replace(/[\n\t]/g, " ");
						for (var c = 0,
						g = b.length; c < g; c++) {
							f = f.replace(" " + b[c] + " ", " ")
						}
						e.className = f.trim()
					} else {
						e.className = ""
					}
				}
			})
		}
	}
	function an(b, c, a) {
		this.each(function(d, e) {
			if (e.className != b) {
				e.className = b;
				if (a) {
					a(1)
				}
			} else {
				e.className = c;
				if (a) {
					a(0)
				}
			}
		})
	}
	function al(a) {
		this.each(function(b, c) {
			c.className = a
		})
	}
	function N(a, b) {
		this.each(function(d, e) {
			var c = e.className.split(" ");
			for (var d = 0,
			f = c.length; d < f; d++) {
				if (c[d] == a) {
					c[d] = b;
					break
				}
			}
			e.className = c.join(" ")
		})
	}
	function O(a) {
		var b, c = [];
		this.each(function(f, h) {
			switch (a.substring(0, 1)) {
			case ".":
				var j = a.substr(1);
				if (h.getElementsByClassName) {
					aNodeList = h.getElementsByClassName(j);
					for (var f = 0; f < aNodeList.length; f++) {
						c.push(aNodeList[f])
					}
				} else {
					var k = h.getElementsByTagName("*");
					for (var f = 0; f < k.length; f++) {
						if (k[f].className == j) {
							c.push(k[f])
						}
					}
				}
				break;
			case "#":
				var g = a.substr(1);
				var k = h.getElementsByTagName("*");
				for (var f = 0; f < k.length; f++) {
					if (k[f].id == g) {
						c.push(k[f])
					}
				}
				break;
			default:
				c = h.getElementsByTagName(a);
				var e = [];
				for (var f = 0,
				d = c.length; f < d; f++) {
					e.push(c[f])
				}
				c = e
			}
		});
		b = new netease.mail.base.Element(c);
		return b.dom ? b: null
	}
	function af(a, c) {
		var b, e = [];
		this.each(function(f, g) {
			if (!c) {
				g = g.parentNode
			}
			while (g) {
				if (d(g)) {
					e.push(g)
				}
				g = g.parentNode
			}
		});
		b = new netease.mail.base.Element(e);
		return b.dom ? b: null;
		function d(g) {
			switch (a.substring(0, 1)) {
			case ".":
				var h = a.substr(1);
				if (g.className == h) {
					return true
				}
				break;
			case "#":
				var f = a.substr(1);
				if (g.id == f) {
					return true
				}
				break;
			default:
				if (g.tagName && g.tagName.toUpperCase() == a.toUpperCase()) {
					return true
				}
			}
		}
	}
	function ap() {
		var a = [];
		this.each(function(c, e) {
			if (e && e.parentNode) {
				var b = e.parentNode.childNodes;
				for (var d = 0; d < b.length; d++) {
					if (b[d] == e && b[d + 1]) {
						a.push(b[d + 1])
					}
				}
			}
		});
		return new at(a)
	}
	function av() {
		var a = [];
		this.each(function(c, e) {
			if (e && e.parentNode) {
				var b = e.parentNode.childNodes;
				for (var d = 0; d < b.length; d++) {
					if (b[d] == e && b[d - 1]) {
						a.push(b[d - 1])
					}
				}
			}
		});
		return new at(a)
	}
	function W(a) {
		this.each(function(c, f) {
			if (f && f.nodeType == 1) {
				if (typeof a == "string") {
					var d = (f.ownerDocument || document).createElement("DIV");
					d.innerHTML = a;
					var b = d.childNodes;
					var e = new at(f);
					while (b.length > 0) {
						e.append(b[0])
					}
				} else {
					f.appendChild(a)
				}
			}
		})
	}
	function ay(a) {
		this.each(function(d, g) {
			if (g && g.parentNode) {
				var b = g.childNodes.length;
				if (typeof a == "string") {
					var e = document.createElement("DIV");
					e.innerHTML = a;
					var c = e.childNodes;
					for (var f = 0; f < c.length; f++) {
						new at(g).previous(c[f])
					}
				} else {
					if (b == 0) {
						g.appendChild(a)
					} else {
						g.insertBefore(a, g.childNodes[0])
					}
				}
			}
		})
	}
	function aa(a) {
		var b = this;
		this.each(function(e, h) {
			if (h && h.parentNode) {
				if (typeof a == "string") {
					var f = document.createElement("DIV");
					f.innerHTML = a;
					var d = f.childNodes;
					for (var g = d.length - 1; g > -1; g--) {
						new at(h).after(d[g])
					}
				} else {
					var c = b.next();
					if (c.dom) {
						h.parentNode.insertBefore(a, c.dom)
					} else {
						h.parentNode.appendChild(a)
					}
				}
			}
		})
	}
	function Z(a) {
		var b = this;
		this.each(function(d, g) {
			if (g && g.nodeType == 1 && g.parentNode) {
				if (typeof a == "string") {
					var e = document.createElement("DIV");
					e.innerHTML = a;
					var c = e.childNodes;
					for (var f = c.length - 1; f > -1; f--) {
						new at(g).before(c[f])
					}
				} else {
					g.parentNode.insertBefore(a, g)
				}
			}
		})
	}
	function aD(a, e) {
		var c = this;
		var d = (e || document).createElement("DIV");
		d.innerHTML = a;
		var b = d.childNodes[0];
		if (b) {
			this.each(function(g, h) {
				if (h && h.parentNode) {
					new at(h).before(b.cloneNode(true));
					var f = new at(h).pre().dom;
					while (f.firstChild && f.firstChild.nodeType === 1) {
						f = f.firstChild
					}
					f.appendChild(h)
				}
			})
		}
		return c
	}
	function ac(a, e) {
		var c = this;
		var d = (e || document).createElement("DIV");
		d.innerHTML = a;
		var b = d.childNodes;
		this.each(function(f, h) {
			if (h && h.parentNode) {
				for (var g = 0; g < b.length; g++) {
					new at(h).before(b[g].cloneNode(true))
				}
				new at(h).remove()
			}
		})
	}
	function aB() {
		var a = this;
		a.each(function(b, c) {
			if (c.nodeType === 1) {
				new at(c.getElementsByTagName("*")).clean()
			}
			a.reset(c);
			while (c.firstChild) {
				c.removeChild(c.firstChild)
			}
		})
	}
	function ah() {
		var c = this;
		if ($.Component) {
			function b(h) {
				var j = h.id;
				if (j && $.Component._domids[j]) {
					var h = $C($.Component._domids[j]);
					if (h) {
						h.destroy()
					}
				}
			}
			for (var d = this.doms.length - 1; d > -1; d--) {
				var g = this.doms[d];
				if (g) {
					var a = g.getElementsByTagName("*");
					for (var f = a.length - 1; f > -1; f--) {
						var e = a[f];
						if (e) {
							b(e)
						}
					}
					b(g)
				}
			}
		}
		for (var d = this.doms.length - 1; d > -1; d--) {
			var g = this.doms[d];
			c.reset(g);
			if (g.parentNode) {
				g.parentNode.removeChild(g)
			}
			if (g.nodeType === 1) {
				new at(Object.toArray(g.getElementsByTagName("*")).concat([g])).clean()
			}
		}
	}
	function X(f) {
		var d = f.getElementsByTagName("IFRAME");
		for (var c = 0,
		g = d.length; c < g; c++) {
			var b = d[c];
			try {
				if (b.contentWindow) {
					var e = b.contentWindow.document;
					e.body.innerHTML = ""
				}
			} catch(a) {}
			b.src = "about:blank"
		}
	}
	function ax() {
		var a = this;
		var b = [];
		a.each(function(d, f) {
			var e = 0,
			c = 0;
			do {
				e += f.offsetTop || 0;
				c += f.offsetLeft || 0;
				f = f.offsetParent
			} while ( f );
			b.push([c, e])
		});
		return b.length == 1 ? b[0] : b
	}
	function ab(a) {
		var b = this;
		if (typeof a == "undefined") {
			return this.dom.innerHTML
		}
		b.each(function(c, d) {
			d.innerHTML = a
		})
	}
	function ae(b, a, c) {
		var d = S.Event;
		this.each(function(e, f) {
			d.listen(f, b, a, c)
		})
	}
	function am(b, a, c) {
		var d = S.Event;
		this.each(function(e, f) {
			d.unlisten(f, b, a, c)
		})
	}
	function ai(b, a, c) {
		var d = S.Event;
		this.each(function(e, f) {
			d.one(f, b, a, c)
		})
	}
	function Q() {
		var a = this;
		a.each(function(b, c) {
			c.style.display = ""
		})
	}
	function aA() {
		var a = this;
		a.each(function(b, c) {
			c.style.display = "none"
		})
	}
	function ag() {
		var a = this;
		a.each(function(b, c) {
			c.style.display = c.style.display == "none" ? "": "none"
		})
	}
	function ar(a) {
		var b = [];
		this.each(function(c, d) {
			b.push(S.Data.get(d, a))
		});
		return b.length == 1 ? b[0] : b
	}
	function R(b, a) {
		this.each(function(c, d) {
			S.Data.set(d, b, a)
		})
	}
	function ad() {
		var b = S.Event;
		var a = S.Data;
		this.each(function(c, d) {
			a.remove(d);
			b.unlistenAll(d)
		})
	}
	function aC(a) {
		if (this.doms.length == 1) {
			a(0, this.dom)
		} else {
			this.doms.each(a)
		}
	}
	function Y(a) {
		return new at(this.doms.concat(a.doms || []))
	}
})(); (function() {
	var u = "netease.mail.base";
	var s = Object.createClass(u, "Event");
	var y = Object.getClass(u);
	y = netease.mail.base;
	Object.extend(s, {
		_index: 0,
		_poll: {},
		count: 0,
		listen: r,
		unlisten: G,
		unlistenAll: w,
		one: C,
		get: H,
		getEvent: K,
		fix: F,
		getTarget: t,
		fire: z,
		stop: I,
		cancelBubble: v,
		cancel: x,
		isMouseover: A,
		isMouseout: D
	});
	function r(g, d, c, e) {
		e = !!e;
		var f = this._poll;
		var b = g._listener;
		if (!b || !f[b]) {
			var j = this._index;
			b = g._listener = j;
			f[j] = {};
			this._index++;
			this.count++
		}
		var a = f[b];
		if (g.addEventListener) {
			g.addEventListener(d, c, e)
		} else {
			if (g.attachEvent) {
				g.attachEvent("on" + d, c)
			}
		}
		var h = a[d];
		if (!h) {
			h = a[d] = []
		}
		h.push({
			name: d,
			observer: c,
			userCapture: e
		})
	}
	function G(j, d, c, f, h) {
		f = !!f;
		if (j.removeEventListener) {
			j.removeEventListener(d, c, f)
		} else {
			if (j.detachEvent) {
				j.detachEvent("on" + d, c)
			}
		}
		if (!h) {
			var g = this._poll;
			var m = g[j._listener];
			if (!m) {
				return
			}
			var k = m[d];
			if (k && k.length > 0) {
				for (var e = k.length - 1; e > -1; e--) {
					var b = k[e];
					if (b.name = d && b.observer == c && b.userCapture == f) {
						k.splice(e, 1);
						break
					}
				}
				if (k.length == 0) {
					delete m[d];
					var a = Object.count(m);
					if (a == 0) {
						delete g[j._listener];
						j._listener = null;
						this.count--
					}
				}
			}
		}
	}
	function w(d, a) {
		if (!d) {
			return
		}
		var g = d._listener;
		if (!g) {
			return
		}
		var b = this;
		var f = this._poll;
		var h = f[g];
		if (a) {
			var e = h[a];
			if (e) {
				c(e)
			}
		} else {
			for (var a in h) {
				var e = h[a];
				c(e, true)
			}
			delete f[g];
			d._listener = null;
			this.count--
		}
		function c(n, m) {
			for (var j = n.length - 1; j > -1; j--) {
				var k = n[j];
				b.unlisten(d, k.name, k.observer, k.userCapture, m)
			}
		}
	}
	function C(d, b, a, e) {
		var c = this;
		this.listen(d, b,
		function() {
			try {
				a.apply(this, arguments)
			} catch(f) {}
			c.unlisten(d, b, arguments.callee, e)
		},
		e)
	}
	function H(a) {
		a = this.getEvent(a);
		return this.fix(a)
	}
	function K(b) {
		b = b || window.event || top.window.event;
		if (!b && !y.Browser.isIE()) {
			var d = [];
			var a = arguments.callee.caller;
			while (a) {
				b = a.arguments[0];
				if (b && b instanceof window.Event) {
					break
				} else {
					b = undefined
				}
				var e = false;
				for (var c = 0; c < d.length; c++) {
					if (a == d[c]) {
						e = true;
						break
					}
				}
				if (e) {
					break
				} else {
					d.push(a)
				}
				a = a.caller
			}
		}
		return b
	}
	function F(a) {
		var b = "altKey attrChange attrName bubbles button cancelable charCode clientX clientY ctrlKey currentTarget data detail eventPhase fromElement handler keyCode layerX layerY metaKey newValue offsetX offsetY originalTarget pageX pageY prevValue relatedNode relatedTarget screenX screenY shiftKey srcElement target toElement type view wheelDelta which".split(" ");
		var c = {};
		for (var d = 0,
		g = b.length; d < g; d++) {
			var h = b[d];
			c[h] = a[h]
		}
		if (!c.target) {
			c.target = c.srcElement || document
		}
		if (c.target.nodeType === 3) {
			c.target = c.target.parentNode
		}
		if (!c.relatedTarget && c.fromElement) {
			c.relatedTarget = c.fromElement === c.target ? c.toElement: c.fromElement
		}
		if (c.pageX == null && c.clientX != null) {
			var f = document.documentElement,
			e = document.body;
			c.pageX = c.clientX + (f && f.scrollLeft || e && e.scrollLeft || 0) - (f && f.clientLeft || e && e.clientLeft || 0);
			c.pageY = c.clientY + (f && f.scrollTop || e && e.scrollTop || 0) - (f && f.clientTop || e && e.clientTop || 0)
		}
		if (!c.which && ((c.charCode || c.charCode === 0) ? c.charCode: c.keyCode)) {
			c.which = c.charCode || c.keyCode
		}
		if (!c.metaKey && c.ctrlKey) {
			c.metaKey = c.ctrlKey
		}
		if (!c.which && c.button !== undefined) {
			c.which = (c.button & 1 ? 1 : (c.button & 2 ? 3 : (c.button & 4 ? 2 : 0)))
		}
		return c
	}
	function t(b, a) {
		if (!b) {
			b = this.getEvent()
		}
		var c = b.target || b.srcElement;
		if (a && c && "#text" == c.nodeName) {
			return c.parentNode
		} else {
			return c
		}
	}
	function z(a, b) {
		if (a.fireEvent) {
			a.fireEvent("on" + b)
		} else {
			var c = document.createEvent("HTMLEvents");
			c.initEvent(b, true, true);
			a.dispatchEvent(c)
		}
	}
	function I(a) {
		if (!a) {
			a = this.getEvent()
		}
		this.cancelBubble(a);
		this.cancel(a)
	}
	function v(a) {
		if (!a) {
			a = this.getEvent()
		}
		if (a.stopPropagation) {
			a.stopPropagation()
		} else {
			a.cancelBubble = true
		}
	}
	function x(a) {
		if (!a) {
			a = this.getEvent()
		}
		if (a.preventDefault) {
			a.preventDefault()
		} else {
			a.returnValue = false
		}
	}
	function A(c, e) {
		try {
			e = e || this.get();
			var a = e.toElement || e.target;
			var b = e.fromElement || e.relatedTarget;
			var f = y.Element;
			if (f.inside(a, c) && !f.inside(b, c)) {
				return true
			} else {
				return false
			}
		} catch(d) {
			return true
		}
	}
	function D(c, e) {
		try {
			e = e || this.get();
			var a = e.toElement || e.relatedTarget;
			var b = e.fromElement || e.target;
			var f = y.Element;
			if (!f.inside(a, c) && f.inside(b, c)) {
				return true
			} else {
				return false
			}
		} catch(d) {
			return true
		}
	}
})(); (function() {
	var t = "netease.mail.base";
	var r = Object.createClass(t, "Util");
	Object.extend(r, {
		tryThese: o,
		getDomDocument: x,
		getXMLValue: y,
		str2Date: w,
		date2Str: q,
		dom2Obj: v,
		obj2Dom: u,
		dom2Str: n,
		str2Dom: s,
		obj2Str: z,
		str2Obj: p
	});
	function o() {
		var c, d, b;
		for (c = 0; c < arguments.length; c++) {
			d = arguments[c];
			try {
				b = d();
				break
			} catch(a) {}
		}
		return b
	}
	function x() {
		return this.tryThese(function() {
			return new ActiveXObject("Msxml2.DOMDocument.6.0")
		},
		function() {
			return new ActiveXObject("Msxml2.DOMDocument.3.0")
		},
		function() {
			return document.implementation.createDocument("", "", null)
		},
		function() {
			return new ActiveXObject("Msxml2.DOMDocument.5.0")
		},
		function() {
			return new ActiveXObject("Msxml2.DOMDocument.4.0")
		},
		function() {
			return new ActiveXObject("Msxml2.DOMDocument")
		},
		function() {
			return new ActiveXObject("MSXML.DOMDocument")
		},
		function() {
			return new ActiveXObject("Microsoft.XMLDOM")
		}) || null
	}
	function y(a) {
		var c = "";
		if (a && a.firstChild) {
			try {
				c = a.textContent;
				if (!c) {
					throw "content null"
				}
			} catch(b) {
				c = a.firstChild.nodeValue
			}
		}
		return c
	}
	function w(h) {
		var g, f, d;
		g = h.split(" ");
		f = g[0].split("-");
		var j = parseInt(f[0], 10);
		var k = parseInt(f[1], 10) - 1;
		var c = parseInt(f[2], 10);
		var a = 0;
		var b = 0;
		var e = 0;
		if (g[1]) {
			f = g[1].split(":");
			a = parseInt(f[0], 10);
			b = parseInt(f[1], 10);
			e = parseInt(f[2], 10)
		}
		d = new Date(j, k, c, a, b, e);
		return d
	}
	function q(b) {
		var c, a;
		c = b.getFullYear() + "-";
		a = b.getMonth() + 1;
		if (a < 10) {
			a = "0" + a
		}
		c += a + "-";
		a = b.getDate();
		if (a < 10) {
			a = "0" + a
		}
		c += a + " ";
		a = b.getHours();
		if (a < 10) {
			a = "0" + a
		}
		c += a + ":";
		a = b.getMinutes();
		if (a < 10) {
			a = "0" + a
		}
		c += a + ":";
		a = b.getSeconds();
		if (a < 10) {
			a = "0" + a
		}
		c += a;
		return c
	}
	function v(b) {
		var a = null;
		if (b) {
			var c, f, g, d, e;
			if (b.nodeType == 9) {
				for (c = 0, f = b.childNodes, g = f.length; c < g && (d = f[c]); c++) {
					if (d.nodeType != 1) {
						continue
					}
					a = this.dom2Obj(d);
					break
				}
			} else {
				switch (b.nodeName) {
				case "object":
					a = {};
					for (c = 0, f = b.childNodes, g = f.length; c < g && (d = f[c]); c++) {
						if (d.nodeType != 1) {
							continue
						}
						e = "";
						if (d.attributes) {
							e = d.attributes.getNamedItem("name").value
						}
						if (e) {
							a[e] = this.dom2Obj(d)
						}
					}
					break;
				case "array":
					a = [];
					for (c = 0, f = b.childNodes, g = f.length; c < g && (d = f[c]); c++) {
						if (d.nodeType != 1) {
							continue
						}
						a.push(this.dom2Obj(d))
					}
					break;
				case "int":
				case "long":
				case "number":
					a = parseInt(this.getXMLValue(b), 10);
					break;
				case "boolean":
					a = this.getXMLValue(b) == "true" ? true: false;
					break;
				case "date":
					a = this.str2Date(this.getXMLValue(b));
					break;
				case "base64":
					a = this.getXMLValue(b);
					break;
				case "null":
					a = null;
					break;
				default:
					a = this.getXMLValue(b);
					break
				}
			}
		}
		return a
	}
	function u(c) {
		var f = this;
		var d = f.getDomDocument();
		if (!d) {
			throw "no xml parser"
		}
		function g(j) {
			return d.createElement(j)
		}
		function b(j, k) {
			j.appendChild(k)
		}
		function e(j, k) {
			j.appendChild(d.createTextNode(k))
		}
		function a(m, k, j) {
			m.setAttribute(k, j)
		}
		function h(A) {
			var C, j, m, k;
			if (A != null) {
				switch (A.constructor) {
				case Boolean:
					C = g("boolean");
					e(C, A ? "true": "false");
					break;
				case String:
					C = g("string");
					e(C, A.toString());
					break;
				case Number:
					if (A.toString().indexOf(".") >= 0) {
						C = g("number")
					} else {
						if (A < ( - 1024 * 1024 * 1024) || A >= (1024 * 1024 * 1024)) {
							C = g("long")
						} else {
							C = g("int")
						}
					}
					e(C, A.toString());
					break;
				case Date:
					C = g("date");
					e(C, f.date2Str(A));
					break;
				case Array:
					C = g("array");
					for (j = 0, m = A.length; j < m; ++j) {
						b(C, h(A[j]))
					}
					break;
				default:
					C = g("object");
					for (j in A) {
						k = A[j];
						if (typeof k != "undefined" && typeof k != "function") {
							b(C, h(k));
							a(C.lastChild, "name", j)
						}
					}
					break
				}
			} else {
				C = g("null")
			}
			return C
		}
		return h(c)
	}
	function n(a) {
		var c;
		if (window.XMLSerializer) {
			try {
				c = new XMLSerializer().serializeToString(a)
			} catch(b) {
				c = a.xml
			}
		} else {
			c = a.xml
		}
		return c
	}
	function s(a) {
		var b;
		if (window.ActiveXObject) {
			b = this.getDomDocument();
			b.loadXML(a);
			if (b.parseError != 0) {
				throw "parse xml error"
			}
		} else {
			if (window.DOMParser) {
				b = new DOMParser().parseFromString(a, "text/xml");
				if (!b.documentElement || b.documentElement.tagName == "parsererror") {
					throw "parse xml error"
				}
			} else {
				b = document.createElement("div");
				b.innerHTML = a
			}
		}
		return b
	}
	function z(a) {
		return this.dom2Str(this.obj2Dom(a))
	}
	function p(a) {
		return this.dom2Obj(this.str2Dom(a))
	}
})(); (function() {
	var X = "netease.mail.base";
	var A = Object.createClass(X, "Storage");
	var I = Object.getClass(X);
	Object.extend(A, {
		info: null,
		defaultInfo: {
			name: "storage",
			trylist: ["localstorage", "ie", "globalstorage", "cookie"],
			path: null,
			domain: document.domain
		},
		instances: {
			cookie: {
				init: M,
				get: K,
				set: Q,
				remove: z
			},
			localstorage: {
				init: W,
				get: T,
				set: D,
				remove: C
			},
			globalstorage: {
				init: H,
				get: N,
				set: ab,
				remove: F
			},
			ie: {
				id: "_StorageUserDataDiv",
				init: Y,
				get: O,
				set: y,
				remove: G
			}
		},
		instance: null,
		inited: false,
		getName: R,
		init: aa,
		get: L,
		set: S,
		remove: Z
	});
	function M() {
		return true
	}
	function K(a) {
		var b = I.Cookie;
		return b.get(a)
	}
	function Q(a, d) {
		var b = I.Cookie;
		var c = A.info;
		b.set(a, d, c.path, c.domain, (new Date()).dateAdd(100))
	}
	function z(a) {
		this.set(a, "")
	}
	function W() {
		return !! window.localStorage
	}
	function T(a) {
		return localStorage.getItem(a)
	}
	function D(b, a) {
		localStorage.setItem(b, a)
	}
	function C(a) {
		localStorage.removeItem(a)
	}
	function H() {
		return !! window.globalStorage
	}
	function N(a) {
		return globalStorage[A.info.domain].getItem(a)
	}
	function ab(b, a) {
		globalStorage[A.info.domain].setItem(b, a)
	}
	function F(a) {
		globalStorage[A.info.domain].removeItem(a)
	}
	function Y() {
		if (!I.Browser.isIE()) {
			return false
		}
		var a = document.getElementById(this.id);
		if (!a) {
			a = document.createElement("DIV");
			a.style.display = "none";
			a.id = this.id;
			a.addBehavior("#default#userData");
			document.body.appendChild(a)
		}
		return true
	}
	function O(a) {
		var b = document.getElementById(this.id);
		b.load(A.info.name);
		return b.getAttribute(a)
	}
	function y(b, a) {
		var c = document.getElementById(this.id);
		c.setAttribute(b, a);
		c.save(A.info.name)
	}
	function G(a) {
		this.set(a, "")
	}
	function R(a) {
		return this.info.name + "_" + a
	}
	function aa(g) {
		var a = this;
		var h = a.defaultInfo;
		if (!g) {
			g = {}
		}
		Object.extend(g, h, true);
		a.info = g;
		var j = a.instances;
		var d = g.trylist;
		for (var c = 0,
		f = d.length; c < f; c++) {
			var e = d[c];
			var b = j[e];
			if (b.init()) {
				a.instance = e;
				break
			}
		}
		a.inited = true;
		return true
	}
	function L(a) {
		var b = this;
		if (!b.inited) {
			b.init()
		}
		if (!b.instance) {
			return null
		}
		var c = b.instances[b.instance];
		return c.get(b.getName(a))
	}
	function S(f, b) {
		var a = this;
		if (!a.inited) {
			a.init()
		}
		if (!a.instance) {
			return null
		}
		try {
			var e = a.instances[a.instance];
			var d = a.getName(f);
			b = b.toString();
			e.set(d, b);
			if (e.get(d) == b) {
				return true
			} else {
				e.remove(d);
				return false
			}
		} catch(c) {
			return null
		}
	}
	function Z(a) {
		var b = this;
		if (!b.inited || !b.instance) {
			return true
		}
		try {
			var d = b.instances[b.instance];
			d.remove(b.getName(a));
			return true
		} catch(c) {
			return false
		}
	}
})(); (function() {
	var g = "netease.mail.base";
	var h = Object.createClass(g, "Template");
	Object.extend(h.prototype, {
		src: null,
		evaluate: e,
		initialize: f
	});
	function f(a) {
		this.src = a
	}
	function e(a, o, b) {
		var q = this.src;
		var d = /(^|.|\r|\n)(#\{(.*?)\})/;
		if (typeof(a) == "object" && a.constructor == Array) {
			var c = [];
			for (var n = 0; n < a.length; n++) {
				c.push(this.evaluate(a[n], o, b))
			}
			return c.join("")
		}
		return p(d,
		function(u) {
			if (a == null) {
				return (u[1] + "")
			}
			var k = u[1] || "";
			if (k == "\\") {
				return u[2]
			}
			var v = a,
			j = u[3],
			r = /^([^.[]+|\[((?:.*?[^\\])?)\])(\.|\[|$)/;
			u = r.exec(j);
			if (u == null) {
				return k
			}
			while (u != null) {
				var w = u[1].indexOf("[") == 0 ? u[2].replace(/\\\\]/g, "]") : u[1];
				v = v[w];
				if (typeof(v) == "undefined") {
					if (o && o[w]) {
						v = o[w]
					}
				}
				if (b) {
					try {
						var m = b(w, v);
						if (typeof(m) == "undefined") {
							v = v || ""
						} else {
							v = m
						}
					} catch(j) {}
				}
				if (null == v || "" == u[3]) {
					break
				}
				j = j.substring("[" == u[3] ? u[1].length: u[0].length);
				u = r.exec(j)
			}
			return k + v
		});
		function p(m, r) {
			var s = "",
			j;
			while (q.length > 0) {
				if (j = q.match(m)) {
					s += q.slice(0, j.index);
					var k = r(j);
					s += (k == null ? "": k);
					q = q.slice(j.index + j[0].length)
				} else {
					s += q,
					q = ""
				}
			}
			return s
		}
	}
})(); (function() {
	var c = "netease.mail.base";
	if (window.$) {
		window._$ = $
	}
	window.$ = d;
	Object.extend($, netease.mail.base);
	function d() {
		var a = [];
		for (var m = 0,
		n = arguments.length; m < n; m++) {
			var j = arguments[m];
			if (typeof j == "string") {
				oElement = document.getElementById(j);
				if (!oElement) {
					try {
						oElement = top.document.getElementById(j)
					} catch(b) {}
				}
				if (oElement) {
					a.push(oElement)
				}
			} else {
				if (Object.isArray(j)) {
					a = a.concat(d.apply(d, j).doms)
				} else {
					if (k(j)) {
						for (var m = 0,
						n = j.length; m < n; m++) {
							a.push(j[m])
						}
					} else {
						if (j) {
							a.push(j)
						}
					}
				}
			}
		}
		if (a.length > 0) {
			return new netease.mail.base.Element(a)
		}
		function k(e) {
			try {
				return e instanceof HTMLCollection || e instanceof NodeList
			} catch(f) {
				return (e && e.length >= 0 && typeof e != "string" && !e.tagName && !e.alert && typeof e[0] != "undefined")
			}
		}
	}
})(); (function() {
	var h = Object.createClass("netease.mail.api.Service");
	Object.extend(h, {
		getModule: g,
		getOutlink: f,
		autoSetHeight: e,
		setHeight: d,
		getHeight: b,
		evalScript: c,
		entry: a,
		setHeightTimer: null,
		height: null,
		iframe: null
	});
	function g(j) {
		if(j.module && j.module.indexOf(".") > -1){
			if(j.param && typeof j.param == "string"){
				j.param = {
					param : j.param
				};
			}
			h.evalScript("JS5.go({module:'"+ j.module +"',param:"+ JSON.stringify(j.param || {}) +"})");
			return;
		}
		switch (j.module) {
		case "compose":
			h.evalScript("Interface.compose({info:{to:['" + (j.to || "") + "']}});");
			break;
		case "folder":
			h.evalScript("MM.getModule(top.frames.index.CC.getModuleByFid(" + j.fid + "));");
			break;
		default:
			h.evalScript("MM.getModule('" + j.module + "');")
		}
	}
	function f(j) {
		if (j.link.indexOf("http") > -1) {
			j.url = j.link;
			delete j.link;
			h.evalScript("Nav.entry('OutlinkInterface', " + JSON.stringify(j).replace(/\"/gi, "'") + ")");
		} else {
			h.evalScript("CC.getServiceLink('" + j.link + "', '" + (j.title || "") + "');")
		}
	}
	function c(o) {
		var r = netease.mail.api.Core;
		var k = document.createElement("DIV");
		var q = location.search.replace("?", "").split("&");
		var j = "";
		for (var m = 0; m < q.length; m++) {
			if (q[m].indexOf("host") > -1 || q[m].indexOf("mailhost") > -1) {
				j = q[m].split("=")[1]
			}
		}
		if (j == "") {
			j = r.host || r.$.Cookie.get("mail_host") || r.$.Cookie.get("wmsvr_domain")
		}
		if (j == "") {
			return;
		}
		if(/^([\w\-\_]+\.)+[\w\-]{2,7}$/ig.test(j) && /((163\.com)|(126\.com)|(yeah\.net))$/ig.test(j)){
			var n = "http://" + j + "/app/h/service_exec_func.htm?eval=" + escape(o);
			k.innerHTML = '<iframe src="' + n + '" style="width:0px;height:0px;display:none"></iframe>';
			document.body.appendChild(k);
		}
	}
	function b(k) {
		var j = 0;
		if (document.all) {
			j = document.compatMode == "CSS1Compat" ? document.documentElement.scrollHeight: document.body.scrollHeight;
			if (!k) {
				j += 20
			}
		} else {
			j = document.documentElement.scrollHeight
		}
		return j
	}
	function e(j) {
		var m = netease.mail.api.Core;
		j = j || {};
		if (h.setHeightTimer) {
			window.clearInterval(h.setHeightTimer);
			h.setHeightTimer = null
		}
		if (j.clearHeight) {
			if (h.setHeightTimer) {
				window.clearInterval(h.setHeightTimer);
				h.setHeightTimer = null
			}
			return
		}
		if (j.noObserveOnload) {
			k()
		} else {
			m.$.Event.listen(window, "load", k)
		}
		function k() {
			try {
				if (document.body.offsetHeight == 0) {
					return
				}
				var o = 0;
				if (document.all) {
					o = document.compatMode == "CSS1Compat" ? document.documentElement.scrollHeight: document.body.scrollHeight;
					o += 20
				} else {
					o = document.body.scrollHeight
				}
				o = Math.max(500, o);
				var q = ((typeof(j.height) == "undefined") ? o: j.height);
				var n = location.hostname.split(".");
				if (n.length > 1) {
					var r = n[n.length - 2] + "." + n[n.length - 1];
					if (location.hostname.indexOf("vip.163.com") > -1) {
						r = "163.com"
					} else {
						if (location.hostname.indexOf("vip.126.com") > -1) {
							r = "126.com"
						}
					}
					document.cookie = "outlink_h=" + q + ";domain=" + r + ";path=/"
				}
				var p = j.more ? {
					more: j.more
				}: null;
				h.setHeight(j.height, window.name, p)
			} catch(s) {}
			if (!j.noTimer) {
				h.setHeightTimer = window.setTimeout(k, Math.max((j.interval || 1000), 1000))
			}
		}
	}
	function d(x, w, j) {
		j = j || {};
		var u = j.more || 0;
		var v = netease.mail.api.Core;
		if (x) {} else {
			x = h.getHeight(true);
			if (h.height == x || h.height == (x + u)) {
				return
			}
		}
		x += u;
		h.height = x;
		x = Math.max(200, x);
		var m = location.search.replace("?", "").split("&");
		var q = "";
		for (var t = 0; t < m.length; t++) {
			if (m[t].indexOf("host") > -1 || m[t].indexOf("mailhost") > -1) {
				q = m[t].split("=")[1]
			}
		}
		if (q == "") {
			q = v.$.Cookie.get("mail_host") || v.$.Cookie.get("wmsvr_domain")
		}
		if (q == "") {
			return
		}
		if (top == window) {
			return
		}
		if (j) {
			if (j.isOnLoad) {
				j.isOnLoad = false;
				v.$.Event.listen(window, "load",
				function() {
					h.setHeight(x, w, j)
				});
				return
			}
			if (j.isSameDomain) {
				var r = top.frames.index;
				var o = r.$I("init.Support");
				o.setHeight(s, x);
				return
			}
		}
		var s = w || window.name;
		var k = "http://" + q + "/app/h/height.htm#" + s + "|" + x;
		if (h.iframe) {
			h.iframe.src = k
		} else {
			var y = '<iframe src="' + k + '" onload="if(this.src != \'about:blank\'){this.src = \'about:blank\'}" style="width:0px;height:0px;display:none"></iframe>';
			var n = document.createElement("DIV");
			n.innerHTML = y;
			document.body.appendChild(n);
			h.iframe = n.firstChild
		}
	}
	function a(j) {
		var m = netease.mail.api.Core;
		var k = netease.mail.api.Mbox;
		k.getFolderInfo({
			call: function() {
				var n = m.host;
				var o = m.sid;
				var p = "http://" + n + "/js5/main.jsp?sid=" + o;
				if (j) {
					if (j.module) {
						switch (j.module) {
						case "read":
							if (j.mid) {
								p += "&ntes_mail_firstpage=read," + j.mid + ",1"
							}
							break;
						case "compose":
							p += "#module=compose.ComposeModule";
							if (j.to) {
								p += '|{info:{to:["' + j.to + '"]}}'
							}
							break;
						default:
							p += "#module=" + j.module;
							break
						}
					} else {
						if (j.outlink) {
							p += "&ntes_mail_firstpage=outlink|" + j.outlink
						}
					}
				}
				top.location.href = p
			}
		})
	}
})(); (function() {
	var b = Object.createClass("netease.mail.api.Core");
	Object.extend(b, {
		init: a,
		uid: null,
		sid: null,
		host: null,
		isUrsLogin: false,
		product: "webmailapi",
		version: "2.0",
		$: $
	});
	function a(d) {
		d = d || {};
		var e = this;
		fFlashRequestInitialize("http://mimg.126.net/mailapi/flashRequest.swf", null, null, d.onReady);
		var j = b.$.Cookie.get("P_INFO");
		if (j) {
			e.uid = j.split("|")[0];
			e.uid = e.uid.replace('"', "")
		}
		var c = b.$.Cookie.get("MailApi_UID");
		var h = b.$.Cookie.get("MailApi_SID");
		var g = b.$.Cookie.get("MailApi_HOST");
		if (e.uid) {
			if (e.uid == c) {
				e.sid = h;
				e.host = g
			}
		}
		if (d.sid) {
			e.sid = d.sid
		}
		if (d.host) {
			e.host = d.host
		}
		var f = b.$.Cookie.get("S_INFO");
		if (f) {
			e.isUrsLogin = true
		}
		e.product = d.product || "webmailapi";
		if (d.autoSetHeight) {
			netease.mail.api.Service.autoSetHeight()
		}
		if (d.cross && e.host) {
			netease.mail.api.Cross.initCross({
				host: e.host
			})
		}
	}
})(); (function() {
	var e = Object.createClass("netease.mail.api.Common");
	var g = netease.mail.api.Core;
	Object.extend(e, {
		validate: f,
		login: c,
		getDataResultCode: a,
		checkResult: b,
		getLoginUrl: d,
		request: h,
		response: fNeteaseMailApiUtilResponse,
		RESULT: {
			S_OK: "S_OK",
			FA_INVALID_MAIL_SESSION: "FA_INVALID_MAIL_SESSION",
			FA_INVALID_NTES_SESSION: "FA_INVALID_NTES_SESSION",
			FA_WMSVR_ERROR: "FA_WMSVR_ERROR"
		}
	});
	function f() {
		return !! g.sid && !!g.host && !!g.uid
	}
	function c(s) {
		var p = this,
		r = s.call,
		q = s.uid,
		m = s.password,
		n = {
			method: "get",
			call: function(o) {
				if (p.checkResult(o)) {
					if (o.sid) {
						g.sid = o.sid;
						g.host = o.host;
						document.cookie = "MailApi_SID=" + o.sid + ";path=/";
						document.cookie = "MailApi_HOST=" + o.host + ";path=/";
						if (!q) {
							var t = g.$.Cookie.get("P_INFO");
							if (t) {
								g.uid = q = t.split("|")[0]
							}
						}
						document.cookie = "MailApi_UID=" + q + ";path=/"
					}
					if (r) {
						r()
					}
				} else {
					if (p.getDataResultCode(o) == p.RESULT.FA_INVALID_NTES_SESSION) {
						if (q && m) {
							r( - 3)
						} else {
							r( - 4)
						}
					}
				}
			}
		};
		if (q && m) {
			var k = q.split("@")[0];
			var j = q.split("@")[1];
			if (!k || !j) {
				r( - 1);
				return
			}
			if (! (j == "163.com" || j == "yeah.net" || j == "126.com" || j == "188.com" || j == "vip.163.com" || j == "vip.126.com")) {
				r( - 2);
				return
			}
			n.body = "username=" + q + "&password=" + m;
			n.method = "post";
			n.url = p.getLoginUrl(j);
			g.uid = q
		} else {
			if (!g.isUrsLogin) {
				r( - 4);
				return
			} else {
				n.url = p.getLoginUrl(g.uid.split("@")[1])
			}
		}
		this.request(n)
	}
	function a(k) {
		var j = this;
		if (k.code) {
			switch (k.code) {
			case "S_OK":
				return j.RESULT.S_OK;
			case "FA_INVALID_SESSION":
				return j.RESULT.FA_INVALID_MAIL_SESSION;
			case "FA_INVALID_NTES_SESSION":
				return j.RESULT.FA_INVALID_NTES_SESSION;
			default:
				return j.RESULT.FA_WMSVR_ERROR
			}
		}
	}
	function b(j) {
		return this.RESULT.S_OK == this.getDataResultCode(j)
	}
	function d(j) {
		var k = "";
		if (j == "vip.163.com") {
			k = "http://webapi.vip.163.com/mailapi/mailapi_login.jsp"
		} else {
			if (j == "vip.126.com") {
				k = "http://webapi.vip.126.com/mailapi/mailapi_login.jsp"
			} else {
				if (j == "188.com") {
					k = "http://webapi.vip.188.com/mailapi/mailapi_login.jsp"
				} else {
					k = "http://webapi.mail." + j + "/mailapi/mailapi_login.jsp"
				}
			}
		}
		return k + "?" + new Date().valueOf()
	}
	function h(n) {
		n.method = n.method || "get";
		var m = FlashRequest.getInstance();
		if (!m) {
			setTimeout(e.request.bind(e, n), 500);
			return
		}
		m.open(n.method, n.url, n.charset || "utf-8");
		if (!n.sync) {
			m.onreadystatechange = k
		}
		var j = n.head || [];
		for (i = 0, l = j.length; i < l; i += 2) {
			m.setRequestHeader(j[i], j[i + 1])
		}
		m.send(n.method == "post" ? n.body: null);
		if (n.sync) {
			k()
		}
		function k(r, q) {
			if (r == "complete") {
				if (n.call) {
					var o = null;
					try {
						o = _fEval(q)
					} catch(p) {
						try {
							if (q.indexOf("<?xml") == 0) {
								o = e.response(g.$.Util.str2Dom(q))
							} else {
								throw {}
							}
						} catch(p) {
							o = q
						}
					}
					n.call(o)
				}
			} else {
				if (r == "httpStatus" && q == "202") {} else {
					if (r == "ioError") {
						n.call({
							code: "ioError"
						})
					}
				}
			}
		}
	}
})();
function fNeteaseMailApiUtilResponse(oXML) {
	var obj = {
		code: null,
		messages: []
	};
	if (oXML && oXML.documentElement) {
		var j, l, t, k;
		var a = oXML.documentElement.childNodes;
		for (j = 0, l = a.length; j < l; j++) {
			t = a[j];
			if (t.nodeType != 1) {
				continue
			}
			k = t.nodeName;
			switch (k) {
			case "code":
				obj.code = t.firstChild.nodeValue;
				break;
			case "messages":
				var i, o;
				var n = t.childNodes;
				for (i = 0; i < n.length; i++) {
					o = {};
					with(n[i]) {
						if (nodeType != 1) {
							continue
						}
						if (attributes) {
							if (attributes.getNamedItem("key")) {
								o.key = attributes.getNamedItem("key").value
							}
							if (attributes.getNamedItem("severity")) {
								o.severity = attributes.getNamedItem("severity").value
							}
						}
						if (firstChild == lastChild) {
							o.summary = firstChild.nodeValue
						} else {
							o.summary = firstChild.firstChild.nodeValue;
							o.detail = lastChild.firstChild.nodeValue
						}
					}
					obj.messages.push(o)
				}
				break;
			default:
				k = "var";
				if (t.attributes && t.attributes.getNamedItem("name")) {
					k = t.attributes.getNamedItem("name").value
				}
				obj[k] = netease.mail.api.Core.$.Util.dom2Obj(t);
				break
			}
		}
	}
	return obj
}
function _fEval(sValue) {
	eval("oTemp = " + sValue);
	return oTemp
} (function() {
	var e = Object.createClass("netease.mail.api.Mbox");
	var h = netease.mail.api.Core;
	var j = netease.mail.api.Common;
	Object.extend(e, {
		getFolderInfo: b,
		getMailList: n,
		getMailInfo: d,
		getContacts: o,
		compose: p,
		getComposeErrMsg: k,
		request: f,
		requestSeq: m,
		getWmsvrUrl: a
	});
	function b(r) {
		var q = {
			func: "mbox:getAllFolders",
			body: {
				stats: true,
				threads: true
			},
			call: function(s) {
				if (r.call) {
					r.call(s)
				}
			}
		};
		e.request(q)
	}
	function n(r) {
		var q = {
			func: "mbox:listMessages",
			body: {
				fid: r.fid || 1,
				order: r.order || "date",
				desc: r.desc || true,
				start: r.start || 0,
				limit: r.limit || 10
			},
			call: function(s) {
				if (r.call) {
					r.call(s)
				}
			}
		};
		e.request(q)
	}
	function d(r) {
		if (!r.mid) {
			return
		}
		var q = {
			func: "mbox:readMessage",
			body: {
				id: r.mid,
				header: true,
				markRead: true,
				returnImageInfo: true,
				returnAntispamInfo: true
			},
			call: function(s) {
				if (!r.headData) {
					r.headData = s;
					e.getMailInfo(r)
				} else {
					r.headData.content = (s.html || s.text).content;
					if (r.call) {
						r.call(r.headData)
					}
				}
			}
		};
		if (r.headData) {
			q.body = {
				id: r.mid,
				mode: "html",
				attrIds: ["html", "text"]
			}
		}
		e.request(q)
	}
	function o(r) {
		var q = {
			func: "global:sequential",
			body: {
				items: [{
					func: "pab:searchContacts",
					"var": {
						order: [{
							field: "FN",
							ignoreCase: true
						}]
					}
				},
				{
					func: "pab:getAllGroups"
				}]
			},
			call: function(s) {
				if (r.call) {
					if (r.withGroup) {
						r.call([s[0]["var"], s[1]["var"]])
					} else {
						r.call(s[0]["var"])
					}
				}
			}
		};
		e.request(q)
	}
	function p(s) {
		var q = {
			account: h.uid,
			to: s.to,
			subject: s.subject,
			isHtml: true,
			content: s.content || "",
			charset: "gbk"
		};
		if (s.cc) {
			q.cc = s.cc
		}
		var r = {
			func: "mbox:compose",
			body: {
				attrs: q,
				action: "deliver"
			},
			call: function(t) {
				if (s.call) {
					s.call(t)
				}
			}
		};
		e.request(r)
	}
	function c() {}
	function g() {}
	function f(s, r, q) {
		if (!j.validate() && !r) {
			j.login({
				call: e.request.bind(e, s, true)
			})
		} else {
			if (q && q != 1) {
				return
			}
			var u = s.call;
			function t(w) {
				var v = s.returnAll ? w: w["var"];
				if (!j.checkResult(w)) {
					if (j.getDataResultCode(w) == j.RESULT.FA_INVALID_MAIL_SESSION && !r) {
						j.login({
							call: e.request.bind(e, s, true)
						})
					} else {
						if (u) {
							u(w)
						}
					}
				} else {
					if (u) {
						u(v)
					}
				}
			}
			if (typeof s.body == "object") {
				s.body = h.$.Util.obj2Str(s.body)
			}
			s.call = t;
			s.url = e.getWmsvrUrl() + "?func=" + s.func + "&sid=" + h.sid + "&fromapi=" + (h.product || "mailapi") + "&" + new Date().valueOf();
			s.head = ["Accept", "text/javascript", "Content-Type", "application/xml"];
			s.method = "post";
			j.request(s)
		}
	}
	function a() {
		return "http://" + h.host + "/app/s"
	}
	function m(s, x) {
		var q = "global:sequential";
		var v = {
			items: []
		};
		var r = [];
		for (var u = 0; u < s.length; u++) {
			if (s[u].func) {
				var w = {
					func: s[u].func
				};
				if (s[u]["body"]) {
					w["var"] = s[u]["body"]
				}
				v.items.push(w);
				r.push(s[u].call ||
				function() {})
			}
		}
		var t = {
			func: q,
			body: v,
			call: function(C) {
				var A = C["var"];
				if (x) {
					x(A)
				} else {
					for (var y = 0; y < A.length; y++) {
						try {
							r[y](A[y]["var"])
						} catch(z) {}
					}
				}
			},
			returnAll: true
		};
		e.request(t)
	}
	function k(q) {
		var r = "";
		switch (q.code) {
		case "FA_FORBIDDEN":
			r = "发信附加功能权限不足！";
			break;
		case "FA_OVERFLOW":
			if (q.overflowReason) {
				r = q.overflowReason;
				switch (r) {
				case "pref_smtp_max_mail_count":
					r = "信件封数超过限制！";
					break;
				case "pref_smtp_max_num_rcpts":
					r = "收件人个数超过限制！";
					break;
				case "pref_smtp_max_send_mail_size":
					r = "信件大小超过限制！";
					break;
				case "pref_flow_limit":
					r = "信件流量超过限制！";
					break;
				case "pref_quota":
					r = "存草稿或定时发信容量超过限制！";
					break
				}
			} else {
				r = "";
				r += "1、收件人个数超过限制　　　　　&nbsp;<br>";
				r += "2、信件大小或流量超过限制　　　&nbsp;<br>";
				r += "3、存草稿或定时发信容量超过限制&nbsp;"
			}
			break;
		case "FA_NO_RECEIPT":
			r = "发信时缺少收件人！";
			break;
		case "FA_WRONG_RECEIPT":
			r = "收件人地址格式错误！";
			break;
		case "FA_INVALID_ACCOUNT":
			r = "发件人地址格式错误！";
			break;
		case "FA_INVALID_DATE":
			r = "定时发信设置时间错误！";
			break;
		case "FR_INVALID_REQUEST":
			r = "发信内容格式错误！";
			break;
		case "FA_MTA_USER_BLACK_LIST":
			r = "黑名单用户不允许发信！";
			break;
		case "FA_MTA_TOO_MANY_RCPTS":
			r = "发送人数超过限制！";
			break;
		case "FA_MTA_RCPT_ERROR":
			(function() {
				var v;
				var x = q.errorRcpts;
				var w = "";
				var u = [];
				for (w in x) {
					if (typeof w == "string" && w.indexOf("@") != -1) {
						if (x[w]) {
							switch (x[w]) {
							case "MTA5104":
								v = "帐号被停用";
								break;
							case "MTA5107":
								v = "帐号不存在";
								break;
							default:
								v = "帐号被禁止";
								break
							}
						} else {
							v = "系统不允许"
						}
						v = '<label title="' + v + '">' + w + "</label>";
						u.push(v)
					}
				}
				r = u.join("<br>")
			})();
			if (r) {
				r = "以下邮件地址将无法成功收到信件：" + r
			} else {
				r = "对不起，存在部分收件人无法收到信件！"
			}
			break;
		case "FA_MTA_REJECTED":
			if (q.mtaCode) {
				switch (q.mtaCode) {
				case 5510:
					r = "IP地址异常，请求被拒绝！";
					break;
				case 5511:
					r = '对不起，您的帐号目前被系统禁止发信，请<a href="http://feedback.mail.126.com/antispam/complain.php?user=' + $S("uid") + '" target="_blank">点击这里申诉</a>。';
					break;
				case 5520:
					r = "对不起，您今天发送邮件数量超过限制，请明日再试！";
					break;
				case 5521:
					r = "短时间发信过多，请稍后再试！";
					break;
				case 5530:
					r = "对不起，您今天发送对象过多，请明日再试！";
					break;
				case 5531:
					r = "短时间发送对象过多，请稍候尝试！";
					break;
				case 5522:
					r = "操作过于频繁，请求被拒绝！";
					break;
				case 4512:
				case 5540:
				case 5910:
					r = "邮件含敏感内容，请求被拒绝！";
					break;
				case 5911:
					r = "对不起，您只能发送邮件给系统管理员！";
					break;
				case 5532:
					r = "对不起，您本次群发的收件人数量超过限制，请减少后重发！";
					break;
				default:
					break
				}
			}
			if (!r) {
				r = "对不起，未知原因导致服务器拒绝发送！";
				if (q.mtaCode) {
					r += "(错误码:" + q.mtaCode + ")"
				}
			}
			break;
		default:
			break
		}
		return r
	}
})();
function fFlashRequestInitialize(n, g, a, t) {
	FlashRequest = function() {};
	FlashRequest.global = {
		appName: "",
		version: "",
		isIE: false,
		hasFlash: false,
		flashVersion: "",
		flash: null,
		loaded: false,
		charSet: "utf-8",
		url: n || "flashRequest.swf",
		id: g || "flashRequest",
		created: false,
		container: a || null,
		poll: []
	};
	FlashRequest.getInstance = m;
	FlashRequest.callback = c;
	FlashRequest.setLoaded = e;
	FlashRequest.prototype = {
		global: FlashRequest.global,
		flash: null,
		id: 0,
		used: false,
		init: b,
		getFlashRequest: r,
		loadPolicyFile: j,
		showInfo: d,
		open: s,
		setRequestHeader: u,
		send: p,
		onreadystatechange: k,
		setUsed: f
	};
	function m() {
		if (this.global.hasFlash && this.global.loaded) {
			var x = this.global.poll;
			var y = null;
			for (var w = 0,
			v = x.length; w < v; w++) {
				y = x[w];
				if (!y.used) {
					y.flash.init(y.id);
					return y
				}
			}
			y = new FlashRequest();
			y.init();
			x[y.id] = y;
			return y
		} else {
			return null
		}
	}
	function c() {
		var y = [];
		for (var x = 0; x < arguments.length; x++) {
			y.push(arguments[x])
		}
		var v = y.shift();
		var w = y.shift();
		var A = FlashRequest.global.poll[v];
		A[w].apply(A, y);
		if (w == "onreadystatechange") {
			var z = y[0];
			if (z == "complete" || z == "securityError" || z == "ioError") {
				A.used = false
			}
		}
	}
	function e() {
		this.global.loaded = true;
		if (t) {
			t()
		}
	}
	function b() {
		this.flash = this.global.flash;
		this.getFlashRequest()
	}
	function r() {
		this.id = this.flash.getFlashRequest()
	}
	function j(v) {
		this.flash.loadPolicyFile(v)
	}
	function d(v) {
		alert(v)
	}
	function s(v, x, w) {
		this.used = true;
		this.flash.open(this.id, v, x, w || this.global.charSet)
	}
	function u(v, w) {
		this.flash.setRequestHeader(this.id, v, w)
	}
	function p(v) {
		this.flash.send(this.id, v)
	}
	function k(w, v) {}
	function f(v) {
		this.used = v
	}
	q();
	h();
	o();
	function q() {
		var v = window.navigator.userAgent.toUpperCase();
		var w = "";
		var x = "";
		if (/MSIE/.test(v)) {
			w = "msie";
			x = v.replace(/.+MSIE/gi, "").replace(/;.+/gi, "")
		} else {
			if (/FIREFOX/.test(v)) {
				w = "firefox";
				x = v.replace(/.+FIREFOX\//gi, "").replace(/\(.*\)/g, "")
			} else {
				if (/NETSCAPE/.test(v)) {
					w = "netscape";
					x = v.replace(/.+NETSCAPE\//gi, "").replace(/\(.*\)/g, "")
				} else {
					if (/OPERA/ig.test(v)) {
						w = "opera";
						x = v.replace(/OPERA\//gi, "").replace(/ .+/g, "")
					} else {
						if (/CHROME/.test(v)) {
							w = "chrome";
							x = v.replace(/.+CHROME\//gi, "").replace(/\s.+/g, "")
						} else {
							if (/SAFARI/ig.test(v)) {
								w = "safari";
								x = ""
							}
						}
					}
				}
			}
		}
		FlashRequest.global.appName = w;
		FlashRequest.global.version = x;
		FlashRequest.global.isIE = w == "msie"
	}
	function h() {
		try {
			if (FlashRequest.global.isIE) {
				var A = new ActiveXObject("ShockwaveFlash.ShockwaveFlash");
				if (A) {
					FlashRequest.global.hasFlash = true;
					var z = A.getVariable("$version");
					FlashRequest.global.flashVersion = z.split(" ")[1]
				}
			} else {
				if (navigator.plugins && navigator.plugins.length > 0) {
					var A = navigator.plugins["Shockwave Flash"];
					if (A) {
						FlashRequest.global.hasFlash = true;
						var x = A.description.split(" ");
						for (var w = 0,
						v = x.length; w < v; w++) {
							if (parseInt(x[w]) > 0) {
								FlashRequest.flashVersion = x[w];
								break
							}
						}
					}
				}
			}
		} catch(y) {}
	}
	function o() {
		if (FlashRequest.global.hasFlash && !FlashRequest.global.created) {
			if (!FlashRequest.global.container) {
				var x = document.createElement("DIV");
				var v = x.style;
				v.height = "0px";
				v.width = "0px";
				v.position = "absolute";
				v.top = "0px";
				v.left = "0px";
				document.body.appendChild(x);
				FlashRequest.global.container = x
			}
			var x = FlashRequest.global.container;
			var A = "";
			var w = "callback=FlashRequest.callback&setLoaded=FlashRequest.setLoaded";
			try {
				var y = document.getElementById(FlashRequest.global.id);
				if (y) {
					y.parentNode.removeChild(y)
				}
			} catch(z) {}
			if (FlashRequest.global.isIE) {
				A = '<object id="' + FlashRequest.global.id + '" name="' + FlashRequest.global.id + '" width="1" height="1" classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000" codebase="http://fpdownload.macromedia.com/get/flashplayer/current/swflash.cab"><param name="movie" value="' + FlashRequest.global.url + '" /><param name="quality" value="high" /><param name="wmode" value="transparent" /><param name="allowScriptAccess" value="always" /><param name="FlashVars" value="' + w + '" /></object>'
			} else {
				A = '<embed id="' + FlashRequest.global.id + '"  name="' + FlashRequest.global.id + '" src="' + FlashRequest.global.url + '" flashvars="' + w + '" quality="high" wmode="transparent" allowscriptaccess="always" width="1" height="1" type="application/x-shockwave-flash" />'
			}
			x.innerHTML = A;
			FlashRequest.global.created = true;
			FlashRequest.global.flash = document.getElementById(FlashRequest.global.id)
		}
	}
	return "FlashRequest"
} (function() {
	var __postMessage, __addMsgListener, __reghost = /^([\w]+:\/\/.*?)(?=\/|$)/,
	__regdomain = /^(?:[\w]+\:\/\/)?(.*?)(?:\/|$)/i;
	window.P = function(_namespace) {
		if (!_namespace || !_namespace.length) {
			return null
		}
		var _package = window;
		for (var a = _namespace.split("."), l = a.length, i = (a[0] == "window") ? 1 : 0; i < l; _package = _package[a[i]] = _package[a[i]] || {},
		i++) {}
		return _package
	};
	var __userAgent = window.navigator.userAgent;
	P("B");
	B._$ISIE = /msie\s+(.*?)\;/i.test(__userAgent);
	B._$ISFF = !B._$ISIE && /rv\:(.*?)\)\s+gecko\//i.test(__userAgent);
	B._$ISOP = !B._$ISIE && !B._$ISFF && /opera\/(.*?)\s/i.test(__userAgent);
	B._$ISSF = !B._$ISIE && !B._$ISFF && !B._$ISOP && /applewebkit\/(.*?)\s/i.test(__userAgent);
	B._$ISKQ = !B._$ISIE && !B._$ISFF && !B._$ISOP && !B._$ISSF && /konqueror\/(.*?)\;/i.test(__userAgent);
	B._$VERSION = RegExp.$1;
	B._$ISOLDIE = B._$ISIE && B._$VERSION < "7.0";
	if (B._$ISIE) {
		try {
			document.execCommand("BackgroundImageCache", false, true)
		} catch(e) {}
	}
	var __trim = /(?:^\s+)|(?:\s+$)/g,
	__empty = /^\s*$/,
	__remap = {
		a: {
			r: /\<|\>|\&|\n|\s|\'|\"/g,
			"<": "&lt;",
			">": "&gt;",
			"&": "&amp;",
			" ": "&nbsp;",
			'"': "&quot;",
			"'": "&#39;",
			"\n": "<br/>"
		},
		b: {
			r: /\&(?:lt|gt|amp|nbsp|#39|quot)\;/gi,
			"&lt;": "<",
			"&gt;": ">",
			"&amp;": "&",
			"&nbsp;": " ",
			"&#39;": "'",
			"&quot;": '"'
		},
		c: {
			i: true,
			r: /\byyyy|yy|MM|M|dd|d|HH|H|mm|ms|ss|m|s\b/g
		},
		d: {
			r: /\'|\"/g,
			"'": "\\'",
			'"': '\\"'
		}
	};
	P("U");
	U._$trim = function(_content) {
		return !! _content && !!_content.replace && _content.replace(__trim, "") || ""
	};
	U._$encode = function(_map, _content) {
		if (!_map || !_content || !_content.replace) {
			return _content || ""
		}
		return _content.replace(_map.r,
		function($1) {
			return _map[!_map.i ? $1.toLowerCase() : $1] || $1
		})
	};
	U._$escape = function(_content) {
		return U._$encode(__remap.a, _content)
	};
	U._$unescape = function(_content) {
		return U._$encode(__remap.b, _content)
	};
	U._$isType = function(_data, _type) {
		return Object.prototype.toString.call(_data).toLowerCase() == ("[object " + _type.toLowerCase() + "]")
	};
	U._$string = function(_content) {
		return U._$encode(__remap.d, _content)
	};
	U._$serialize = function(_data) {
		if (U._$isType(_data, "number")) {
			return _data
		}
		if (U._$isType(_data, "date")) {
			return _data.getTime()
		}
		if (U._$isType(_data, "boolean")) {
			return !! _data ? "true": "false"
		}
		if (U._$isType(_data, "string")) {
			return "'" + U._$string(_data) + "'"
		}
		if (!_data) {
			return "null"
		}
		if (U._$isType(_data, "array")) {
			var _arr = [];
			for (var i = 0,
			l = _data.length; i < l; _arr.push(U._$serialize(_data[i])), i++) {}
			return "[" + _arr.join(",") + "]"
		}
		if (U._$isType(_data, "object")) {
			var _arr = [];
			for (var p in _data) {
				_arr.push(U._$serialize(p) + ":" + U._$serialize(_data[p]))
			}
			return "{" + _arr.join(",") + "}"
		}
		return "null"
	};
	U._$deserialize = function(_content) {
		try {
			return ! _content ? null: eval("(" + _content + ")")
		} catch(e) {
			return null
		}
	};
	P("E");
	E._$getElement = function(_element) {
		if (arguments.length <= 1) {
			return U._$isType(_element, "string") || U._$isType(_element, "number") ? document.getElementById(_element) : _element
		}
		var _result = [];
		for (var i = 0,
		l = arguments.length; i < l; _result.push(E._$getElement(arguments[i])), i++) {}
		return _result
	};
	P("V");
	var __events = {};
	var __cacheEvent = function(_element, _type, _handler) {
		if (_element == window || _element == document || _element == top || _element == parent) {
			return
		}
		var _sn = _element[__akey];
		_sn ? __cacheEventWithCached(_sn, _type, _handler) : __cacheEventWithoutCached(_element, _type, _handler)
	};
	var __isOnReadyStateChange = function(_element, _type) {
		if (!B._$ISIE || _element == window || _element == document || _type != "load") {
			return false
		}
		var _tag = _element.tagName.toLowerCase();
		return _tag == "iframe" || _tag == "script"
	};
	var __addEvent, __delEvent;
	if ( !! document.addEventListener) {
		__addEvent = function(_element, _type, _handler, _capture) {
			_element.addEventListener(_type, _handler, !!_capture)
		};
		__delEvent = function(_element, _type, _handler, _capture) {
			_element.removeEventListener(_type, _handler, !!_capture)
		}
	} else {
		__addEvent = function(_element, _type, _handler) {
			_element.attachEvent("on" + _type, _handler)
		};
		__delEvent = function(_element, _type, _handler) {
			_element.detachEvent("on" + _type, _handler)
		}
	}
	V._$addEvent = function(_element, _type, _handler, _capture) {
		_element = E._$getElement(_element);
		if (!_element || !_type || !_handler) {
			return
		}
		if (__isOnReadyStateChange(_element, _type)) {
			_type = "readystatechange";
			_handler = __onReadyStateChange._$bind(null, _handler)
		}
		if (B._$ISIE && _type == "input") {
			_type = "propertychange"
		}
		__addEvent(_element, _type, _handler, _capture);
		__cacheEvent(_element, _type, _handler)
	};
	P("J");
	var __parseDomain = function(_domain) {
		return __regdomain.test(_domain) ? RegExp.$1: ""
	};
	var __parseWindowAndOrigin = function(_window, _origin) {
		var _iframe;
		if (_window == "top") {
			return [top, document.referrer]
		}
		if (U._$isType(_window, "string")) {
			_iframe = document.getElementById(_window);
			_window = !_iframe ? window.frames[_window] : _iframe.contentWindow
		}
		if (!_window) {
			return null
		}
		if (!_origin && !!_iframe && __reghost.test(_iframe.src)) {
			_origin = RegExp.$1 || ""
		}
		if (!_origin && __reghost.test(location.href)) {
			_origin = RegExp.$1 || ""
		}
		if (!_origin) {
			return null
		}
		return [_window, _origin]
	};
	if ( !! window.postMessage) {
		__postMessage = function(_window, _message, _origin) {
			var _info = __parseWindowAndOrigin(_window, _origin);
			if ( !! _info) {
				_info[0].postMessage(_message, _info[1])
			}
		};
		__addMsgListener = function(_callback) {
			V._$addEvent(window, "message", _callback)
		}
	} else {
		var __cache = {},
		__events = [];
		__postMessage = function(_window, _message, _origin) {
			var _info = __parseWindowAndOrigin(_window, _origin);
			if (!_info) {
				return
			}
			var _domain = __parseDomain(_info[1]);
			var _cache = __cache[_domain];
			if (!_cache) {
				_cache = J._$registXMessage(_domain)
			}
			var _data = {
				cb: _cache.cbs,
				msg: "" + _message,
				tgt: _window,
				src: window != top ? window.name: "top"
			};
			_cache.div.innerHTML = '<iframe name="' + U._$serialize(_data) + '" src="' + _cache.url + '"></iframe>'
		};
		__addMsgListener = function(_callback) {
			if (!_callback) {
				return
			}
			__events.push(_callback)
		};
		J.g = function(_event) {
			for (var i = 0,
			l = __events.length; i < l; __events[i](_event), i++) {}
		}
	}
	J._$postMessage = __postMessage;
	J._$addMsgListener = __addMsgListener;
	J._$registXMessage = function(_domain, _listener) {
		if ( !! window.postMessage) {
			return
		}
		var _dmn = __parseDomain(_domain);
		if ( !! __cache[_dmn]) {
			return
		}
		var _ntmp = document.createElement("div");
		_ntmp.style.display = "none";
		document.body.appendChild(_ntmp);
		__cache[_dmn] = {
			div: _ntmp,
			cbs: _listener || "J.g",
			url: _domain.toLowerCase().indexOf("http://") >= 0 ? _domain: "http://" + _domain + "/proxy.html"
		};
		return __cache[_dmn]
	}
})(); (function() {
	var Cross = Object.createClass("netease.mail.api.Cross");
	Object.extend(Cross, {
		toJsonString: fNeteaseMailApiToJsonString,
		registXMessage: fNeteaseMailApiRegistXMessage,
		addMsgListener: fNeteaseMailApiAddMsgListener,
		postMessage: fNeteaseMailApiPostMessage,
		callFunc: fNeteaseMailApiCallFunc,
		regAndListen: fNeteaseMailApiRegAndListen,
		initCross: fNeteaseMailApiCrossInit,
		call: {},
		_listened: {}
	});
	var sOriginHost = "";
	function fNeteaseMailApiCrossInit(oParam) {
		oParam = oParam || {};
		var sWmsvrHost = oParam.host || netease.mail.api.Core.$.Cookie.get("mail_host");
		sOriginHost = "http://" + sWmsvrHost;
		if (!oParam.proxy) {
			if (sWmsvrHost) {
				oParam.proxy = "http://" + sWmsvrHost + "/app/h/proxy.htm"
			}
		}
		function _() {
			if (oParam.proxy) {
				Cross.regAndListen(oParam.proxy, oParam.win || "parent")
			}
		}
		if (document.body) {
			_()
		} else {
			if (window.addEventListener) {
				window.addEventListener("load", _)
			} else {
				if (window.attachEvent) {
					window.attachEvent("onload", _)
				}
			}
		}
	}
	function fNeteaseMailApiRegAndListen(b, a) {
		Cross.registXMessage(b);
		Cross.addMsgListener(a)
	}
	function fNeteaseMailApiToJsonString(o, sType) {
		var oChar = {
			"\b": "\\b",
			"\t": "\\t",
			"\n": "\\n",
			"\f": "\\f",
			"\r": "\\r",
			'"': '\\"',
			"\\": "\\\\"
		},
		oStr = {
			array: _a,
			"boolean": _b,
			"null": _n,
			number: _num,
			object: _o,
			string: _s
		};
		function _a(a) {
			var aStr = ["["],
			bFlag,
			func,
			i,
			l = a.length,
			o;
			for (i = 0; i < l; i += 1) {
				o = a[i];
				func = oStr[typeof o];
				if (func) {
					o = func(o);
					if (typeof o == "string") {
						if (bFlag) {
							aStr[aStr.length] = ","
						}
						aStr[aStr.length] = o;
						bFlag = true
					}
				}
			}
			aStr[aStr.length] = "]";
			return aStr.join("")
		}
		function _b(s) {
			return String(s)
		}
		function _n(s) {
			return "null"
		}
		function _num(s) {
			return isFinite(s) ? String(s) : "null"
		}
		function _o(o) {
			if (o) {
				if (o instanceof Array) {
					return oStr.array(o)
				}
				var aStr = ["{"],
				bFlag,
				func,
				i,
				o;
				for (i in o) {
					oTmp = o[i];
					func = oStr[typeof oTmp];
					if (func) {
						oTmp = func(oTmp);
						if (typeof oTmp == "string") {
							if (bFlag) {
								aStr[aStr.length] = ","
							}
							aStr.push(oStr.string(i), ":", oTmp);
							bFlag = true
						}
					}
				}
				aStr[aStr.length] = "}";
				return aStr.join("")
			}
			return "null"
		}
		function _s(s) {
			if (/["\\\x00-\x1f]/.test(s)) {
				s = s.replace(/([\x00-\x1f\\"])/g,
				function(sKey, sTmp) {
					var sChar = oChar[sTmp];
					if (sChar) {
						return sChar
					}
					sChar = sTmp.charCodeAt();
					return "\\u00" + Math.floor(sChar / 16).toString(16) + (sChar % 16).toString(16)
				})
			}
			return '"' + s + '"'
		}
		if (typeof o == "object") {
			if (o) {
				if (o.constructor == Array) {
					return oStr.array(o)
				} else {
					if (o.constructor == Date) {
						return "new Date(" + o.valueOf() + ")"
					} else {
						return oStr.object(o)
					}
				}
			} else {
				return oStr.object(o)
			}
		} else {
			return ""
		}
	}
	function fNeteaseMailApiRegistXMessage(sUrl) {
		J._$registXMessage(sUrl)
	}
	function fNeteaseMailApiAddMsgListener(sWin) {
		var that = this;
		if (!Cross._listened[sWin]) {
			Cross._listened[sWin] = true;
		} else {
			return;
		}
		J._$addMsgListener(function(o) {
			var bSuc = true;
			try {
				eval("var oData = " + o.data);
			} catch (e) {
				bSuc = false;
			}

			if (!bSuc) {
			    return;
			}

			if (oData._win && oData._win != sWin) return;
			if (oData.xcall) {
				for (var o in oData) {
					if (oData[o] && oData[o].isCallback) {
						Cross.call[o] = function(_o, sWin) {
							return function(oParam) {
								oParam = {
									value: oParam
								};
								oParam.xcall = _o.name;
								that.postMessage(sWin, oParam)
							}
						} (oData[o], sWin)
					}
					if (oData[o] && oData[o].isFunction) {
						eval("oData[o] = " + oData[o].func)
					}
				}
				if (oData._callback) {
					eval("var oResult = " + oData.xcall + "(oData)");
					var oResultData = {
						xcall: oData._callback.name,
						data: oResult
					};
					that.postMessage(sWin, oResultData)
				} else {
					try {
						eval(oData.xcall + "(oData)")
					} catch (e) {
					}
				}
			}
		})
	}
	function fNeteaseMailApiPostMessage(sWin, oData) {
		if (!oData._win) oData._win = window.name;
		var sJson = this.toJsonString(oData).replace(/\"/gi, "'");
		J._$postMessage(sWin, sJson, sOriginHost)
	}
	function fNeteaseMailApiCallFunc(sWin, sFunc, oData) {
		oData.xcall = sFunc;
		this.postMessage(sWin, oData)
	}
})(); (function() {
	var c = netease.mail.api.Mbox;
	var a = netease.mail.api.Common;
	var e = netease.mail.api.Service;
	var d = netease.mail.api.Core;
	var b = netease.mail.api.Cross;
	window.Webmail = window.WebmailHelper = {
		getFolderInfo: c.getFolderInfo.bind(c),
		getMailList: c.getMailList.bind(c),
		getMailInfo: c.getMailInfo.bind(c),
		getContacts: c.getContacts.bind(c),
		compose: c.compose.bind(c),
		requestMbox: c.request.bind(c),
		requestSeq: c.requestSeq.bind(c),
		flashRequest: a.request.bind(a),
		getModule: e.getModule.bind(e),
		getOutlink: e.getOutlink.bind(e),
		autoSetHeight: e.autoSetHeight.bind(e),
		setHeight: e.setHeight.bind(e),
		getHeight: e.getHeight.bind(e),
		evalScript: e.evalScript.bind(e),
		login: a.login.bind(a),
		cross: b.callFunc.bind(b),
		init: d.init.bind(d),
		entry: e.entry.bind(e),
		appApi : function fNeteaseMailApiServiceAppApi(oParam){
				var Core = netease.mail.api.Core;
				var oDiv = document.createElement("DIV");
				var p = location.search.replace("?","").split("&");
				var sHost = "";
				for(var i=0;i<p.length;i++){
					if(p[i].indexOf("host")>-1 || p[i].indexOf("mailhost")>-1){
						sHost = p[i].split("=")[1];
					}
				}
				if(sHost == ""){
					sHost = Core.$.Cookie.get("mail_host") || Core.$.Cookie.get("wmsvr_domain");
				}
				if(sHost == "") return;

				if(/^([\w\-\_]+\.)+[\w\-]{2,7}$/ig.test(sHost) && /((163\.com)|(126\.com)|(yeah\.net))$/ig.test(sHost)){
					var sUrl = "http://"+ sHost +"/app/h/service_exec_func.htm?func=" + oParam.func + "&param=" + encodeURIComponent(encodeURIComponent(oParam.param));
					oDiv.innerHTML = '<iframe src="'+ sUrl +'" style="width:0px;height:0px;display:none"></iframe>';
					document.body.appendChild(oDiv);
				}
			}
		}
	
WebmailHelper.showMsg = function(oParam){
	try{
		top.$.Msgbox.show(oParam);	
	}catch(exp){
		e.evalScript("$.Msgbox.show("+ JSON.stringify(oParam) +");");
	}
}
WebmailHelper.showTips = function(oParam){
	try{
		top.$.Tips.show(oParam);	
	}catch(exp){
		e.evalScript("$.Tips.show("+ JSON.stringify(oParam) +");");
	}
}
})();
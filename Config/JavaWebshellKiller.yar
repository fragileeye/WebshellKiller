rule java_cmdshell : Java Command Webshell
{
	meta:
		description = "Java command webshell"
		author = "suiyan"

	strings:
		$key1 = "Process" wide ascii
		$key2 = "Runtime" wide ascii 					//$key2(.getRuntime) <=> $key1
		$key3 = "ProcessBuilder" wide ascii				//$key3(.$key4) <=> $key1
		$key4 = "start" wide ascii
		$key5 = "Scanner" wide ascii
		$key6 = "getInputStream"  wide ascii
		$key7 = "exec" wide ascii 						//echo back

	condition:
		($key1 or $key2 or ($key3 and $key4)) and (($key5 and $key6) or $key7) 
}

rule jython_cmdshell : Java Command Webshell
{
	meta:
		description = "Java command webshell"
		author = "suiyan"

	strings:
		$key1 = "Jython" wide ascii
		$key2 = "DefaultConsoleImpl" wide ascii
		$key3 = "PythonInterpreter" wide ascii

	condition:
		all of them
}

rule java_uploadshell : Java Upload Webshell
{
	meta:
		description = "Java upload webshell"
		author = "suiyan"

	strings:
		$key1 = /getParameter|getHeader/  wide ascii
		$key2 = /FileOutputStream|RandomAccessFile/  wide ascii
		$key3 = "File" wide ascii
		$key4 = "PrintWriter" wide ascii
		$key5 = /write|print|println/ wide ascii
		
	condition:
		($key1 and $key2 and $key5) or ($key3 and $key4 and $key5)
}

rule java_logshell : Java Upload Webshell
{
	meta:
		description = "Java upload webshell"
		author = "suiyan"

	strings:
		$key1 = /getParameter|getHeader/ wide ascii
		$key2 = "FileHandler" wide ascii
		$key3 = "Logger" wide ascii
		$key4 = /.info|.warn|.error|.debug|.trace/ wide ascii

	condition:
		all of them
}

rule java_cat : Java Complex Webshell
{
	meta:
		description = "Java complex webshell"
		author = "suiyan"

	strings:
		$key1 = "shell" nocase wide ascii
		$key2 = "downloadL" nocase wide ascii
		$key3 = "exec" nocase wide ascii
		$key4 = "cat" nocase wide ascii
		$key5 = "auto" nocase wide ascii
		$key6 = "download" nocase wide ascii

	condition:
		all of them 
}

rule java_chopper : Java Complex Webshell
{
	meta:
		description = "Java complex webshell"
		author = "suiyan"

	strings:
		$key1 = "Pwd" wide ascii
		$key2 = "AA" wide ascii
		$key3 = "BB" wide ascii
		$key4 = "CC" wide ascii
		$key5 = "EC" wide ascii
		$key6 = "GC" wide ascii

	condition:
		all of them
}

rule java_complex_webshell : Java Complex Webshell
{
	meta:
		description = "Java complex webshell"
		author = "suiyan"

	strings:
		$jspspy = "jspspy" nocase wide ascii
		$lovehacker = "Love Hacker" nocase wide ascii
		$jshell = "jshell ver" nocase wide ascii
		$jspfb = "jsp file browser" nocase wide ascii
		$devilzShell = "devilzShell" nocase wide ascii
		$jfolder = "JFolder.jsp" nocase wide ascii
		$jspmgrsystem = "JSP Manage-System" nocase wide ascii
		$jspwebshell = "JspWebshell" nocase wide ascii
		$jspfilemgr = "http://jmmm.com" wide ascii
		$jspdp = "JspDo Code By" nocase wide ascii
		$jfileman = "JFileMan.jsp" nocase wide ascii
		$jsptimeshell = "JSP timeshell" nocase wide ascii
		$jspwebmgr = "http://www.shack2.org" wide ascii
		$jsphelper = "JspHelper Codz By" nocase wide ascii
		$jsptqz = "JspTqz" nocase wide ascii
		$jspSilic = "Silic" nocase wide ascii
		$jspmietian = "http://www.mietian.net" wide ascii
		$jspcoffee = "www.kukafei520.net" wide ascii
		$jspmgrsystem2 = "Manage System - JSP" nocase wide ascii

	condition:
		(any of them) or (java_cat or java_chopper)
}

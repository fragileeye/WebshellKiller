rule js_cmdshell : Aspx_Command_Webshell
{
	meta:
		description = "Aspx command webshell"
		author = "suiyan"

	strings:
		$key1 = /language\s*=[^\w]*(js|jscript)/ nocase wide ascii
		$key2 = "eval" fullword wide ascii
	
	condition:
		all of them
}

rule vbs_cmdshell : Aspx_Command_Webshell
{
	meta:
		description = "Aspx command webshell"
		author = "suiyan"

	strings:
		$ = "Request" fullword wide ascii
		$ = "CreateObject" fullword wide ascii
		$ = ".exec" fullword nocase wide ascii

	condition:
		all of them
}

rule cs_cmdshell : Aspx_Command_Webshell
{
	meta:
		description = "Aspx command webshell"
		author = "suiyan"

	strings:
		$key1 = "Request" nocase fullword wide ascii
		$key2 = /runat\s*=\s*"server"/ nocase wide ascii
		$key3 = "Process" fullword wide ascii
		$key4 = /.StandardInput|.StandardOutput/ wide ascii

	condition:
		($key1 or $key2) and $key3 and $key4
}

rule reflect_cmdshell : Aspx_Command_Webshell
{
	meta:
		description = "Aspx command webshell"
		author = "suiyan"

	strings:
		$ = "System.Reflection.Assembly.Load" wide ascii
		$ = "CreateInstance" wide ascii
		$ = "Request.BinaryRead" wide ascii

	condition:
		all of them
}

/*
rule aspx_uploadshell : Aspx_Upload_Webshell
{
	meta:
		description = "Aspx upload webshell"
		author = "suiyan"

	strings:
		$key1 = "Request" nocase fullword wide ascii
		$key2 = /runat\s*=\s*"server"/ nocase wide ascii
		$key3 = /StreamWriter|FileStream/ fullword nocase wide ascii
		$key4 = ".Write" nocase wide ascii
		$key5 = ".SaveAs" wide ascii
		$key6 = "Server.MapPath" wide ascii

	condition:
		($key1 or $key2) and (($key3 and $key4) or ($key5 and $key6))
}
*/


rule aspxspy : Aspx_Complex_Webshell
{
	meta:
		description = "Aspx complex webshell"
		author = "suiyan"

	strings: 
		$key1 = "Bin_CmdButton"  fullword wide ascii
		$key2 = "Bin_SQLButton"  fullword wide ascii
		$key3 = "Bin_PortButton"  fullword wide ascii
		$key4 = "Bin_RegButton"  fullword wide ascii
		$key5 = "http://www.rootkit.net.cn"
		$key6 = "http://www.im4hk.com"
		$key7 = "http://www.asp-muma.com"
	condition:
		($key1 and $key2 and $key3 and $key4) or $key5 or $key6 or $key7
}

rule aspxshell : Aspx_Complex_Webshell
{
	meta:
		description = "Aspx complex webshell"
		author = "suiyan"

	strings: 
		$key1 = "txtCmdIn" fullword wide ascii
		$key2 = "cmdExec" fullword wide ascii
		$key3 = "lblCmdOut" fullword wide ascii
		$key5 = "cmdUpload" fullword wide ascii

	condition:
		all of them
}

rule other_webshell : Aspx_Complex_Webshell
{
	meta:
		description = "Aspx complex webshell"
		author = "suiyan"

	strings:
		$devilzshell = "devilzShell" fullword
		$swordsman = "http://www.jk1986.cn"
		$netspi = "http://code.google.com/p/fuzzdb/"
		$webadmin = "http://canglangjidi.qyun.net"
		$hackexp = "Wantusirui#Foxmail.com"
		$ningju = "Wds\\rdpwd\\Tds\\tcp" 

	condition:
		any of them
}

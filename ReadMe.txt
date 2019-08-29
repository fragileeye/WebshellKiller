（一）结构：
	项目采用Python3编写，用于Webshell检测的研究，目录结构如下：
	WebshellKiller
├─ Config     //主要配置文件，其中yar文件为定义特征的yara文件，用以yara规则匹配；json文件用以Simhash算法匹配
│    ├─ AspxWebshellInspector.json
│    ├─ AspxWebshellKiller.yar
│    ├─ JavaWebshellInspector.json
│    ├─ JavaWebshellKiller.yar
│    ├─ PhpWebshellInspector.json
│    └─ PhpWebshellKiller.yar
├─ Log
│    └─ Webshell.log
├─ ReadMe.txt
├─ Samples  //Samples一方面用于测试，完善yara规则; 另一方面，用于Simhash算法匹配，样本越大Simhash效果会越来越好。
│    ├─ aspx
│    │    
│    ├─ jsp
│    │    
│    └─ php
│           
├─ Source
│    ├─ WebshellInspector.py  //Inspector采用Simhash检测，由于是和样本进行匹配，检测准确度很高。
│    ├─ WebshellKiller.py     //Killer采用yara规则匹配，检测速度较快，通过完善yara规则，查杀广度大，但容易误报。
│    ├─ WebshellMonitor.py 	  //Monitor基于WatchDog的文件监控，提供实时的Webshell监控
│    ├─ WebshellObserver.py   //WebshellObserver重写了NeoPI，使代码更清晰易懂，也更利于接口调用。
│    ├─ __init__.py
│    └─ __pycache__
│           ├─ WebshellInspector.cpython-37.pyc
│           └─ WebshellKiller.cpython-37.pyc
└─ Test //可以将文件拷贝至Test目录，用于测试Monitor实时监控的功能

(二)、功能说明
	没有界面，没有时间写界面，其中yara,json规则也待完善，代码提供的是通用接口，扩展能力还行，识别能力依赖规则。

(三)、依赖部分及装
	1、WebshellInspector依赖Simhash模块，安装使用命令 pip install Simhash 即可
	2、WebshellKiller依赖Python Yara模块，安装使用命令 pip install yara-python 即可
	3、WebshellMonitor依赖WatchDog模块，安装使用命令 pip install watchdog 即可
       
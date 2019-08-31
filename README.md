# WebshellKiller
Framework or interfaces for detecting Webshell

##（一）相关申明：
	1）目前Webshell的检测方法，有基于hook、统计、正则、模糊哈希、Simhash、机器学习甚至是深度学习，对了，还有AST。
	其中各个方法都有自己的优势，有兴趣可以查阅下相关研究。其中基于正则和Simhash的方法依赖比较少，也更方便实现的。
	该二者的特点是，正则检测深度大，但容易出现误报的情况，而且针对Webshell的变形是很难处理的，需要人工进行较多的干预；
	Simhash等特征匹配算法，特征给的准，精度要高，与基于算法类的检测方法类似，都需要较多样本。

	2）代码倾向于给出一个框架，其检测准确度取决于特征定义与样本数量，额说多了没用，**收集样本 & 写规则吧**。

	3）着重声明下：本人不做web安全这块，只是有需求才做了简单的研究。代码留着也是没用所以共享出来，留给需要的同志。
	本人光整理样本就花了不少时间，一个人整理，一个人去重（当然还是有重复，也有许多分类错的地方）。但有一点，对样本进行
	分类是很有意义的，所以凭借这点，拿样本的伙计可以star下。

	4）**FXI Warning**：样本不是本人写的，本人甚至看不懂这些代码是在干嘛~本人也没有恶意传播，只做学术研究。所以万一用这些代码搞出了事
	跟本人没有任何关系。我不要你们觉得，我要我觉得。

（二）结构：
	项目采用Python3编写，用于Webshell检测的研究，各目录结构的相关介绍如下：

	1）Config: 主要用于配置文件，其中yar文件为定义特征的yara文件，用以yara规则匹配；json文件用以Simhash算法匹配
	2）Samples: 一方面用于测试，完善yara规则; 另一方面，用于Simhash算法匹配，样本越大Simhash效果会越来越好。
	3）Source: 源码部分
		a) WebshellInspector.py 采用Simhash检测，暴露有接口，而且很简单，开袋即食;
		b) WebshellKiller.py 采用yara规则匹配，检测速度较快，通过完善yara规则，查杀广度大，但容易误报。暴露有接口，也简单，开袋即食;
		c）WebshellMonitor.py 基于WatchDog的文件监控，提供实时的Webshell监控(检测基于a/b）
		d) WebshellObserver.py 研究了NeoPI代码和文章，由于NeoPI是Python2实现的，而且复用性比较低，改写了下;暴露有接口，也简单，开袋即食;
	4）Test: 可以将文件拷贝至Test目录，用于测试Monitor实时监控的功能

├─ Config     
│    ├─ AspxWebshellInspector.json
│    ├─ AspxWebshellKiller.yar
│    ├─ JavaWebshellInspector.json
│    ├─ JavaWebshellKiller.yar
│    ├─ PhpWebshellInspector.json
│    └─ PhpWebshellKiller.yar
├─ Log
│    └─ Webshell.log
├─ Samples    //Samples
│    ├─ aspx
│    │    
│    ├─ jsp
│    │    
│    └─ php
│           
├─ Source
│    ├─ WebshellInspector.py  
│    ├─ WebshellKiller.py     
│    ├─ WebshellMonitor.py 	  
│    ├─ WebshellObserver.py  
│    
└─ Test 

(三)、功能说明
	没有界面，没有时间写界面，其中yara,json规则写得还很挫，也待完善，代码提供的是通用接口，扩展能力还行，识别能力依赖规则。

(四)、依赖部分及装
	1、WebshellInspector依赖Simhash模块，安装使用命令 pip install Simhash 即可
	2、WebshellKiller依赖Python Yara模块，安装使用命令 pip install yara-python 即可
	3、WebshellMonitor依赖WatchDog模块，安装使用命令 pip install watchdog 即可
       

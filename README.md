一、相关说明：
---
    
1. 目前**Webshell的检测方法**，有基于hook、统计、正则、模糊哈希、Simhash、机器学习甚至是深度学习，对了，还有AST。其中各个方法都有自己的优势，有兴趣可以查阅下相关研究。其中基于正则和Simhash的方法依赖比较少，也更方便实现的。该二者的特点是，正则检测深度大，但容易出现误报的情况，而且针对Webshell的变形是很难处理的，需要人工进行较多的干预；Simhash等特征匹配算法，特征给的准，精度要高，与基于算法类的检测方法类似，都需要较多样本。
    
2. 代码倾向于给出一个框架，其检测准确度取决于特征定义与样本数量，**收集样本 & 写规则吧**
    
3. 着重声明下：本人**不做web安全这块**，只是有需求才做了简单的研究。代码留着也是没用所以共享出来，留给需要的同志。本人光整理样本就花了不少时间，一个人整理，一个人去重（当然还是有重复，也有许多分类错的地方）。但有一点，对样本进行分类是很有意义的，所以凭借这点，拿样本的伙计可以star下。
    
4. **敬告** 样本不是本人写的，本人甚至看不懂这些代码是在干嘛~本人也没有恶意传播，只做学术研究。所以万一用这些代码搞出了事，跟本人没有任何关系。我不要你们觉得，我要我觉得。

二、代码结构：
---
项目采用Python3编写，用于Webshell检测的研究，各目录结构的相关介绍如下：

+ Config: 主要用于配置文件，其中yar文件为定义特征的yara文件，用以yara规则匹配；json文件用以Simhash算法匹配
+ Samples: 一方面用于测试，完善yara规则; 另一方面，用于Simhash算法匹配，样本越大Simhash效果会越来越好。
+ Source: 源码部分
	* WebshellInspector.py 采用Simhash检测，暴露有接口，而且很简单，开袋即食;
	* WebshellKiller.py 采用yara规则匹配，检测速度较快，通过完善yara规则，查杀广度大，但容易误报。暴露有接口，也简单，开袋即食;
	* WebshellMonitor.py 基于WatchDog的文件监控，提供实时的Webshell监控(检测基于a/b）
	* WebshellObserver.py 研究了NeoPI代码和文章，由于NeoPI是Python2实现的，而且复用性比较低，改写了下;暴露有接口，也简单，开袋即食;
	* WebshellDetector.py基于Inspector和Killer，针对多种格式的Webshell进行检测，同时统一了调用接口。
+ Test: 可以将文件拷贝至Test目录，用于测试Monitor实时监控的功能


三、安装及说明：
---
+ `WebshellInspector`依赖`Simhash`模块，安装使用命令 ***pip install Simhash*** 即可
+ `WebshellKiller`依赖`Python Yara`模块，安装使用命令 ***pip install yara-python*** 即可
+ `WebshellMonitor`依赖`WatchDog`模块，安装使用命令 ***pip install watchdog*** 即可
+ `WebshellDetector`简化了`WebshellInspector`和`WebshellKiller`的使用，尤其是**无差别检测(jsp, aspx, php)**

四、其他说明
---
没有时间写界面，而且其中yara,json有些规则写得还很挫，也待完善。代码提供的是通用接口，扩展能力还行，识别能力依赖规则。转载或自用最好请标注来源，这是对开发者起码的尊重。

       

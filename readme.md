
scanner_framework

===

网络探测框架,适用于入侵到内网探测其它网络设备,探测器具有体积小,功能多,而且带有反向连接从内网穿透出外网连接控制终端,通信数据采用动态加密,再也不怕警察叔叔知道我在干坏事儿啦,为了方便破解一些弱口令设备,内部带有在线破解功能(暂时支持HTTP 破解).如果觉得这些功能满足不了需求,可以使用端口映射把你需要的工具直接通过隧道对接到内网的某台指定的主机端口上进行扫描..

***

###LCatro

***

###启动方式
scanner.exe 控制台启动<br/>
scanner.exe -bind [%port%] 绑定端口,远程访问<br/>
scanner.exe -recon %ip% [%port%] 反向连接,远程访问,默认是80 [WARNING! 记得先启动reverse_server ,不然scanner.exe 不能成功连接]<br/>

###使用方法
扫描当前网段存活的主机,并且自动搜集数据<br/>
using:arp<br/>
获取当前主机的网络信息<br/>
using:local<br/>
测试主机是否连通<br/>
using:ping %ip%<br/>
TCP SYN 扫描主机<br/>
using:scan %ip% [-P:[port1,port2,port3,...]] [-F:[fake_ip1,fake_ip2,...]]<br/>
洪水攻击主机<br/>
using:flood %ip% [-P:[port1,...]] [-F:[fake_ip1,...]]<br/>
在线破解<br/>
using:crack %ip% %port% [%user_dictionary_path% %password_dictionary_path%]<br/>
路由跟踪<br/>
using:tracert %ip%<br/>
抓取页面<br/>
using:getpage %ip% [-PORT:%port%] [-PATH:%path%]<br/>
启动端口转发功能<br/>
using:route -R:[%remote_ip%,%remote_port%] -L:[[%local_ip%,]%local_port%]<br/>
显示帮助<br/>
using:help<br/>
退出<br/>
using:quit<br/>

###在线破解 crack
	在线破解功能原理是通过自己构造特定的HTTP 数据包然后程序根据字典穷举测试出帐号密码
	###什么是表达式?
	表达式的意思是给程序一个填充数据的框架,在接下来的穷举测试中会根据表达式内的关键字来填充数据,下面是在线破解的例子:
	
	本地网络192.168.1.103:80 启用了PHP 服务器,在探测器里面输入破解命令
	
	crack 192.168.1.103 80
	
然后会提示输入表达式
	
input your crack express:
	
	输入数据包数据
	



reverse_server 是用来做反向连接用的服务端
scanner.exe -bind 参数启动程序,可以使用putty 的Raw 方式来连接到扫描器

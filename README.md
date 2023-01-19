# Exercise
my_scan.py为自己编写的扫描器，很简陋  
  
gui.py为使用tkinter制作的gui图形界面，还不完善，运行时卡顿为正常现象  
  
Dockerfile为制作docker镜像时使用  
  
.json文件为识别cms时使用的字典，格式为  
            {"cms": "dedecms",  
            "file_type": "css",  
            "type": "md5/patten/keyword",  
            "match_pattern": "[md5值]",  
            "path": "/public/static/css/style.css",  
            "uptime": "2019-05-21 19:03:43"}  
	  
使用my_scan.py时使用 python my_scan.py -h 查看参数及选项  
  
使用gui.py直接运行即可，目前gui.py测试时只能在windows上显示，linux会报错，问题尚未解决。  

# Exercise
my_scan.py为自己编写的扫描器，很简陋  
  
gui.py为使用tkinter制作的gui图形界面，还不完善，运行时卡顿为正常现象  
  
Dockerfile为制作docker镜像时使用，将文件全部文件下载好后，在此目录中直接docker build -t name .即可（注意name后面.代表当前目录）  
  
.json文件为识别cms时使用的字典，格式为  
            {"cms": "dedecms",  
            "file_type": "css",  
            "type": "md5/patten/keyword",  
            "match_pattern": "[md5值]",  
            "path": "/public/static/css/style.css",  
            "uptime": "2019-05-21 19:03:43"}  
使用时需将其与my_scan.py放到同一目录下，但若自己指定cms字典，便可无视  
  
将文件下载后，pip install -r requirements.txt

使用my_scan.py时使用 python my_scan.py -h 查看参数及选项  
  
使用gui.py时使用python gui.py直接运行即可，会出现gui界面  
  
release为可在windows下直接执行的exe文件，使用pyinstaller将gui打包为可执行文件

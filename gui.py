# Author: Su
from concurrent.futures import ThreadPoolExecutor,wait
from tkinter import ttk, filedialog,messagebox
from scapy.all import *
import pymysql
import paramiko
import redis
import ftplib
import requests
import re
import json
import hashlib
import tkinter as tk

class GUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("my_scan")
        self.root.geometry("650x500")
        # 用到的参数
        self.ip = tk.StringVar()
        self.url = tk.StringVar()
        self.ports = tk.StringVar()
        self.threads_number = tk.IntVar()
        self.attackname = tk.StringVar()
        self.proxy = tk.StringVar()
        self.user = tk.StringVar()
        self.data = tk.StringVar()
        self.z=tk.IntVar()
        self.ip_file_path = ''
        self.attack_file_path = ''
        self.finigers_file_path = ''
        self.ceshi = ''
        self.live_mainframe = []
        self.dic = {}

        #菜单
        menubar = tk.Menu(self.root)
        menubar.add_command(label='首页', command=self.show_main)
        menubar.add_command(label='设置', command=self.show_setting)
        menubar.add_command(label='关于', command=self.show_about)
        self.root['menu'] = menubar

        #关于页面的制作
        self.about_frame = tk.Frame(self.root,bg="light blue")
        content = "关于作品：本作品由suyou制作\n\n关于作者：群里最菜的萌新\n\n相关说明：作品制作时间不长，不完善，bug较多，请见谅"
        tk.Label(self.about_frame, text=content,bg="light blue").pack(side='top',fill='y',expand=True)

        #设置页面的制作
        self.setting_frame = tk.Frame(self.root,bg="light blue")
        ftp_content = "关于ftp:爆破ftp时，注意ftp文件格式为 user:passwd"
        fingers_content = '''关于fingers:识别cms时，若选择在线测试，通过爬虫向在线cms识别网站发送数据包\n获取返回的json，从而获取网站配置\n若未选择，则使用zms指纹字典进行匹配识别，字典为json格式，且格式如下
            {"cms": "dedecms",
            "file_type": "css",
            "type": "md5/patten/keyword",
            "match_pattern": "[md5值]",
            "path": "/public/static/css/style.css",
            "uptime": "2019-05-21 19:03:43"}'''
        ssh_mysql_redis_content = "关于爆破其他服务:字典格式为一行一个密码即可"
        proxy_content = "关于proxy:仅为使用在线cms识别过多封ip后进行代理使用"
        ip_content = "关于ip和ip文件：同时只能存在一个，且ip文件格式为一行一个ip"
        tk.Label(self.setting_frame, text=ftp_content,bg="light blue",wraplength=600).pack(side='top',pady=5)
        tk.Label(self.setting_frame, text=proxy_content,bg="light blue",wraplength=600).pack(side='top',pady=5)
        tk.Label(self.setting_frame, text=ip_content,bg="light blue",wraplength=600).pack(side='top',pady=5)
        tk.Label(self.setting_frame, text=ssh_mysql_redis_content,bg="light blue",wraplength=600).pack(side='top',pady=5)
        tk.Label(self.setting_frame, text=fingers_content,bg="light blue",wraplength=600).pack(side='top',pady=5)

        #主页页面的制作
        self.main_frame = tk.Frame(self.root,bg="light blue")
        # 获取扫描ip
        tk.Label(self.main_frame, text="目标IP：",bg="light blue").grid(row=1, column=1,pady=5)
        tk.Entry(self.main_frame, textvariable=self.ip).grid(row=1, column=2,pady=5)
        # 获取扫描ip端口范围
        tk.Label(self.main_frame, text="端口范围：",bg="light blue").grid(row=1, column=3,pady=5)
        duanko = tk.Entry(self.main_frame,textvariable=self.ports)
        duanko.insert(0, "若无则扫描常用端口")
        duanko.grid(row=1, column=4,pady=5)
        # 获取开启线程数
        tk.Label(self.main_frame,text="开启线程数：",bg="light blue",width=13).grid(row=1, column=5,pady=5)
        xiancheng = tk.Entry(self.main_frame,textvariable=self.threads_number,width=5)
        xiancheng.delete(0,"end")
        xiancheng.insert(0,'20')
        xiancheng.grid(row=1, column=6,pady=5)
        # 获取要爆破的服务
        tk.Label(self.main_frame,text="Attack service:",bg="light blue",width=13).grid(row=2, column=1,pady=5)
        vlist = ['','mysql', 'ssh', "redis", "ftp"]
        ttk.Combobox(self.main_frame, values=vlist, state="readonly",width=5,textvariable=self.attackname).grid(row=2,column=2,pady=5)
        # 获取对应爆破服务用户
        tk.Label(self.main_frame,text="User:",bg="light blue",width=13).grid(row=2, column=3,pady=5)
        user = tk.Entry(self.main_frame,textvariable=self.user)
        user.delete(0,"end")
        user.insert(0,'root')
        user.grid(row=2, column=4,pady=5)
        # 获取要检测的url
        tk.Label(self.main_frame, text="目标url：",bg="light blue").grid(row=3, column=1,pady=5)
        tk.Entry(self.main_frame, textvariable=self.url).grid(row=3, column=2,pady=5)
        # 是否使用在线测试cms网站
        tk.Checkbutton(self.main_frame, text="在线测试", variable=self.z).grid(row=3,column=5,pady=5)
        # 获取在线测试cms时使用的代理
        tk.Label(self.main_frame,text="Proxy:",bg="light blue",width=13).grid(row=3, column=3,pady=5)
        proxy = tk.Entry(self.main_frame,textvariable=self.proxy)
        proxy.delete(0,"end")
        proxy.grid(row=3, column=4,pady=5)
        # 获取ip文件
        tk.Button(self.main_frame, text="选择扫描IP文件",bg="light blue",command=self.get_ip_file).grid(row=4, column=1,pady=5)
        self.ip_file = tk.Text(self.main_frame,width=70,height=2)
        self.ip_file.grid(row=4,column=2,columnspan=4,pady=5)
        # 获取爆破文件
        tk.Button(self.main_frame, text="选择服务爆破字典",bg="light blue",command=self.get_attack_file).grid(row=5, column=1,pady=5)
        self.attack_file = tk.Text(self.main_frame,width=70,height=2)
        self.attack_file.grid(row=5,column=2,columnspan=4,pady=5)
        # 获取fingers文件
        tk.Button(self.main_frame, text="选择fingers文件",bg="light blue",command=self.get_fingers_file).grid(row=6, column=1,pady=5)
        self.finigers_file = tk.Text(self.main_frame,width=70,height=2)
        self.finigers_file.grid(row=6,column=2,columnspan=4,pady=5)
        # 提交参数,进行测试
        tk.Button(self.main_frame,text="Submit",command=self.check_var).grid(row=7,column=5,pady=10,rowspan=2,columnspan=2)

        self.main_frame.pack(side='top', fill=tk.BOTH, expand=True)

    def show_about(self):
        self.main_frame.pack_forget()
        self.setting_frame.pack_forget()
        self.about_frame.pack(side='top', fill=tk.BOTH, expand=True)

    def show_setting(self):
        self.main_frame.pack_forget()
        self.about_frame.pack_forget()
        self.setting_frame.pack(side='top', fill=tk.BOTH, expand=True)

    def show_main(self):
        self.about_frame.pack_forget()
        self.setting_frame.pack_forget()
        self.main_frame.pack(side='top', fill=tk.BOTH, expand=True)

    def get_ip_file(self):
        self.ip_file.delete(1.0,"end")
        self.ip_file_path = filedialog.askopenfilename()
        self.ip_file.insert("insert", self.ip_file_path)
    def get_attack_file(self):
        self.attack_file.delete(1.0,"end")
        self.attack_file_path = filedialog.askopenfilename()
        self.attack_file.insert("insert", self.attack_file_path)
    def get_fingers_file(self):
        self.finigers_file.delete(1.0,"end")
        self.finigers_file_path = filedialog.askopenfilename()
        self.finigers_file.insert("insert", self.finigers_file_path)

    def check_var(self):
        self.root.update()
        temp = tk.Label(self.main_frame,text='正在扫描中请稍等',width=50,height=10,wraplength = 500)
        temp.grid(row=8,rowspan=4,column=1,columnspan=3)
        self.data = ''
        self.dic = {}
        self.live_mainframe =[]
        if (self.ip.get() and not self.ip_file_path) or (not self.ip.get() and self.ip_file_path) or self.url.get():
            if self.ip_file_path:
                with open(self.ip_file_path, mode='r') as f:
                    ips = f.readlines()
                try:
                    pool = ThreadPoolExecutor(max_workers=self.threads_number.get())
                    tasks = [pool.submit(self.scan_live_mainframe, i.strip()) for i in ips]
                    wait(tasks)
                    if len(self.live_mainframe) == 0:
                        self.data += "本次扫描未发现存活主机\n"
                    else:
                        self.data += "存活主机如下：" + '-' * 20 + '\n'
                        for key in self.dic:
                            self.data += f"{key}     {self.dic[key]}\n"
                except Exception as e:
                    messagebox.showwarning(title="警告", message='程序运行出错,错误如下:\n'+str(e))
                    self.root.update()
            if (self.ip.get() and not self.url.get()) or (not self.ip.get() and self.url.get()):
                if self.ip.get() and not self.attackname.get():
                    self.scan_live_mainframe(self.ip.get())
                    for key in self.dic:
                        self.data += f"{key}     {self.dic[key]}\n"
                    if '/' not in self.ip.get():
                        self.scan_port(self.ip.get(), self.ports.get())

                if self.ip.get() and self.attackname.get() and self.attack_file_path:
                    if not os.path.exists(self.attack_file_path):
                        messagebox.showwarning(title="警告", message="The file is not exist in the dir!!!")
                    if self.attackname.get() == 'mysql':
                        mysql_port = 3306
                        self.attack_mysql(self.ip.get(), self.attack_file_path, self.user.get(), mysql_port)
                    elif self.attackname.get() == 'ssh':
                        ssh_port = 22
                        self.attack_ssh(self.ip.get(), self.attack_file_path, self.user.get(), ssh_port)
                    elif self.attackname.get() == 'redis':
                        redis_port = 6379
                        self.attack_redis(self.ip.get(), self.attack_file_path, redis_port)
                    elif self.attackname.get() == 'ftp':
                        self.attack_ftp(self.ip.get(), self.attack_file_path)
                if self.url.get():
                    self.data += "查询网站为：\n"+ self.url.get() + '\n'
                    if self.z.get():  # 若存在-z参数则使用爬虫进行获取cms
                        self.get_cms_byReptiles(self.url.get(), self.proxy.get())
                    else:
                        self.get_cms_bydic(self.url.get(), self.finigers_file_path, self.threads_number.get())
        else:
            messagebox.showwarning(title="警告", message='ip，ip文件，url需存在一个')
        self.root.update()
        try:
            temp.destroy()
        except:
            pass
        self.root.update()
        temp2 = tk.Label(self.main_frame,text=self.data,width=50,height=10,wraplength = 500)
        temp2.grid(row=8,rowspan=4,column=1,columnspan=3)
        self.root.update()

    def arp_scan(self,ip):
        # print(f"进行ARP方式扫描{20*'-'}")
        try:
            # 指定Ether后sr不会发包，所以使用srp
            result,unresult = srp(Ether(dst='FF:FF:FF:FF:FF:FF')/ARP(pdst=ip),timeout=2,verbose=0)  #srp返回回复与未回复包，回复包后续使用，未回复包留着以防要用
        except Exception as e:
            # print(e)
            pass
        else:
            # print(f"本次ARP扫描发现了{len(result)}台主机存活:")
            for send,reveive in result:
                self.live_mainframe.append(reveive.psrc)
                # print(f"{reveive.psrc}")  #输出存活ip
                # print(f"{reveive.src}")  #输出存活ip对应mac地址
        # for i in live_mainframe:
        #     print(i)
    def tcp_syn_scan(self,ip):
        often_port_list = [20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 119, 139, 161, 162, 389, 443, 445, 1433, 1521, 2049,
                           2094, 3306, 3389, 4000, 5555,5632, 5900, 7001, 8010, 8080, 8888]  # 常用端口列表
        # print(f"进行TCP方式扫描{20 * '-'}")
        tcp_sport = random.randint(1024,65536)  # 随机一个发送端口
        for i in often_port_list:
            packet = IP(id = random.randint(1, 65536),dst=ip)/TCP(sport = tcp_sport,dport=i)  # 构造tcp包
            try:
                result,unresult = sr(packet,timeout=1,verbose=0)
                res = str(result[0])
                # print(res)
            except Exception as e:
                pass
            else:
                if re.findall("SA",res):  # 返回syn或ack中含有flag  SA
                    # print(f"{ip}主机在线")
                    self.live_mainframe.append(ip)
                    return True
                else:
                    return False
    def tcp_all(self,ip):
        global live_mainframe
        pre_ip = (ip.split('.')[:-1])  #分隔ip地址192.168.x
        pool = ThreadPoolExecutor(max_workers=100)
        task_list = [pool.submit(self.tcp_syn_scan, '.'.join(pre_ip)+'.'+str(i)) for i in range(1,255)]  # 拼凑ip地址传入函数扫描，并加入线程池
        wait(task_list)
        self.live_mainframe = list(set(self.live_mainframe))  #与arp结果进行比较，集合去除重复ip
    def ICMP_scan(self,ip):#ICMP协议探测是否存活
        id_ip = random.randint(1, 65535)  # 随机产生IP ID位
        id_ping = random.randint(1, 65535)  # 随机产生ping ID位
        seq_ping = random.randint(1, 65535)  # 随机产生ping序列号位
        packet = IP(dst=ip, ttl=64, id=id_ip) / ICMP(id=id_ping, seq=seq_ping)  #构造ICMP包
        # packet.show()  # 测试使用显示数据包内容
        res = sr1(packet, timeout=1, verbose=False)
        # print(res.src)   # 输入为网址时查看网址ip
        if res:
            self.live_mainframe.append(ip)
            return True
        else:
            return False
    def ICMP_all(self,ip):
        global live_mainframe
        # print(f"进行ICMP方式扫描{20 * '-'}")
        pre_ip = (ip.split('.')[:-1])  #分隔ip地址192.168.x
        pool = ThreadPoolExecutor(max_workers=100)
        tasks = [pool.submit(self.ICMP_scan, '.'.join(pre_ip)+'.'+str(i)) for i in range(1,255)]  # 拼凑ip地址传入函数扫描，并加入线程池
        wait(tasks)
        self.live_mainframe = list(set(self.live_mainframe))  #与arp结果进行比较，集合去除重复ip
        # print(f"本次ICMP扫描发现了{len(live_mainframe)}台主机存活:")
        # for i in live_mainframe:
        #     print(f"{i}存活")
    def scan_live_mainframe(self,ip):
        '''
        扫描存活主机
        :param ip: 要扫描的网段或者IP
        :return:
        '''
        if '/' in ip:
            self.arp_scan(ip)
            self.ICMP_all(ip)
            self.tcp_all(ip)
            # print(f"本次扫描发现了{len(live_mainframe)}台主机存活:")
        else:
            if self.ICMP_scan(ip):
                self.live_mainframe.append(ip)
            elif self.tcp_syn_scan(ip):
                self.live_mainframe.append(ip)
            else:
                pass
        dic = self.dic
        def get_os(ip):
            if dic.get(ip) == True:
                return 0
            id_ip = random.randint(1, 65535)  # 随机产生IP ID位
            id_ping = random.randint(1, 65535)  # 随机产生ping ID位
            seq_ping = random.randint(1, 65535)  # 随机产生ping序列号位
            packet = IP(dst=ip, id=id_ip) / ICMP(id=id_ping, seq=seq_ping)  # 构造ICMP包
            # packet.show()  # 测试使用显示数据包内容
            res = sr1(packet, timeout=1, verbose=False)
            if res is None:
                dic[ip] = '未识别到该操作系统'
            elif int(res[IP].ttl) <=64:
                dic[ip] = 'Unix/Linux'
            else:
                dic[ip] = 'Windows'
        pool = ThreadPoolExecutor(max_workers=10)
        tasks = [pool.submit(get_os,i) for i in self.live_mainframe]
        wait(tasks)
    def scan_port(self,host,ports=''):
        '''
        端口扫描，使用socket模块获取对应端口服务
        :param host:目标主机ip
        :param ports: 扫描端口范围，以-分隔，默认为‘’，此时扫描常用端口列表
        :return:
        '''
        often_port_list = [20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 119, 139, 161, 162, 389, 443, 445, 1433, 1521, 2049,
                           2094, 3306,3307, 3389, 4000, 5632, 5900, 6379, 7001, 8010, 8080, 8888]  # 常用端口列表
        count = 0
        pool = ThreadPoolExecutor(100)  # 开启线程池进行扫描
        port_open = dict()  # 存放开放端口的字典
        def connect_socket(host, port):
            '''
            只在端口扫描中为线程池使用，并且使用外部参数，所以定义在端口扫描内部
            :param host:
            :param port:
            :return:
            '''
            nonlocal count
            nonlocal  port_open
            con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            con.settimeout(0.1)
            con_result = con.connect_ex((host, port))  # 连接成功返回0
            con.close()
            if con_result == 0:
                try:
                    port_open[port] = socket.getservbyport(port)  # 利用socket获取常用端口对应服务
                except socket.error:
                    pass
                count += 1
        if len(ports.split("-"))!=2:  # 未指定扫描端口时扫描常用端口列表
            tasks = [pool.submit(connect_socket, host, port) for port in often_port_list]
            wait(tasks)
        else:
            start_port, end_port = ports.split("-")
            tasks = [pool.submit(connect_socket, host, port) for port in range(int(start_port),int(end_port)+1)]
            wait(tasks)
        if count == 0:
            self.data +=f"不好意思，{host}主机{ports}端口均未开放\n"
        else:
            self.data +=f"{host}主机开启端口如下：------------------\n"
            for port in port_open:
                self.data +=f"[+]{port}端口，服务为{port_open[port]}\n"
    def attack_mysql(self,host,path,user='root',port=3306):
        '''
        爆破数据库密码，使用pymysql进行连接mysql数据库
        :param host: 目标主机地址
        :param path: 爆破密码字典路径
        :param user: 要连接的用户，默认为root
        :return:
        '''
        runing_flag = 0
        real_password = '未成功破解数据库密码！！！请换新字典进行尝试'
        if user=='root':
            real_password = real_password+'\t 可能无root远程登录权限'
        with open(path,'r') as f:
            passwords = f.readlines()
        def connect_mysql(password):
            nonlocal runing_flag,host,user,real_password,port
            if runing_flag == 1:
                return 0
            try:
                db = pymysql.connect(host=host,user=user,password=password,port=port)
                db.close()
                runing_flag = 1
                real_password = password
            except:
                pass
        pool = ThreadPoolExecutor(max_workers=100)
        tasks = [pool.submit(connect_mysql,password.strip()) for password in passwords]
        wait(tasks)
        self.data += '爆破结果：\n'+real_password +'\n'
    def attack_redis(self,host,path,port=6379):
        runing_flag = 0
        real_password = '未成功破解数据库密码！！！请换新字典进行尝试'
        with open(path,'r') as f:
            passwords = f.readlines()
        def connect_redis(password):
            nonlocal runing_flag,host,real_password,port
            if runing_flag == 1:
                return 0
            try:
                r = redis.StrictRedis(host=host,port=port,password=password,decode_responses=True)
                r.close()
                runing_flag = 1
                real_password = password
            except:
                pass
        pool = ThreadPoolExecutor(max_workers=100)
        tasks = [pool.submit(connect_redis,password.strip()) for password in passwords]
        wait(tasks)
        self.data += '爆破结果：\n' + real_password + '\n'
    def attack_ssh(self,host,path,user='root',port=22):
        runing_flag = 0
        real_password = '未成功破解ssh密码！！！请换新字典进行尝试'
        if user=='root':
            real_password = real_password+'\n 可能无root远程登录权限'
        with open(path,'r') as f:
            passwords = f.readlines()
        def connect_ssh(password):
            nonlocal runing_flag, host, user, real_password, port
            if runing_flag == 1:
                return 0
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(host, port, user, password=password, timeout=1.5)
                runing_flag = 1
                real_password = password
                ssh.close()
                # print(f'\n[*] {str(host)} FTP Logon Succeeded: {user}/{passwd}')
            except:
                pass
        pool = ThreadPoolExecutor(max_workers=100)
        tasks = [pool.submit(connect_ssh, password.strip()) for password in passwords]
        wait(tasks)
        self.data += '爆破结果：\n' + real_password + '\n'
    def attack_ftp(self,host,file):
        allow = {}
        real_password = '未成功破解ssh密码！！！请换新字典进行尝试'
        try:
            ftp = ftplib.FTP(host)
            ftp.login('anonymous','suyou@yousu.com')
            ftp.quit()
            self.data += f"{host}ftp允许匿名登录\n"
        except:
            pass
            # print("anonymous登录失败")
        with open(file,mode='r') as f:
            userpasswds = f.readlines()
        def connect_ftp(user,passwd):
            nonlocal allow
            try:
                ftp = ftplib.FTP(host)
                ftp.login(user,passwd)
                ftp.quit()
                allow[user] = passwd
                # print(f'\n[*] {host} FTP Logon Succeeded: {user}/{passwd}')
            except:
                pass
        pool = ThreadPoolExecutor(max_workers=100)
        tasks = [pool.submit(connect_ftp,userpasswd.split(':')[0],userpasswd.split(':')[1].strip()) for userpasswd in userpasswds]
        wait(tasks)
        self.data +='爆破结果如下:\n'
        for key in allow:
            self.data +=f'{key}/{allow[key]}\n'
    def get_webtitle(self,url):
        user_agent_list = [
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
            "Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10.5; en-US; rv:1.9.2.15) Gecko/20110303 Firefox/3.6.15",
            ]
        header ={
            'Connection': 'close'
        }
        header['User-Agent'] = random.choice(user_agent_list)
        requests.packages.urllib3.disable_warnings()  # 取消ssl验证warning
        try:
            resp = requests.get(url,headers=header,verify=False,timeout=3)
            content = resp.content.decode()
            # print(content)  #测试
            obj = re.compile(r"<title>(?P<title>.*?)</title>",re.S)
            title = obj.findall(content)[0]
            self.data +="web title:"+title+'\n'
        except:
            messagebox.showwarning(title="警告", message=f"{url}访问失败，请检查输入是否正确")
    def get_cms_bydic(self,url,cms_fingers,threads=20):
        user_agent_list = [
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
            "Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10.5; en-US; rv:1.9.2.15) Gecko/20110303 Firefox/3.6.15",
        ]
        header = {
            'Connection': 'close'
        }
        header['User-Agent'] = random.choice(user_agent_list)
        with open(cms_fingers) as f:
            fingers = json.load(f)['data']
        if_complete = False
        fingers_count = len(fingers)
        count = 0
        # print(f"CMS Fingers Count: {fingers_count}")
        # print("正在扫描请稍等"+'-'*20)
        def compare_cms(finger):
            nonlocal url,if_complete,count,fingers_count
            # print('\r', f"扫描进度 {count}/{fingers_count}", end='', flush=True)
            count +=1
            if if_complete:
                return 0
            path = finger.get("path")
            target_url = url + path if path[0]=='/' else url + '/' + path  # 拼凑特定文件路径
            # print(target_url)  #测试
            if requests.head(target_url) == 200:   # 判断网站是否存在该特定文件，若无，直接跳过
                match_pattern = finger.get("match_pattern")
            else:
                return 0
            resp = requests.get(target_url,headers=header,verify=False,timeout=3)
            real_md5 = hashlib.md5()
            real_md5.update(resp.text.encode("utf-8"))
            real_md5 = real_md5.hexdigest()  # 获取加密后的16进制字符串
            if real_md5 == match_pattern:  # 匹配成功后返回对应数据
                print(f"\nHint CMS名称: {finger.get('cms')}")
                print(f"Hint 指纹文件: {finger.get('path')}")
                print(f"Hint Md5: {finger.get('match_pattern')}\n")
                if_complete = True
        pool = ThreadPoolExecutor(max_workers=threads)
        tasks = [pool.submit(compare_cms,finger) for finger in fingers]
        wait(tasks)
        if not if_complete:
            messagebox.showwarning(title="警告", message="CMS未识别")
    def get_cms_byReptiles(self,url,proxy):
        user_agent_list = [
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
            "Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10.5; en-US; rv:1.9.2.15) Gecko/20110303 Firefox/3.6.15",
        ]
        header = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Connection": "close",
            "Host": "whatweb.bugscaner.com",
            "Origin": "http://whatweb.bugscaner.com",
            "Referer": "http://whatweb.bugscaner.com/look/",
        }
        header['User-Agent'] = random.choice(user_agent_list)
        check_url = 'http://whatweb.bugscaner.com/what.go'  # 在线cms查询网网址
        target_url = url.encode("gbk")
        data = {
            "url": target_url,
            "location_capcha": "no"
        }
        try:
            if proxy!="":
                proxy = {
                    "http":proxy
                }
                resp = requests.post(check_url, headers=header, data=data,proxies=proxy)
            else:
                resp = requests.post(check_url, headers=header, data=data)
            dic = json.loads(resp.text)

            self.data += "web CMS: "+ ''.join(dic['CMS'])+'\n'  # 获取CMS
            self.data += "Web Servers: "+''.join(dic['Web Servers'])+'\n'  # 获取web server
        except:
            messagebox.showwarning(title="警告", message="在线网址查询出现问题")

if __name__ == '__main__':
    gui = GUI()
    gui.root.mainloop()
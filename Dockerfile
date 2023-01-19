FROM python

RUN pip install scapy -i https://pypi.tuna.tsinghua.edu.cn/simple

RUN pip install scapy -i https://pypi.tuna.tsinghua.edu.cn/simple

RUN pip install pymysql -i https://pypi.tuna.tsinghua.edu.cn/simple

RUN pip install paramiko -i https://pypi.tuna.tsinghua.edu.cn/simple

RUN pip install requests -i https://pypi.tuna.tsinghua.edu.cn/simple

CMD python my_scan.py
# coding:UTF-8
import socket

from scapy.all import *
import socket
from binascii import hexlify


def to_one_direction(saddr, daddr, sport, dport, proto):
    # hexStr1 = hexlify(socket.inet_aton(ary1))
    # ch2 = lambda x: '.'.join([str(int(x / (256 ** i) % 256)) for i in range(3, -1, -1)])
    # ch3 = lambda x: sum([256 ** j * int(i) for j, i in enumerate(x.split('.')[::-1])])
    sp_tag = str(sport)
    dp_tag = str(dport)
    if proto == 4:
        saddr_c = struct.unpack("L", socket.inet_pton(socket.AF_INET, saddr))[0]
        daddr_c = struct.unpack("L", socket.inet_pton(socket.AF_INET, daddr))[0]

    else:
        saddr_c = struct.unpack("<HHHHHHHH", socket.inet_pton(socket.AF_INET6, saddr))
        daddr_c = struct.unpack("<HHHHHHHH", socket.inet_pton(socket.AF_INET6, daddr))
        saddr = '_'.join(saddr.split(':'))
        daddr = '_'.join(daddr.split(':'))
    # 此即将四元组按照固定顺序排位，两个方向变成一个方向，保证四元组的唯一性
    if saddr_c > daddr_c:
        temp = daddr
        daddr = saddr
        saddr = temp

        temp = sp_tag
        sp_tag = dp_tag
        dp_tag = temp

    name = saddr + '_' + 'to' + daddr + '_' + sp_tag + '_' + dp_tag + '.pcap'

    return name


# 添加存放文件的目录
def mk_dir(pathname):
    if not os.path.exists(pathname):
        os.mkdir(pathname)
    return pathname + '/'


class PcapDecode:
    base_dir = os.path.dirname(__file__) + '/'

    def __init__(self):
        # ETHER:读取以太网层协议配置文件
        with open('./protocol/ETHER', 'r', encoding='UTF-8') as f:
            ethers = f.readlines()
        self.ETHER_DICT = dict()
        for ether in ethers:
            ether = ether.strip().strip('\n').strip('\r').strip('\r\n')
            self.ETHER_DICT[int(ether.split(':')[0])] = ether.split(':')[1]  # 将配置文件中的信息(0257:Experimental)存入dict

        # IP:读取IP层协议配置文件
        with open('./protocol/IP', 'r', encoding='UTF-8') as f:
            ips = f.readlines()
        self.IP_DICT = dict()
        for ip in ips:
            ip = ip.strip().strip('\n').strip('\r').strip('\r\n')
            self.IP_DICT[int(ip.split(':')[0])] = ip.split(':')[1]  # 将配置文件中的信息(41:IPv6)存入dic

        # PORT:读取应用层协议端口配置文件
        with open('./protocol/PORT', 'r', encoding='UTF-8') as f:
            ports = f.readlines()
        self.PORT_DICT = dict()
        for port in ports:
            port = port.strip().strip('\n').strip('\r').strip('\r\n')
            self.PORT_DICT[int(port.split(':')[0])] = port.split(':')[1]  # 如：21:FTP

        # TCP:读取TCP层协议配置文件
        with open('./protocol/TCP', 'r', encoding='UTF-8') as f:
            tcps = f.readlines()
        self.TCP_DICT = dict()
        for tcp in tcps:
            tcp = tcp.strip().strip('\n').strip('\r').strip('\r\n')
            self.TCP_DICT[int(tcp.split(':')[0])] = tcp.split(':')[1]  # 465:SMTPS

        # UDP:读取UDP层协议配置文件
        with open('./protocol/UDP', 'r', encoding='UTF-8') as f:
            udps = f.readlines()
        self.UDP_DICT = dict()
        for udp in udps:
            udp = udp.strip().strip('\n').strip('\r').strip('\r\n')
            self.UDP_DICT[int(udp.split(':')[0])] = udp.split(':')[1]  # 513:Who

    # 解析以太网层协议 ---ether_decode——ip_decode(tcp_decode or udp_decode)
    def ether_decode(self, p):
        data = dict()  # 解析出的信息以dict的形式保存
        if p.haslayer("Ether"):  # scapy.haslayer,将pcap包中的信息分层，再处理
            data = self.ip_decode(p)  # 解析IP层协议
            return data
        else:
            # 直接存为不可解析报文
            data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
            data['Source'] = 'Unknown'
            data['Destination'] = 'Unknown'
            data['Procotol'] = 'Unknown'
            data['len'] = len(corrupt_bytes(p))
            data['info'] = p.summary()
            return data

    # 解析IP层协议
    def ip_decode(self, p):
        data = dict()
        if p.haslayer("IP"):  # 2048:Internet IP (IPv4) ，分IPV4和IPV6和其他协议
            ip = p.getlayer("IP")
            if p.haslayer("TCP"):  # 6:TCP
                data = self.tcp_decode(p, ip)
                return data
            elif p.haslayer("UDP"):  # 17:UDP
                data = self.udp_decode(p, ip)
                return data
            else:
                # 已知的ipv4协议
                if ip.proto in self.IP_DICT:  # 若ip分层中的协议信息在字典中，则提取ip分层中的源地址、目的地址、协议（转换）等
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['Source'] = ip.src
                    data['Destination'] = ip.dst
                    data['Procotol'] = self.IP_DICT[ip.proto]
                    dst_dir = mk_dir('demo/' + self.IP_DICT[ip.proto])
                    name = to_one_direction(ip.src, ip.dst, 4)
                    wrpcap(dst_dir + name, p, append=True)
                    # wrpcap(self.base_dir+'demo/'+self.IP_DICT[ip.proto]+'.pcap', p, append=True)
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
                else:
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['Source'] = ip.src
                    data['Destination'] = ip.dst
                    data['Procotol'] = 'IPv4'
                    dst_dir = mk_dir(self.base_dir + 'demo/unknown_ipv4')
                    name = to_one_direction(ip.src, ip.dst, 4)
                    wrpcap(dst_dir + name, p, append=True)
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
        elif p.haslayer("IPv6"):  # 34525:IPv6
            ipv6 = p.getlayer("IPv6")
            if p.haslayer("TCP"):  # 6:TCP
                data = self.tcp_decode(p, ipv6)
                return data
            elif p.haslayer("UDP"):  # 17:UDP
                data = self.udp_decode(p, ipv6)
                return data
            else:
                if ipv6.nh in self.IP_DICT:
                    # 将此报文写进文件中
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['Source'] = ipv6.src
                    data['Destination'] = ipv6.dst
                    data['Procotol'] = self.IP_DICT[ipv6.nh]
                    dst_dir = mk_dir(self.base_dir + 'demo/' + self.IP_DICT[ipv6.nh])
                    saddr = '_'.join(ipv6.src.split(':'))
                    daddr = '_'.join(ipv6.dst.split(':'))
                    name = saddr + '_' + daddr + '.pcap'
                    wrpcap(dst_dir + name, p, append=True)
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
                else:
                    # 不在已知的协议中
                    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                    data['Source'] = ipv6.src
                    data['Destination'] = ipv6.dst
                    data['Procotol'] = 'IPv6'
                    dst_dir = mk_dir(self.base_dir + 'demo/unknwon_ipv6')
                    saddr = '_'.join(ipv6.src.split(':'))
                    daddr = '_'.join(ipv6.dst.split(':'))
                    name = saddr + '_' + daddr + '.pcap'
                    wrpcap(dst_dir + name, p, append=True)
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
        else:
            if p.type in self.ETHER_DICT:
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                data['Source'] = p.src
                data['Destination'] = p.dst
                data['Procotol'] = self.ETHER_DICT[p.type]
                dst_dir = mk_dir(self.base_dir + 'demo/' + self.ETHER_DICT[p.type])
                saddr = '_'.join(p.src.split(':'))
                daddr = '_'.join(p.dst.split(':'))
                name = saddr + '_' + daddr + '.pcap'
                wrpcap(dst_dir + name, p, append=True)
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                return data
            else:
                data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
                data['Source'] = p.src
                data['Destination'] = p.dst
                data['Procotol'] = hex(p.type)  # 若在字典中没有该协议，则以16进制的形式显示
                dst_dir = mk_dir(self.base_dir + 'demo/' + hex(p.type))
                saddr = '_'.join(p.src.split(':'))
                daddr = '_'.join(p.dst.split(':'))
                name = saddr + '_' + daddr + '.pcap'
                wrpcap(dst_dir + name, p, append=True)
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                return data

    # 解析TCP层协议
    def tcp_decode(self, p, ip):
        data = dict()
        tcp = p.getlayer("TCP")
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
        data['Source'] = ip.src + ":" + str(ip.sport)
        data['Destination'] = ip.dst + ":" + str(ip.dport)
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        if tcp.dport in self.PORT_DICT:  # 若端口信息在PORT_DICT\TCP_DICT中则转换为已知
            data['Procotol'] = self.PORT_DICT[tcp.dport]
            dst_dir = mk_dir(self.base_dir + 'demo/' + self.PORT_DICT[tcp.dport])
            name = to_one_direction(ip.src, ip.dst, ip.sport, ip.dport, ip.version)
            wrpcap(dst_dir + name, p, append=True)
        elif tcp.sport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[tcp.sport]
            dst_dir = mk_dir(self.base_dir + 'demo/' + self.PORT_DICT[tcp.sport])
            name = to_one_direction(ip.src, ip.dst, ip.sport, ip.dport, ip.version)
            wrpcap(dst_dir + name, p, append=True)
        elif tcp.dport in self.TCP_DICT:
            data['Procotol'] = self.TCP_DICT[tcp.dport]
            dst_dir = mk_dir(self.base_dir + 'demo/' + self.TCP_DICT[tcp.dport])
            name = to_one_direction(ip.src, ip.dst, ip.sport, ip.dport, ip.version)
            wrpcap(dst_dir + name, p, append=True)
        elif tcp.sport in self.TCP_DICT:
            data['Procotol'] = self.TCP_DICT[tcp.sport]
            dst_dir = mk_dir(self.base_dir + 'demo/' + self.TCP_DICT[tcp.sport])
            name = to_one_direction(ip.src, ip.dst, ip.sport, ip.dport, ip.version)
            wrpcap(dst_dir + name, p, append=True)
        else:
            data['Procotol'] = "TCP"
            dst_dir = mk_dir(self.base_dir + 'demo/' + 'TCP')
            name = to_one_direction(ip.src, ip.dst, ip.sport, ip.dport, ip.version)
            wrpcap(dst_dir + name, p, append=True)
        return data

    # 解析UDP层协议
    def udp_decode(self, p, ip):
        data = dict()
        udp = p.getlayer("UDP")
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.time))
        data['Source'] = ip.src + ":" + str(ip.sport)
        data['Destination'] = ip.dst + ":" + str(ip.dport)
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        if udp.dport in self.PORT_DICT:  # 若端口信息在PORT_DICT\UDP_DICT中则转换为已知
            data['Procotol'] = self.PORT_DICT[udp.dport]
            dst_dir = mk_dir(self.base_dir + 'demo/' + self.PORT_DICT[udp.dport])
            name = to_one_direction(ip.src, ip.dst, udp.sport, udp.dport, ip.version)
            wrpcap(dst_dir + name, p, append=True)
        elif udp.sport in self.PORT_DICT:
            data['Procotol'] = self.PORT_DICT[udp.sport]
            dst_dir = mk_dir(self.base_dir + 'demo/' + self.PORT_DICT[udp.sport])
            name = to_one_direction(ip.src, ip.dst, udp.sport, udp.dport, ip.version)
            wrpcap(dst_dir + name, p, append=True)
        elif udp.dport in self.UDP_DICT:
            data['Procotol'] = self.UDP_DICT[udp.dport]
            dst_dir = mk_dir(self.base_dir + 'demo/' + self.UDP_DICT[udp.dport])
            name = to_one_direction(ip.src, ip.dst, udp.sport, udp.dport, ip.version)
            wrpcap(dst_dir + name, p, append=True)
        elif udp.sport in self.UDP_DICT:
            data['Procotol'] = self.UDP_DICT[udp.sport]
            dst_dir = mk_dir(self.base_dir + 'demo/' + self.UDP_DICT[udp.dport])
            name = to_one_direction(ip.src, ip.dst, udp.sport, udp.dport, ip.version)
            wrpcap(dst_dir + name, p, append=True)
        else:
            data['Procotol'] = "UDP"
            dst_dir = mk_dir(self.base_dir + 'demo/' + 'UDP')
            name = to_one_direction(ip.src, ip.dst, udp.sport, udp.dport, ip.version)
            wrpcap(dst_dir + name, p, append=True)
        return data


if __name__ == '__main__':

    # pkts = sniff(iface="WLAN", count=3, filter="tcp and ip[12:4] = 0xC0A80176")  # 简单的抓取数据包
    # wrpcap("demo.pcap", pkts)  # 保存为demo.pcap

    PD = PcapDecode()  # 实例化该类为PD
    pcap_test = rdpcap("pcaps/trex_test_use.pcap")  # 这个demo.pcap包含3次连接
    data_result = dict()  # 将解析结果存入dict
    count = 0
    f = open('demo.txt', 'w', encoding='utf-8')
    for p in pcap_test:
        count += 1
        print(count)
        data_result = PcapDecode.ether_decode(PD, p)
        # print(data_result)
        f.write(str(data_result) + '\n')
    f.close()

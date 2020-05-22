# coding:UTF-8

from scapy.all import *


def to_one_direction(saddr, daddr, sport, dport, proto):
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

    name = saddr + '_' + 'to' + '_' + daddr + '_' + sp_tag + '_' + dp_tag + '.pcap'

    return name


# 添加存放文件的目录
def mk_dir(pathname):
    if not os.path.exists(pathname):
        os.mkdir(pathname)
    return pathname + '/'


def ipv4_pcap_create(dir, ip, p):
    dst_dir = mk_dir(dir)
    name = to_one_direction(ip.src, ip.dst, '', '', 4)
    wrpcap(dst_dir + name, p, append=True)


def ipv6_pcap_create(dir, p):
    dst_dir = mk_dir(dir)
    saddr = '_'.join(p.src.split(':'))
    daddr = '_'.join(p.dst.split(':'))
    name = saddr + '_' + 'to' + '_' + daddr + '.pcap'
    wrpcap(dst_dir + name, p, append=True)


class PcapDecode:
    base_dir = os.path.dirname(__file__) + '/'
    pcap_file = ''

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
        # mk_dir(self.pcap_file + '/unknown_IPv4/')

    def mk_proto_dir(self):
        mk_dir(self.base_dir + self.pcap_file)
        # mk_dir(self.base_dir + self.pcap_file + '/IPv4')
        # mk_dir(self.base_dir + self.pcap_file + '/IPv6')
        mk_dir(self.base_dir + self.pcap_file + '/TCP')
        mk_dir(self.base_dir + self.pcap_file + '/UDP')

    # 解析以太网层协议 ---ether_decode——ip_decode(tcp_decode or udp_decode)
    def ether_decode(self, p):
        if p.haslayer("Ether"):  # scapy.haslayer,将pcap包中的信息分层，再处理
            self.ip_decode(p)  # 解析IP层协议

        else:
            # 直接存为不可解析报文
            dst_dir = mk_dir(self.base_dir + self.pcap_file + '/Unknown')
            wrpcap(dst_dir, p, append=True)

    # 解析IP层协议
    def ip_decode(self, p):
        if p.haslayer("IP"):  # 2048:Internet IP (IPv4) ，分IPV4和IPV6和其他协议

            ip = p.getlayer("IP")
            if p.haslayer("TCP"):  # 6:TCP
                self.tcp_decode(p, ip)

            elif p.haslayer("UDP"):  # 17:UDP
                self.udp_decode(p, ip)

            else:
                # 已知的ipv4协议
                if ip.proto in self.IP_DICT:  # 若ip分层中的协议信息在字典中，则提取ip分层中的源地址、目的地址、协议（转换）等
                    mk_dir(self.base_dir + self.pcap_file + '/IPv4')
                    # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/IPv4/' + self.IP_DICT[ip.proto])
                    # name = to_one_direction(ip.src, ip.dst, 4)
                    # wrpcap(dst_dir + name, p, append=True)
                    ipv4_pcap_create(self.base_dir + self.pcap_file + '/IPv4/' + self.IP_DICT[ip.proto], ip, p)
                else:
                    # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/unknown_IPv4')
                    # name = to_one_direction(ip.src, ip.dst, 4)
                    # wrpcap(dst_dir + name, p, append=True)
                    ipv4_pcap_create(self.base_dir + self.pcap_file + '/unknown_IPv4', ip, p)

        elif p.haslayer("IPv6"):  # 34525:IPv6
            ipv6 = p.getlayer("IPv6")
            if p.haslayer("TCP"):  # 6:TCP
                self.tcp_decode(p, ipv6)
            elif p.haslayer("UDP"):  # 17:UDP
                self.udp_decode(p, ipv6)
            else:
                if ipv6.nh in self.IP_DICT:
                    # 将此报文写进文件中
                    mk_dir(self.base_dir + self.pcap_file + '/IPv6')
                    # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/IPv6/' + self.IP_DICT[ipv6.nh])
                    # saddr = '_'.join(ipv6.src.split(':'))
                    # daddr = '_'.join(ipv6.dst.split(':'))
                    # name = saddr + '_' + daddr + '.pcap'
                    # wrpcap(dst_dir + name, p, append=True)
                    ipv6_pcap_create(self.base_dir + self.pcap_file + '/IPv6/' + self.IP_DICT[ipv6.nh], p)
                else:
                    # 不在已知的协议中

                    # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/unknwon_IPv6')
                    # saddr = '_'.join(ipv6.src.split(':'))
                    # daddr = '_'.join(ipv6.dst.split(':'))
                    # name = saddr + '_' + daddr + '.pcap'
                    # wrpcap(dst_dir + name, p, append=True)
                    ipv6_pcap_create(self.base_dir + self.pcap_file + '/unknwon_IPv6', p)
        else:
            if p.type in self.ETHER_DICT:
                # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/' + self.ETHER_DICT[p.type])
                # saddr = '_'.join(p.src.split(':'))
                # daddr = '_'.join(p.dst.split(':'))
                # name = saddr + '_' + daddr + '.pcap'
                # wrpcap(dst_dir + name, p, append=True)
                ipv6_pcap_create(self.base_dir + self.pcap_file + '/' + self.ETHER_DICT[p.type], p)

            else:
                # 若在字典中没有该协议，则以16进制的形式显示
                # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/' + hex(p.type))
                # saddr = '_'.join(p.src.split(':'))
                # daddr = '_'.join(p.dst.split(':'))
                # name = saddr + '_' + daddr + '.pcap'
                # wrpcap(dst_dir + name, p, append=True)
                ipv6_pcap_create(self.base_dir + self.pcap_file + '/' + hex(p.type), p)

    # 解析TCP层协议
    def tcp_decode(self, p, ip):
        tcp = p.getlayer("TCP")
        tcp_tuple = [ip.src, ip.dst, ip.sport, ip.dport, ip.version]
        if tcp.dport in self.PORT_DICT:  # 若端口信息在PORT_DICT\TCP_DICT中则转换为已知
            # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/TCP/' + self.PORT_DICT[tcp.dport])
            # name = to_one_direction(ip.src, ip.dst, ip.sport, ip.dport, ip.version)
            # wrpcap(dst_dir + name, p, append=True)
            self.tcp_pcap_create(self.PORT_DICT[tcp.dport], tcp_tuple)

        elif tcp.sport in self.PORT_DICT:
            # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/TCP/' + self.PORT_DICT[tcp.sport])
            # name = to_one_direction(ip.src, ip.dst, ip.sport, ip.dport, ip.version)
            # wrpcap(dst_dir + name, p, append=True)
            self.tcp_pcap_create(self.PORT_DICT[tcp.sport], tcp_tuple)

        elif tcp.dport in self.TCP_DICT:
            # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/TCP/' + self.TCP_DICT[tcp.dport])
            # name = to_one_direction(ip.src, ip.dst, ip.sport, ip.dport, ip.version)
            # wrpcap(dst_dir + name, p, append=True)
            self.tcp_pcap_create(self.TCP_DICT[tcp.dport], tcp_tuple)

        elif tcp.sport in self.TCP_DICT:
            # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/TCP/' + self.TCP_DICT[tcp.sport])
            # name = to_one_direction(ip.src, ip.dst, ip.sport, ip.dport, ip.version)
            # wrpcap(dst_dir + name, p, append=True)
            self.tcp_pcap_create(self.TCP_DICT[tcp.sport], tcp_tuple)

        else:
            dst_dir = self.base_dir + self.pcap_file + '/TCP/'
            name = to_one_direction(ip.src, ip.dst, ip.sport, ip.dport, ip.version)
            wrpcap(dst_dir + name, p, append=True)
            self.tcp_pcap_create('', tcp_tuple)

    def tcp_pcap_create(self, protocol, tcp_tuple):
        dst_dir = mk_dir(self.base_dir + self.pcap_file + '/TCP/' + protocol)
        pcap_name = to_one_direction(tcp_tuple[0], tcp_tuple[1], tcp_tuple[2], tcp_tuple[3], tcp_tuple[4])
        wrpcap(dst_dir + pcap_name, p, append=True)

    # 解析UDP层协议
    def udp_decode(self, p, ip):
        udp = p.getlayer("UDP")
        udp_tuple = [ip.src, ip.dst, udp.sport, udp.dport, ip.version]
        if udp.dport in self.PORT_DICT:  # 若端口信息在PORT_DICT\UDP_DICT中则转换为已知
            # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/UDP/' + self.PORT_DICT[udp.dport])
            # name = to_one_direction(ip.src, ip.dst, udp.sport, udp.dport, ip.version)
            # wrpcap(dst_dir + name, p, append=True)
            self.udp_pcap_create(self.PORT_DICT[udp.dport], udp_tuple)
        elif udp.sport in self.PORT_DICT:
            # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/UDP/' + self.PORT_DICT[udp.sport])
            # name = to_one_direction(ip.src, ip.dst, udp.sport, udp.dport, ip.version)
            # wrpcap(dst_dir + name, p, append=True)
            self.udp_pcap_create(self.PORT_DICT[udp.sport], udp_tuple)
        elif udp.dport in self.UDP_DICT:
            # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/UDP/' + self.UDP_DICT[udp.dport])
            # name = to_one_direction(ip.src, ip.dst, udp.sport, udp.dport, ip.version)
            # wrpcap(dst_dir + name, p, append=True)
            self.udp_pcap_create(self.UDP_DICT[udp.dport], udp_tuple)
        elif udp.sport in self.UDP_DICT:
            # dst_dir = mk_dir(self.base_dir + self.pcap_file + '/UDP/' + self.UDP_DICT[udp.dport])
            # name = to_one_direction(ip.src, ip.dst, udp.sport, udp.dport, ip.version)
            # wrpcap(dst_dir + name, p, append=True)
            self.udp_pcap_create(self.UDP_DICT[udp.sport], udp_tuple)
        else:
            # dst_dir = self.base_dir + self.pcap_file + '/UDP/'
            # name = to_one_direction(ip.src, ip.dst, udp.sport, udp.dport, ip.version)
            # wrpcap(dst_dir + name, p, append=True)
            self.udp_pcap_create('', udp_tuple)

    def udp_pcap_create(self, protocol, udp_tuple):
        dst_dir = mk_dir(self.base_dir + self.pcap_file + '/UDP/' + protocol)
        pcap_name = to_one_direction(udp_tuple[0], udp_tuple[1], udp_tuple[2], udp_tuple[3], udp_tuple[4])
        wrpcap(dst_dir + pcap_name, p, append=True)


if __name__ == '__main__':

    # pkts = sniff(iface="WLAN", count=10000)  # 简单的抓取数据包
    # wrpcap("pcaps/demo.pcap", pkts)  # 保存为demo.pcap

    test_pcap_file = "pcaps/10w_test.pcap"
    PD = PcapDecode()  # 实例化该类为PD

    pcap_test = rdpcap(test_pcap_file)  #
    PD.pcap_file = test_pcap_file.split('/').pop()
    PD.mk_proto_dir()

    count = 0
    for p in pcap_test:
        count += 1
        print(count)
        PcapDecode.ether_decode(PD, p)

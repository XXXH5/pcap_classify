#!/usr/bin/python

# 用法：./pcap-parser_3.py test.pcap
import sys
import socket
import struct
from os import path
import os
from scapy.all import *

# filename = "C:\\Users\\26432\\Desktop\\test\\trex_test_use.pcap"
# packages = sniff(offline="trex_test_use.pcap", filter="tcp")
# wrpcap("test.pcap", packages)
filename = "C:\\Users\\26432\\Desktop\\test\\demo\\TCP.pcap"


def packets_parser(filename):
    file = open(filename, "rb")

    # 24个字节为数据包包头，包含了一些文件信息
    pcaphdrlen = 24

    # 数据报报头
    pkthdrlen = 16

    # 以太网帧头
    linklen = 14

    # IP头
    iphdrlen = 20

    # TCP头部
    tcphdrlen = 20

    #
    stdtcp = 20

    files4out = {}

    # Read 24-bytes pcap header
    # Pcap文件头24B各字段说明：
    #
    # Magic：4B：0x1A 2B 3C 4D:用来标示文件的开始
    # Major：2B，0x02 00:当前文件主要的版本号
    # Minor：2B，0x04 00当前文件次要的版本号
    # ThisZone：4B当地的标准时间；全零
    # SigFigs：4B时间戳的精度；全零
    # SnapLen：4B最大的存储长度
    # LinkType：4B链路类型
    datahdr = file.read(pcaphdrlen)
    (tag, maj, min, tzone, ts, ppsize, lt) = struct.unpack("=L2p2pLLLL", datahdr)

    # 判断链路层是Cooked还是别的
    if lt == 0x71:
        linklen = 16
    else:
        linklen = 14

    # Read 16-bytes packet header
    data = file.read(pkthdrlen)
    d = path.dirname(__file__)

    while data:
        ipsrc_tag = 0
        ipdst_tag = 0
        sport_tag = 0
        dport_tag = 0
        # 字段说明：
        # Timestamp：时间戳高位，精确到seconds
        # Timestamp：时间戳低位，精确到microseconds
        # Caplen：当前数据区的长度，即抓取到的数据帧长度，由此可以得到下一个数据帧的位置。
        # Len：离线数据长度：网络中实际数据帧的长度，一般不大于caplen，多数情况下和Caplen数值相等。
        (sec, microsec, iplensave, origlen) = struct.unpack("=LLLL", data)

        # read link
        link = file.read(linklen)

        # read IP header
        ipdata = file.read(iphdrlen)
        # print(type(ipdata), count)
        # Version:版本号
        # Type of service:服务类型
        # Total Length:IP包总长 长度16比特。
        # Identifier:标识符
        # Flags:标记
        # Fragment Offset:片偏移
        # Time to Live:生存时间
        # Protocol:协议
        # Header Checksum:头部校验
        # Source: 源地址
        # Destination: 目的地址

        (vl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr) = struct.unpack(">ssHHHssHLL", ipdata)
        iphdrlen = ord(vl) & 0x0F
        iphdrlen *= 4
        # print(protocol)
        # read TCP standard header
        tcpdata = file.read(stdtcp)
        (sport, dport, seq, ack_seq, pad1, win, check, urgp) = struct.unpack(">HHLLHHHH", tcpdata)
        tcphdrlen = pad1 & 0xF000
        tcphdrlen = tcphdrlen >> 12
        tcphdrlen = tcphdrlen * 4

        # skip data
        skip = file.read(iplensave - linklen - iphdrlen - stdtcp)

        print
        socket.inet_ntoa(struct.pack('L', socket.htonl(saddr)))
        src_tag = socket.inet_ntoa(struct.pack('L', socket.htonl(saddr)))
        dst_tag = socket.inet_ntoa(struct.pack('L', socket.htonl(daddr)))
        sp_tag = str(sport)
        dp_tag = str(dport)

        # 此即将四元组按照固定顺序排位，两个方向变成一个方向，保证四元组的唯一性
        if saddr > daddr:
            temp = dst_tag
            dst_tag = src_tag
            src_tag = temp
        if sport > dport:
            temp = sp_tag
            sp_tag = dp_tag
            dp_tag = temp
        # 新建目录
        new_path = d + '/demo' + '/' + src_tag + '_' + dst_tag
        # abspath = path.abspath(d)
        isExists = os.path.exists(new_path)
        # 判断结果
        if not isExists:
            os.makedirs(new_path)
        # 加上端口
        name = src_tag + '_' + dst_tag + '_' + sp_tag + '_' + dp_tag
        # 不加端口
        # name = src_tag + '_' + dst_tag   # + '_' + sp_tag + '_' + dp_tag
        if (name) in files4out:
            file_out = files4out[name]
            file_out.write(data)
            file_out.write(link)
            file_out.write(ipdata)
            file_out.write(tcpdata)
            file_out.write(skip)

            files4out[name] = file_out
        else:
            file_out = open(new_path + '/' + name + '.pcap', "wb")
            file_out.write(datahdr)
            file_out.write(data)
            file_out.write(link)
            file_out.write(ipdata)
            file_out.write(tcpdata)
            file_out.write(skip)

            files4out[name] = file_out

        # read next packet
        data = file.read(pkthdrlen)

    file.close
    for file_out in files4out.values():
        file_out.close()


packets_parser(filename)

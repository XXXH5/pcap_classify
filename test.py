# # 用lambda的方式，整数toIP 地址 一行代码搞定
# ch2 = lambda x: '.'.join([str(int(x / (256 ** i) % 256)) for i in range(3, -1, -1)])
# print(ch2(123456789))
#
# # '7.91.205.21'
#
# # 用lambda的方式，IP地址转换到整数
# ch3 = lambda x: sum([256 ** j * int(i) for j, i in enumerate(x.split('.')[::-1])])
# print(ch3('7.91.205.21'))

# ipv4_1 = '192.168.1.118'
# ipv4_2 = '39.96.145.152'
#
# ipv6 = "fe80::bcdc:9cc8:d9f4:b2c6"
# ipv61 = "ff02::1:2"
# print(struct.unpack("L", socket.inet_pton(socket.AF_INET, ipv4_1))[0])
# print(struct.unpack("L", socket.inet_pton(socket.AF_INET, ipv4_2))[0])

# print(socket.inet_ntop(socket.AF_INET, struct.pack("L", 4294967295)))


# print(struct.unpack("<HHHHHHHH", socket.inet_pton(socket.AF_INET6, ipv6)))
# print(struct.pack("<HHHHHHHH", 33022, 0, 0, 0, 56508, 51356, 62681, 50866))
# print(struct.unpack("<HHHHHHHH", socket.inet_pton(socket.AF_INET6, ipv61)))
# print(struct.unpack(">HHHHHHHH", socket.inet_pton(socket.AF_INET6, ipv6)))
# print(struct.pack(">HHHHHHHH", 65152, 0, 0, 0, 48348, 40136, 55796, 45766))

# pcap_file = 'C:/Users/26432/Desktop/test/pcaps/trex_test_use.pcap'
#
# print(pcap_file.split('/').pop())

from time import sleep


def progress(percent=0, width=30):
    left = width * percent // 100
    right = width - left
    print('\r[', '#' * left, ' ' * right, ']', f' {percent:.0f}%', sep='', end='', flush=True)


for i in range(101):
    progress(i)
    sleep(0.1)

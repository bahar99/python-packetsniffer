import socket, sys
from struct import *


#mac address
def eth_addr(a) :
  b = map('{:02x}'.format, a)
  mac_add = ':'.join(b).upper()
  return mac_add


sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
file = open("sniffer.txt" , "w+")
while True:
    packet = sock.recvfrom(65535)

    packet = packet[0]

    ethernet_header = packet[:14]
    eth = unpack('! 6s 6s H', ethernet_header)
    eth_type = socket.ntohs(eth[2])
    if eth_type == 8:
        ip_header = unpack('!BBHHHBBH4s4s', packet[14:20 + 14])
        version_ihl = ip_header[0]
        header_len = ip_header[1]
        toS=ip_header[2];
        ttl = ip_header[5]
        protocol = ip_header[6]
        s_addr = socket.inet_ntoa(ip_header[8])
        d_addr = socket.inet_ntoa(ip_header[9])
        ip_offset = ip_header[4]
        ip_checksum = ip_header[7]
        ip_id = ip_header[3]
        print('Ethernet Frame:')
        file.write('Ethernet :\n')
        print('\t- Destination :' + eth_addr(packet[0:6]) + ' ,Source :' + eth_addr(packet[6:12])+' ,Protocol: 8')
        file.write('Destination :' + eth_addr(packet[0:6]) + ' ,Source :' + eth_addr(packet[6:12]) + '\n')
        print('\t- IPV4 Packet :')
        file.write('IPV4 Packet : ')
        print('\t\t- version:'+str(version_ihl)+' Header Length:'+str(header_len)+'Source Address :' + str(s_addr) + ' ,Destination Address :' + str(d_addr) + ' ,checksum :'
              + str(ip_checksum) + ' ,Protocol:' + str(protocol) + ' ,TTL :' + str(ttl) + ' ,Identification:' + str(
            ip_id) + ' ,Fragment offset:' + str(ip_offset))
        file.write('Source Address :' + str(s_addr) + ' ,Destination Address :' + str(d_addr) + ' ,checksum :'
                + str(ip_checksum) + ' ,Protocol:' + str(protocol) + ' ,TTL :' + str(ttl) + ' ,ID:' + str(
            ip_id) + ' ,offset:' + str(ip_offset) + '\n')
        ihl = version_ihl & 0xF
        iph_length = ihl * 4\

        # TCP
        if protocol == 6:
            print('TCP Segment:')
            file.write('TCP\n')
            t_length = iph_length + 14
            tcp_header = packet[t_length:t_length + 20]

            tcph = unpack('!HHLLHHHH', tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            offset_flags = tcph[4]
            tcp_window = tcph[5]
            tcp_checksum = tcph[6]
            offset = (offset_flags >> 12) * 4
            flag_urg = (offset_flags & 32) >> 5
            flag_ack = (offset_flags & 16) >> 4
            flag_psh = (offset_flags & 8) >> 3
            flag_rst = (offset_flags & 4) >> 2
            flag_syn = (offset_flags & 2) >> 1
            flag_fin = offset_flags & 1
            data = packet[offset:]
            print('Source Port : ' + str(source_port) + ' ,Dest Port : ' + str(dest_port) + ' ,Seq number : ' + str(
                sequence) + ' \nAck number : ' + str(acknowledgement)
                  + ' ,Checksum : ' + str(tcp_checksum) + ' ,Window size : ' + str(
                tcp_window) + ' \nflag urgent : ' + str(flag_urg) + ' ,flag ack : ' + str(
                flag_ack) + ' ,flag push : ' + str(flag_psh) +
                  ' ,flag rst : ' + str(flag_rst) + ' ,flag syn : ' + str(flag_syn) + ' ,flag finish : ' + str(
                flag_fin) + ' ,data offset : ' + str(offset))
            file.write('Source Port : ' + str(source_port) + ' ,Dest Port : ' + str(dest_port) + ' ,Seq number : ' + str(
                sequence) + ' \nAck number : ' + str(acknowledgement)
                    + ' ,Checksum : ' + str(tcp_checksum) + ' ,Window size : ' + str(
                tcp_window) + ' \nflag urgent : ' + str(flag_urg) + ' ,flag ack : ' + str(
                flag_ack) + ' ,flag push : ' + str(flag_psh) +
                    ' ,flag rst : ' + str(flag_rst) + ' ,flag syn : ' + str(flag_syn) + ' ,flag finish : ' + str(
                flag_fin) + ' ,data offset : ' + str(offset) + '\n')
            print('-TCP data:'+str(data))
            print(
                '------------------------------------------------------------------------------------------------------------------------------------------')
            file.write(
                '------------------------------------------------------------------------------------------------------------------------------------------')


            if source_port == 80 or dest_port == 80:
                print('\t-http:')
                http_data = data.decode('utf-8')
                http_info = str(http_data).split('\n')
                for line in http_info:
                    print(str(line)+'\n')
        # UDP
        elif protocol == 17:
            print('UDP:')
            file.write('UDP:')
            u = iph_length + 14
            udph_length = 8
            udp_header = packet[u:u + 8]

            udph = unpack('!HHHH', udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print('Source Port : ' + str(source_port) + ' ,Dest Port : ' + str(dest_port) + ' ,Length : ' + str(
                length) + ' ,Checksum : ' + str(checksum))
            file.write('Source Port : ' + str(source_port) + ' ,Dest Port : ' + str(dest_port) + ' ,Length : ' + str(
                length) + ' ,Checksum : ' + str(checksum) + '\n')
            print(
                '------------------------------------------------------------------------------------------------------------------------------------------')
            file.write(
                '------------------------------------------------------------------------------------------------------------------------------------------')

        # ICMP
        elif protocol == 1:
            print('ICMP:')
            file.write('ICMP:')
            u = iph_length + 14
            icmph_length = 8
            icmp_header = packet[u:u + 8]

            icmph = unpack('!BBHHH', icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
            seq = icmph[4]
            print('Type : ' + str(icmp_type) + ' ,Code : ' + str(code) + ' ,Checksum : ' + str(checksum) +
                  ', seq : ' + str(seq))
            file.write('Type : ' + str(icmp_type) + ' ,Code : ' + str(code) + ' ,Checksum : ' + str(
                checksum) + ', seq : ' + str(seq) + '\n')
            print(
                '------------------------------------------------------------------------------------------------------------------------------------------')
            file.write(
                '------------------------------------------------------------------------------------------------------------------------------------------')
        else:
            pass
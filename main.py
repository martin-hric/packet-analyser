from scapy.all import *
from binascii import *
from collections import Counter
import ruamel.yaml
import os
import sys

path = 'vzorky_pcap_na_analyzu/trace-27.pcap'
output = {
    'name': 'PKS2022/23',
    'pcap_name': path,
    'packets': [],
    'ipv4_senders': [],
    'max_send_packets_by': [],

}

yaml = ruamel.yaml.YAML()

class HexPacket:
    def __init__(self, hex):
        self.hex = hex
        self.length_pcap_API = 0
        self.length_medium = 0
        self.type = ''
        self.protocol_2 = ''
        self.src_mac = ''
        self.dst_mac = ''
        self.src_ipv4 = ''
        self.dst_ipv4 = ''
        self.protocol_3 = ''

class AnalysedPacket():
    def __init__(self, packet):
        self.number = int
        self.type = str
        self.length_pcap_API = int
        self.length_medium = int
        self.payload = packet[28:30]
        self.d_length = packet[24:28]
        self.protocol_2 = str
        self.protocol_3 = packet[46:48]
        self.protocol_4 = str
        self.dst_mac = packet[:12]
        self.src_mac = packet[12:24]
        self.src_port = int(packet[68:72], 16)
        self.dst_port = int(packet[72:76], 16)
        self.src_ipv4 = str
        self.dst_ipv4 = str
        self.l_port = str
        self.druh = str
        self.sap = str
        self.pid = packet[40:44]


def append_to_output(d,key,value):
    if key not in output.get(d):
        output[d].key = []
    output[d].key.append(value)

def savePcap():
    packet = rdpcap(path)
    txt = open('./txt/hex_packet.txt', 'w')

    for ramec in packet:
        txt.write(hexlify(raw(ramec)).decode() + '\n')

    txt.close()


def analyse():
    hex_txt = open('./txt/hex_packet.txt', 'r')
    arp_paket = open('./txt/arp_paket.txt', 'w')
    icmp_paket = open('./txt/icmp_paket.txt', 'w')
    lldp_subor = open('./txt/lldp.txt', 'w')
    lldp_subor.write('LLDP ramce: \n')

    dict = read_types()
    number = 0
    ipv4_list = []
    arp = 0
    icmp = 0
    lldp = 0

    for ramec in hex_txt:
        # load packet into class
        packet = AnalysedPacket(ramec)
        number = number + 1
        packet.number = number
        out = {}

        packet.length_pcap_API = int((len(ramec) - 1) / 2)
        packet.length_medium = packet.length_pcap_API + 4
        if packet.length_medium < 64:
            packet.length_medium = 64

        if int(packet.d_length, 16) > 1500:
            packet.type = 'Ethernet II'
        elif packet.payload == 'ff' and int(packet.d_length, 16) <= 1500:
            packet.type = 'IEEE 802.3 RAW'
            packet.protocol_3 = 'IPX'
        elif packet.payload == 'aa' and int(packet.d_length, 16) <= 1500:
            packet.type = 'IEEE 802.3 LLC & SNAP'
        else:
            packet.type = 'IEEE 802.3 LLC'
            packet.sap = find_protocol(packet.payload.upper(), dict, '#LSAPs')
    
        packet.protocol_2 = find_protocol(packet.d_length.upper(), dict, '#Ethertypes')

        if packet.protocol_2 == 'IPv4':
            packet.src_ipv4 = convert_hexString_to_IP(ramec[52:60])
            packet.dst_ipv4 = convert_hexString_to_IP(ramec[60:68])

        packet.l_port = min(packet.src_port, packet.dst_port)

        packet.protocol_3 = find_protocol(packet.protocol_3, dict, '#IP')
        if packet.protocol_3 == 'ICMP':
            packet.druh = ''
            if packet.protocol_2 == 'IPv4':
                icmp = icmp + 1
                icmp_paket.write(str(packet.number) + '\n' + ramec)
        elif packet.protocol_3 == '':
            packet.druh = ''
        elif packet.protocol_3 == 'TCP':
            packet.druh = '#TCP ports'
        elif packet.protocol_3 == 'UDP':
            packet.druh = '#UDP ports'

        packet.protocol_4 = find_protocol(packet.l_port, dict, packet.druh)

        if packet.protocol_2 == 'IPv4':
            ipv4_list.append(packet.src_ipv4)
        elif packet.protocol_2 == 'ARP':
            arp = arp + 1
            arp_paket.write(str(packet.number) + '\n' + ramec)
        elif packet.protocol_2 == 'LLDP':
            lldp = lldp + 1

        if packet.protocol_2 == 'LLDP':
            lldp_subor.write('ramec: ' + str(packet.number) + '\n')
        

        out['frame_number'] = packet.number
        out['len_frame_pcap'] = packet.length_pcap_API
        out['len_frame_medium'] = packet.length_medium
        out['frame_type'] = packet.type
        out['src_mac'] = packet.src_mac
        out['dst_mac'] = packet.dst_mac

        if(packet.type == 'Ethernet II'):
            out['ether_type'] = packet.protocol_2  
        
        source_mac = ''
        for(i, c) in enumerate(packet.src_mac):
            if i % 2 == 0 and i != 0:
                source_mac += ':'
            source_mac += c

        destination_mac = ''
        for(i, c) in enumerate(packet.dst_mac):
            if i % 2 == 0 and i != 0:
                destination_mac += ':'
            destination_mac += c

        out['src_mac'] = source_mac
        out['dst_mac'] = destination_mac

        if(packet.protocol_2 == 'IPv4'):
            out['protocol'] = packet.protocol_3
            out['src_ip'] = packet.src_ipv4
            out['dst_ip'] = packet.dst_ipv4

        if(packet.protocol_3 != '' and packet.protocol_3 != 'ICMP'):
            out['src_port'] = packet.src_port
            out['dst_port'] = packet.dst_port

        if(packet.protocol_4 != ''):
            out['app_protocol'] = packet.protocol_4

        if(packet.type == 'IEEE 802.3 LLC'):
            if(packet.sap != ''):
                out['sap'] = packet.sap

        if(packet.type == 'IEEE 802.3 LLC & SNAP'):
            packet.pid = find_protocol(packet.pid.upper(), dict, '#Ethertypes')
            if(packet.pid != ''):
                out['pid'] = packet.pid
    

        hexa = ''
        for i in range(packet.length_pcap_API * 2):
            if i % 2 == 0 and i != 0 and i% 32 != 0:
                hexa += ' '
            if i % 32 == 0 and i != 0:
                hexa += '\n'
            hexa += ramec[i].upper()

        hexa += '\n'

        out['hexa_frame'] = ruamel.yaml.scalarstring.LiteralScalarString(hexa)
        output['packets'].append(out)

        packet.number = packet.number + 1

    yaml.dump(output, open('output.yaml', 'w'))

    # a_textak.write('-----------------------------------------------------------------------------\n')
    # a_textak.write('IP adresy vysielajúcich uzlov:\n')
    # pocet = Counter(ipv4_list)
    # for element in pocet.keys():
    #     a_textak.write(str(element) + '\n')
    # a_textak.write('Adresa uzla s najväčším počtom odoslaných paketov:\n')
    # a_textak.write(str(pocet.most_common(1)) + '\n')
    # a_textak.write('----------------------------------------------------------------------------\n')
    # a_textak.write('pocet LLDP: ' + str(lldp) + '\n')
    # lldp_subor.write('\npocet LLDP: ' + str(lldp))

    hex_txt.close()
    arp_paket.close()
    icmp_paket.close()
    lldp_subor.close()

    # if icmp > 0:
    #     icmp_comm()

    # if arp > 0:
    #     arp_comm()


# # vypisuje icmp komunikacie
# def icmp_comm():
#     icmp_paket = open('./txt/icmp_paket.txt', 'r')
#     icmp_textak = open('analyzovany_paket.txt', 'a', encoding='utf-8')
#     dict = read_types()
#     icmp_textak.write(
#         '-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')
#     icmp_textak.write(
#         '-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')
#     icmp_textak.write('ICMP KOMUNIKACIE: \n')

#     for ramec in icmp_paket:
#         ramec = ramec.strip()
#         if ramec.isdigit():
#             cislo_icmp = ramec
#             continue
#         type = int(ramec[68:70], 16)
#         typ = find_protocol(type, dict, '#ICMP')
#         if typ != '':
#             packet.length_pcap_API = int((len(ramec) - 1) / 2)
#             packet.length_medium = packet.length_pcap_API + 4
#             if packet.length_medium < 64:
#                 packet.length_medium = 64

#             packet.type = 'Ethernet II'

#             packet.protocol_2 = 'IPv4'

#             packet.dst_mac = ramec[:12]
#             packet.src_mac = ramec[12:24]

#             if packet.protocol_2 == 'IPv4':
#                 packet.src_ipv4 = convert_hexString_to_IP(ramec[52:60])
#                 packet.dst_ipv4 = convert_hexString_to_IP(ramec[60:68])

#             packet.protocol_3 = 'ICMP'

#             icmp_textak.write('----------------------------------- ramec: ' + str(
#                 cislo_icmp) + '----------------------------------' + '\n')
#             icmp_textak.write('dĺžka rámca poskytnutá pcap API: ' + str(packet.length_pcap_API) + 'B' + '\n')
#             icmp_textak.write('dĺžka rámca prenášaného po médiu: ' + str(packet.length_medium) + 'B' + '\n')
#             icmp_textak.write(packet.type + '\n')

#             icmp_textak.write('Zdrojová MAC adresa')
#             for i in range(12):
#                 if i % 2 == 0:
#                     icmp_textak.write(':')
#                 icmp_textak.write(packet.src_mac[i])
#             icmp_textak.write('\n')

#             icmp_textak.write('Cieľová MAC adresa')
#             for i in range(12):
#                 if i % 2 == 0:
#                     icmp_textak.write(':')
#                 icmp_textak.write(packet.dst_mac[i])

#             icmp_textak.write('\n' + packet.protocol_2)
#             icmp_textak.write('\nZdrojová IP adresa: ' + packet.src_ipv4)
#             icmp_textak.write('\nCielova IP adresa: ' + packet.dst_ipv4)
#             icmp_textak.write('\n' + packet.protocol_3)
#             icmp_textak.write('\nTyp ICMP komunikacie: ' + typ)

#             for i in range(packet.length_pcap_API * 2):
#                 if i % 2 == 0:
#                     icmp_textak.write(' ')
#                 if i % 16 == 0:
#                     icmp_textak.write('   ')
#                 if i % 32 == 0:
#                     icmp_textak.write('\n')
#                 icmp_textak.write(ramec[i])
#             icmp_textak.write('\n')

#     icmp_textak.write(
#         '-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')
#     icmp_textak.write(
#         '-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')

#     icmp_paket.close()
#     icmp_textak.close()


# # organizuje, ci sa vypisuje uplna/neuplna komunikacia
# def arp_comm():
#     arp_packet = open('arp_paket.txt', 'r')
#     count = 0
#     reply_back = 0
#     for ramec in arp_packet:
#         ramec = ramec.strip()
#         if ramec.isdigit():
#             cislo_arp = ramec
#             continue
#         elif ramec[43] == '1':
#             typ = 'request'
#         elif ramec[43] == '2':
#             typ = 'reply'

#         if typ == 'request':
#             request_target_IP = convert_hexString_to_IP(ramec[76:84])
#             request_sender_IP = convert_hexString_to_IP(ramec[56:64])
#             has_reply = find_reply(request_target_IP, request_sender_IP, cislo_arp)

#             if has_reply != '':
#                 count = count + 1
#                 reply_back = vypis_all_same_req(request_target_IP, request_sender_IP, cislo_arp, has_reply, count)

#             else:
#                 vypis_neuplne_komunikacie(cislo_arp, typ)

#         if typ == 'reply' and int(reply_back) != int(cislo_arp):
#             vypis_neuplne_komunikacie(cislo_arp, typ)

#     arp_packet.close()


# # zisti, ci ma ARP komunikacia reply
# def find_reply(target_IP, sender_IP, cislo):
#     arp_textak = open('arp_paket.txt', 'r')
#     for ramec in arp_textak:
#         ramec = ramec.strip()
#         if ramec.isdigit():
#             reply = ramec
#             continue
#         if int(cislo) >= int(reply):
#             continue
#         if ramec[43] == '2' and target_IP == convert_hexString_to_IP(
#                 ramec[56:64]) and sender_IP == convert_hexString_to_IP(ramec[76:84]):
#             arp_textak.close()
#             return reply
#     return ''

# # vypise neuplne komunikacie
# def vypis_neuplne_komunikacie(cislo, typ):
#     arp_packet = open('arp_paket.txt', 'r')
#     arp_textak = open('analyzovany_paket.txt', 'a', encoding='utf-8')

#     for ramec in arp_packet:
#         ramec = ramec.strip()
#         if ramec.isdigit():
#             ciselko = ramec
#             continue
#         if ciselko == cislo:
#             packet.dst_mac = ramec[:12]
#             packet.src_mac = ramec[12:24]

#             packet.length_pcap_API = int((len(ramec) - 1) / 2)
#             packet.length_medium = packet.length_pcap_API + 4
#             if packet.length_medium < 64:
#                 packet.length_medium = 64

#             target_IP = convert_hexString_to_IP(ramec[76:84])
#             sender_IP = convert_hexString_to_IP(ramec[54:64])

#             arp_textak.write('\nNEUPLNA KOMUNIKACIA:\n')
#             arp_textak.write('ARP ' + typ + ', IP adresa: ' + str(target_IP) + '   MAC adresa: ???\nZdrojova IP:' + str(
#                 sender_IP) + ',   Cielova IP:' + str(target_IP) + '\n')
#             arp_textak.write('----------------------------------- ramec: ' + str(
#                 cislo) + '----------------------------------' + '\n')
#             arp_textak.write('dĺžka rámca poskytnutá pcap API: ' + str(packet.length_pcap_API) + 'B' + '\n')
#             arp_textak.write('dĺžka rámca prenášaného po médiu: ' + str(packet.length_medium) + 'B' + '\n')
#             arp_textak.write('Ethernet II\n')

#             arp_textak.write('Zdrojová MAC adresa')
#             for i in range(12):
#                 if i % 2 == 0:
#                     arp_textak.write(':')
#                 arp_textak.write(packet.src_mac[i])
#             arp_textak.write('\n')

#             arp_textak.write('Cieľová MAC adresa')
#             for i in range(12):
#                 if i % 2 == 0:
#                     arp_textak.write(':')
#                 arp_textak.write(packet.dst_mac[i])

#             arp_textak.write('\nARP')

#             for i in range((packet.length_pcap_API * 2)):
#                 if (i) % 2 == 0:
#                     arp_textak.write(' ')
#                 if (i) % 16 == 0:
#                     arp_textak.write('   ')
#                 if (i) % 32 == 0:
#                     arp_textak.write('\n')
#                 arp_textak.write(ramec[i])
#             arp_textak.write('\n')

#     arp_textak.close()
#     arp_packet.close()


# # vypise vsetky ramce uplnych arp komunikacii
# def vypis_all_same_req(target_IP, sender_IP, cislo_req, cislo_reply, cislo_komunikacie):
#     arp_textak = open('analyzovany_paket.txt', 'a', encoding='utf-8')
#     arp_paket = open('arp_paket.txt', 'r')
#     arp_textak.write('\n\nUplna komunikacia cislo: ' + str(cislo_komunikacie) + '\n')
#     arp_textak.write('ARP request, IP adresa: ' + str(target_IP) + '   MAC adresa: ???\nZdrojova IP:' + str(
#         sender_IP) + ',   Cielova IP:' + str(target_IP) + '\n')

#     for ramec in arp_paket:
#         ramec = ramec.strip()
#         if ramec.isdigit():
#             number = ramec
#             continue
#         here_sender_IP = convert_hexString_to_IP(ramec[56:64])
#         here_target_IP = convert_hexString_to_IP(ramec[76:84])
#         if int(number) >= int(cislo_req) and int(number) < int(
#                 cislo_reply) and target_IP == here_target_IP and sender_IP == here_sender_IP:
#             packet.dst_mac = ramec[:12]
#             packet.src_mac = ramec[12:24]

#             packet.length_pcap_API = int((len(ramec) - 1) / 2)
#             packet.length_medium = packet.length_pcap_API + 4
#             if packet.length_medium < 64:
#                 packet.length_medium = 64

#             arp_textak.write('----------------------------------- ramec: ' + str(
#                 number) + '----------------------------------' + '\n')
#             arp_textak.write('dĺžka rámca poskytnutá pcap API: ' + str(packet.length_pcap_API) + 'B' + '\n')
#             arp_textak.write('dĺžka rámca prenášaného po médiu: ' + str(packet.length_medium) + 'B' + '\n')
#             arp_textak.write('Ethernet II\n')

#             arp_textak.write('Zdrojová MAC adresa')
#             for i in range(12):
#                 if i % 2 == 0:
#                     arp_textak.write(':')
#                 arp_textak.write(packet.src_mac[i])
#             arp_textak.write('\n')

#             arp_textak.write('Cieľová MAC adresa')
#             for i in range(12):
#                 if i % 2 == 0:
#                     arp_textak.write(':')
#                 arp_textak.write(packet.dst_mac[i])

#             arp_textak.write('\nARP')

#             for i in range((packet.length_pcap_API * 2)):
#                 if (i) % 2 == 0:
#                     arp_textak.write(' ')
#                 if (i) % 16 == 0:
#                     arp_textak.write('   ')
#                 if (i) % 32 == 0:
#                     arp_textak.write('\n')
#                 arp_textak.write(ramec[i])
#             arp_textak.write('\n')

#         elif int(number) == int(cislo_reply):
#             mac_reply = ramec[44:56]
#             arp_textak.write('\nARP reply, IP adresa: ' + str(target_IP) + '   MAC adresa')
#             for i in range(12):
#                 if i % 2 == 0:
#                     arp_textak.write(':')
#                 arp_textak.write(mac_reply[i])

#             arp_textak.write('\nZdrojova IP:' + str(here_sender_IP) + ',   Cielova IP:' + str(here_target_IP) + '\n')

#             packet.dst_mac = ramec[:12]
#             packet.src_mac = ramec[12:24]

#             packet.length_pcap_API = int((len(ramec) - 1) / 2)
#             packet.length_medium = packet.length_pcap_API + 4
#             if packet.length_medium < 64:
#                 packet.length_medium = 64

#             arp_textak.write('----------------------------------- ramec: ' + str(
#                 number) + '----------------------------------' + '\n')
#             arp_textak.write('dĺžka rámca poskytnutá pcap API: ' + str(packet.length_pcap_API) + 'B' + '\n')
#             arp_textak.write('dĺžka rámca prenášaného po médiu: ' + str(packet.length_medium) + 'B' + '\n')
#             arp_textak.write('Ethernet II\n')

#             arp_textak.write('Zdrojová MAC adresa')
#             for i in range(12):
#                 if i % 2 == 0:
#                     arp_textak.write(':')
#                 arp_textak.write(packet.src_mac[i])
#             arp_textak.write('\n')

#             arp_textak.write('Cieľová MAC adresa')
#             for i in range(12):
#                 if i % 2 == 0:
#                     arp_textak.write(':')
#                 arp_textak.write(packet.dst_mac[i])

#             arp_textak.write('\nARP')

#             for i in range((packet.length_pcap_API * 2)):
#                 if (i) % 2 == 0:
#                     arp_textak.write(' ')
#                 if (i) % 16 == 0:
#                     arp_textak.write('   ')
#                 if (i) % 32 == 0:
#                     arp_textak.write('\n')
#                 arp_textak.write(ramec[i])
#             arp_textak.write('\n')

#         elif int(number) > int(cislo_reply):
#             return cislo_reply
#     return cislo_reply

def convert_hexString_to_IP(string):
    ip = ["".join(x) for x in zip(*[iter(string)] * 2)]
    ip = [int(x, 16) for x in ip]
    ip = ".".join(str(x) for x in ip)
    return ip

# read types of protocols and save as dict
def read_types():
    file = open('./txt/types.txt', 'r')
    dict = {}
    type = ''
    for line in file:
        if line[0] == '#':
            type = line.strip()
            dict[type] = {}
        else:
            num, name = line.split(' ', 1)
            dict[type][num] = name.rstrip()
    file.close()
    return dict

# find protocol in dict
def find_protocol(ciselko, dict, type):
    if type == '':
        return ''
    if str(ciselko) in dict[type]:
        return dict[type][str(ciselko).upper()]
    else:
        return ''

savePcap()
analyse()
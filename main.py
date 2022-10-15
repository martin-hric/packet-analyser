from scapy.all import *
from binascii import *
from collections import Counter
import ruamel.yaml

path = 'vzorky_pcap_na_analyzu/trace-27.pcap'
output = {
    'name': 'PKS2022/23',
    'pcap_name': path,
    'packets': [],
    'ipv4_senders': [],
    'max_send_packets_by': [],

}

yaml = ruamel.yaml.YAML()

class AnalysedPacket():
    def __init__(self, packet):
        self.number = int
        self.type = str
        self.length_pcap_API = int
        self.length_medium = int
        self.payload = packet[28:30]
        self.hex_ethertype = packet[24:28]
        self.ethertype = str
        self.ip_protocol = str
        self.app_protocol = str
        self.dst_mac = packet[:12]
        self.src_mac = packet[12:24]
        self.src_port = int(packet[68:72], 16)
        self.dst_port = int(packet[72:76], 16)
        self.src_ip = str
        self.dst_ip = str
        self.arp_opcode = str
        self.sap = str
        self.pid = packet[40:44]

def savePcap():
    packet = rdpcap(path)
    txt = open('./txt/hex_packet.txt', 'w')

    for ramec in packet:
        txt.write(hexlify(raw(ramec)).decode() + '\n')

    txt.close()

def analyse():
    #open external files
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
        number += 1
        packet.number = number
        out = {}

        #set lenghts of packet
        packet.length_pcap_API = int((len(ramec) - 1) / 2)
        packet.length_medium = packet.length_pcap_API + 4
        if packet.length_medium < 64:
            packet.length_medium = 64

        #format src_mac address
        source_mac = ''
        for(i, c) in enumerate(packet.src_mac):
            if i % 2 == 0 and i != 0:
                source_mac += ':'
            source_mac += c

        #format dst_mac address
        destination_mac = ''
        for(i, c) in enumerate(packet.dst_mac):
            if i % 2 == 0 and i != 0:
                destination_mac += ':'
            destination_mac += c

        #set ethertypes
        packet.ethertype = find_protocol(packet.hex_ethertype.upper(), dict, '#Ethertypes')

        out['frame_number'] = packet.number
        out['len_frame_pcap'] = packet.length_pcap_API
        out['len_frame_medium'] = packet.length_medium
        out['src_mac'] = source_mac
        out['dst_mac'] = destination_mac

        #set frame types
        if int(packet.hex_ethertype, 16) > 1500:
            packet.type = 'Ethernet II'
            if packet.ethertype != '':
                out['ether_type'] = packet.ethertype
        elif packet.payload == 'ff':
            packet.type = 'IEEE 802.3 RAW'
        elif packet.payload == 'aa':
            packet.type = 'IEEE 802.3 LLC & SNAP'
            packet.pid = find_protocol(packet.pid.upper(), dict, '#PID')
            if(packet.pid != ''):
                out['pid'] = packet.pid
        else:
            packet.type = 'IEEE 802.3 LLC'
            packet.sap = find_protocol(packet.payload.upper(), dict, '#SAP')
            if(packet.sap != ''):
                out['sap'] = packet.sap

        out['frame_type'] = packet.type
    
        if(packet.hex_ethertype == '0800' or packet.hex_ethertype == '86DD' or packet.hex_ethertype == '0806'):
            #IPv4
            if(packet.hex_ethertype == '0800'):
                packet.src_ip = convert_hexString_to_IP(ramec[52:60])
                packet.dst_ip = convert_hexString_to_IP(ramec[60:68])
            #IPv6
            elif(packet.hex_ethertype == '86DD'):
                packet.src_ip = convert_ipv6(ramec[44:76])
                packet.dst_ip = convert_ipv6(ramec[76:108])
            #ARP
            elif(packet.hex_ethertype == '0806'):
                if ramec[43] == '1':
                    packet.arp_opcode = 'REQUEST'
                elif ramec[43] == '2':
                    packet.arp_opcode = 'REPLY'
                out['arp_opcode'] = packet.arp_opcode
                packet.src_ip = convert_hexString_to_IP(ramec[56:64])
                packet.dst_ip = convert_hexString_to_IP(ramec[76:84])

            out['src_ip'] = packet.src_ip
            out['dst_ip'] = packet.dst_ip
        #if its IPv4, set nested protocols
        if packet.hex_ethertype == '0800':
            ipv4_list.append(packet.src_ip)
            #smaller_port is the port with lower value and we set the application protocol according to it
            smaller_port = min(packet.src_port, packet.dst_port)
            #set ip protocol
            packet.ip_protocol = find_protocol(ramec[46:48].upper(), dict, '#IP')
            out['protocol'] = packet.ip_protocol
            #TCP and #UDP -> set ports and application protocol
            if ramec[46:48] == '06' or ramec[46:48] == '11':
                out['src_port'] = packet.src_port
                out['dst_port'] = packet.dst_port
                packet.app_protocol = find_protocol(smaller_port, dict, '#APP Ports')
                if packet.app_protocol != '':
                    out['app_protocol'] = packet.app_protocol
            #ICMP  
            elif ramec[46:48] == '01':
                icmp += 1
                icmp_paket.write(str(packet.number) + '\n' + ramec)
#|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||               
            #IGMP
            elif ramec[46:48] == '02':
                pass
            #PIM
            elif ramec[46:48] == '67':
                pass
        #LLDP
        elif packet.hex_ethertype== '88CC':
            lldp += 1
            lldp_subor.write('ramec: ' + str(packet.number) + '\n')

        #format hexa_frame 
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

    #all ipv4 nodes and their count
    ipv4_count = Counter(ipv4_list)

    for ip in ipv4_count:
        ipv4_packets = {
            'node': ip,
            'number_of_sent_packets': ipv4_count[ip]
        }
        output['ipv4_senders'].append(ipv4_packets)

    #find most common ipv4 node(s), if there are more than 1, find all of them
    most_common = ipv4_count.most_common(1)
    for ip in ipv4_count:
        if ipv4_count[ip] == most_common[0][1]:
            output['max_send_packets_by'].append(ip)
    
    hex_txt.close()
    arp_paket.close()
    icmp_paket.close()
    lldp_subor.close()

    if icmp > 0:
        icmp_comm()

    if arp > 0:
        arp_comm()


# vypisuje icmp komunikacie
def icmp_comm():
    icmp_paket = open('./txt/icmp_paket.txt', 'r')
    icmp_textak = open('analyzovany_paket.txt', 'a', encoding='utf-8')
    dict = read_types()
    icmp_textak.write(
        '-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')
    icmp_textak.write(
        '-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')
    icmp_textak.write('ICMP KOMUNIKACIE: \n')

    for ramec in icmp_paket:
        ramec = ramec.strip()
        if ramec.isdigit():
            cislo_icmp = ramec
            continue
        type = int(ramec[68:70], 16)
        typ = find_protocol(type, dict, '#ICMP')
        if typ != '':
            packet.length_pcap_API = int((len(ramec) - 1) / 2)
            packet.length_medium = packet.length_pcap_API + 4
            if packet.length_medium < 64:
                packet.length_medium = 64

            packet.type = 'Ethernet II'

            packet.ethertype = 'IPv4'

            packet.dst_mac = ramec[:12]
            packet.src_mac = ramec[12:24]

            if packet.ethertype == 'IPv4':
                packet.src_ipv4 = convert_hexString_to_IP(ramec[52:60])
                packet.dst_ipv4 = convert_hexString_to_IP(ramec[60:68])

            packet.ip_protocol = 'ICMP'

            icmp_textak.write('----------------------------------- ramec: ' + str(
                cislo_icmp) + '----------------------------------' + '\n')
            icmp_textak.write('dĺžka rámca poskytnutá pcap API: ' + str(packet.length_pcap_API) + 'B' + '\n')
            icmp_textak.write('dĺžka rámca prenášaného po médiu: ' + str(packet.length_medium) + 'B' + '\n')
            icmp_textak.write(packet.type + '\n')

            icmp_textak.write('Zdrojová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    icmp_textak.write(':')
                icmp_textak.write(packet.src_mac[i])
            icmp_textak.write('\n')

            icmp_textak.write('Cieľová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    icmp_textak.write(':')
                icmp_textak.write(packet.dst_mac[i])

            icmp_textak.write('\n' + packet.ethertype)
            icmp_textak.write('\nZdrojová IP adresa: ' + packet.src_ipv4)
            icmp_textak.write('\nCielova IP adresa: ' + packet.dst_ipv4)
            icmp_textak.write('\n' + packet.ip_protocol)
            icmp_textak.write('\nTyp ICMP komunikacie: ' + typ)

            for i in range(packet.length_pcap_API * 2):
                if i % 2 == 0:
                    icmp_textak.write(' ')
                if i % 16 == 0:
                    icmp_textak.write('   ')
                if i % 32 == 0:
                    icmp_textak.write('\n')
                icmp_textak.write(ramec[i])
            icmp_textak.write('\n')

    icmp_textak.write(
        '-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')
    icmp_textak.write(
        '-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n')

    icmp_paket.close()
    icmp_textak.close()


# organizuje, ci sa vypisuje uplna/neuplna komunikacia
def arp_comm():
    arp_packet = open('arp_paket.txt', 'r')
    count = 0
    reply_back = 0
    for ramec in arp_packet:
        ramec = ramec.strip()
        if ramec.isdigit():
            cislo_arp = ramec
            continue
        elif ramec[43] == '1':
            typ = 'request'
        elif ramec[43] == '2':
            typ = 'reply'

        if typ == 'request':
            request_target_IP = convert_hexString_to_IP(ramec[76:84])
            request_sender_IP = convert_hexString_to_IP(ramec[56:64])
            has_reply = find_reply(request_target_IP, request_sender_IP, cislo_arp)

            if has_reply != '':
                count = count + 1
                reply_back = vypis_all_same_req(request_target_IP, request_sender_IP, cislo_arp, has_reply, count)

            else:
                vypis_neuplne_komunikacie(cislo_arp, typ)

        if typ == 'reply' and int(reply_back) != int(cislo_arp):
            vypis_neuplne_komunikacie(cislo_arp, typ)

    arp_packet.close()


# zisti, ci ma ARP komunikacia reply
def find_reply(target_IP, sender_IP, cislo):
    arp_textak = open('arp_paket.txt', 'r')
    for ramec in arp_textak:
        ramec = ramec.strip()
        if ramec.isdigit():
            reply = ramec
            continue
        if int(cislo) >= int(reply):
            continue
        if ramec[43] == '2' and target_IP == convert_hexString_to_IP(
                ramec[56:64]) and sender_IP == convert_hexString_to_IP(ramec[76:84]):
            arp_textak.close()
            return reply
    return ''

# vypise neuplne komunikacie
def vypis_neuplne_komunikacie(cislo, typ):
    arp_packet = open('arp_paket.txt', 'r')
    arp_textak = open('analyzovany_paket.txt', 'a', encoding='utf-8')

    for ramec in arp_packet:
        ramec = ramec.strip()
        if ramec.isdigit():
            ciselko = ramec
            continue
        if ciselko == cislo:
            packet.dst_mac = ramec[:12]
            packet.src_mac = ramec[12:24]

            packet.length_pcap_API = int((len(ramec) - 1) / 2)
            packet.length_medium = packet.length_pcap_API + 4
            if packet.length_medium < 64:
                packet.length_medium = 64

            target_IP = convert_hexString_to_IP(ramec[76:84])
            sender_IP = convert_hexString_to_IP(ramec[54:64])

            arp_textak.write('\nNEUPLNA KOMUNIKACIA:\n')
            arp_textak.write('ARP ' + typ + ', IP adresa: ' + str(target_IP) + '   MAC adresa: ???\nZdrojova IP:' + str(
                sender_IP) + ',   Cielova IP:' + str(target_IP) + '\n')
            arp_textak.write('----------------------------------- ramec: ' + str(
                cislo) + '----------------------------------' + '\n')
            arp_textak.write('dĺžka rámca poskytnutá pcap API: ' + str(packet.length_pcap_API) + 'B' + '\n')
            arp_textak.write('dĺžka rámca prenášaného po médiu: ' + str(packet.length_medium) + 'B' + '\n')
            arp_textak.write('Ethernet II\n')

            arp_textak.write('Zdrojová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(packet.src_mac[i])
            arp_textak.write('\n')

            arp_textak.write('Cieľová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(packet.dst_mac[i])

            arp_textak.write('\nARP')

            for i in range((packet.length_pcap_API * 2)):
                if (i) % 2 == 0:
                    arp_textak.write(' ')
                if (i) % 16 == 0:
                    arp_textak.write('   ')
                if (i) % 32 == 0:
                    arp_textak.write('\n')
                arp_textak.write(ramec[i])
            arp_textak.write('\n')

    arp_textak.close()
    arp_packet.close()


# vypise vsetky ramce uplnych arp komunikacii
def vypis_all_same_req(target_IP, sender_IP, cislo_req, cislo_reply, cislo_komunikacie):
    arp_textak = open('analyzovany_paket.txt', 'a', encoding='utf-8')
    arp_paket = open('arp_paket.txt', 'r')
    arp_textak.write('\n\nUplna komunikacia cislo: ' + str(cislo_komunikacie) + '\n')
    arp_textak.write('ARP request, IP adresa: ' + str(target_IP) + '   MAC adresa: ???\nZdrojova IP:' + str(
        sender_IP) + ',   Cielova IP:' + str(target_IP) + '\n')

    for ramec in arp_paket:
        ramec = ramec.strip()
        if ramec.isdigit():
            number = ramec
            continue
        here_sender_IP = convert_hexString_to_IP(ramec[56:64])
        here_target_IP = convert_hexString_to_IP(ramec[76:84])
        if int(number) >= int(cislo_req) and int(number) < int(
                cislo_reply) and target_IP == here_target_IP and sender_IP == here_sender_IP:
            packet.dst_mac = ramec[:12]
            packet.src_mac = ramec[12:24]

            packet.length_pcap_API = int((len(ramec) - 1) / 2)
            packet.length_medium = packet.length_pcap_API + 4
            if packet.length_medium < 64:
                packet.length_medium = 64

            arp_textak.write('----------------------------------- ramec: ' + str(
                number) + '----------------------------------' + '\n')
            arp_textak.write('dĺžka rámca poskytnutá pcap API: ' + str(packet.length_pcap_API) + 'B' + '\n')
            arp_textak.write('dĺžka rámca prenášaného po médiu: ' + str(packet.length_medium) + 'B' + '\n')
            arp_textak.write('Ethernet II\n')

            arp_textak.write('Zdrojová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(packet.src_mac[i])
            arp_textak.write('\n')

            arp_textak.write('Cieľová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(packet.dst_mac[i])

            arp_textak.write('\nARP')

            for i in range((packet.length_pcap_API * 2)):
                if (i) % 2 == 0:
                    arp_textak.write(' ')
                if (i) % 16 == 0:
                    arp_textak.write('   ')
                if (i) % 32 == 0:
                    arp_textak.write('\n')
                arp_textak.write(ramec[i])
            arp_textak.write('\n')

        elif int(number) == int(cislo_reply):
            mac_reply = ramec[44:56]
            arp_textak.write('\nARP reply, IP adresa: ' + str(target_IP) + '   MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(mac_reply[i])

            arp_textak.write('\nZdrojova IP:' + str(here_sender_IP) + ',   Cielova IP:' + str(here_target_IP) + '\n')

            packet.dst_mac = ramec[:12]
            packet.src_mac = ramec[12:24]

            packet.length_pcap_API = int((len(ramec) - 1) / 2)
            packet.length_medium = packet.length_pcap_API + 4
            if packet.length_medium < 64:
                packet.length_medium = 64

            arp_textak.write('----------------------------------- ramec: ' + str(
                number) + '----------------------------------' + '\n')
            arp_textak.write('dĺžka rámca poskytnutá pcap API: ' + str(packet.length_pcap_API) + 'B' + '\n')
            arp_textak.write('dĺžka rámca prenášaného po médiu: ' + str(packet.length_medium) + 'B' + '\n')
            arp_textak.write('Ethernet II\n')

            arp_textak.write('Zdrojová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(packet.src_mac[i])
            arp_textak.write('\n')

            arp_textak.write('Cieľová MAC adresa')
            for i in range(12):
                if i % 2 == 0:
                    arp_textak.write(':')
                arp_textak.write(packet.dst_mac[i])

            arp_textak.write('\nARP')

            for i in range((packet.length_pcap_API * 2)):
                if (i) % 2 == 0:
                    arp_textak.write(' ')
                if (i) % 16 == 0:
                    arp_textak.write('   ')
                if (i) % 32 == 0:
                    arp_textak.write('\n')
                arp_textak.write(ramec[i])
            arp_textak.write('\n')

        elif int(number) > int(cislo_reply):
            return cislo_reply
    return cislo_reply

def convert_hexString_to_IP(string):
    ip = ["".join(x) for x in zip(*[iter(string)] * 2)]
    ip = [int(x, 16) for x in ip]
    ip = ".".join(str(x) for x in ip)
    return ip

def convert_ipv6(string):
    ip = ["".join(x) for x in zip(*[iter(string)] * 4)]
    ip = [x for x in ip]
    ip = ":".join(str(x) for x in ip)
    ip = ip.replace(':0000:', '::')
    ip = ip.replace(':000', ':')
    ip = ip.replace(':00', ':')
    ip = ip.replace(':0', ':')
    while(ip.__contains__(':::')):
        ip = ip.replace(':::', '::')
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
yaml.dump(output, open('output.yaml', 'w'))
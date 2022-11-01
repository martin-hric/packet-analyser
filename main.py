from scapy.all import *
from binascii import *
from collections import Counter
import ruamel.yaml
import argparse

path = 'vzorky_pcap_na_analyzu/trace-6.pcap'
yaml = ruamel.yaml.YAML()
yaml.representer.ignore_aliases = lambda *args : True

class AnalysedPacket:
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

#solving 1-3 task
def analyse():
    #open external files
    hex_txt = open('./txt/hex_packet.txt', 'r')
    
    output = {
    'name': 'PKS2022/23',
    'pcap_name': path,
    'packets': [],
    'ipv4_senders': [],
    'max_send_packets_by': [],
}

    ssdp_output = {
        'name': 'PKS2022/23',
        'pcap_name': path,
        'ssdp_count': [],
        'all_count': [],
        'percent of ssdp': [],
        'packets': []
    }

    dict = read_types()
    number = 0
    ipv4_list = []
    ssdp_count = 0
    
    for ramec in hex_txt:
        # load packet into class
        packet = AnalysedPacket(ramec)
        number += 1
        packet.number = number
        out = {}
        ssdp = {}

        #set lenghts of packet
        packet.length_pcap_API = int((len(ramec)) / 2)
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
    
        if(packet.hex_ethertype == '0800' or packet.hex_ethertype == '86dd' or packet.hex_ethertype == '0806'):
            #IPv4
            if(packet.hex_ethertype == '0800'):
                packet.src_ip = convert_hexString_to_IP(ramec[52:60])
                packet.dst_ip = convert_hexString_to_IP(ramec[60:68])
            #IPv6
            elif(packet.hex_ethertype == '86dd'):
                packet.src_ip = convert_ipv6(ramec[44:76])
                packet.dst_ip = convert_ipv6(ramec[76:108])
            #ARP
            elif(packet.hex_ethertype == '0806'):
                # arp += 1
                # arp_paket.write(str(packet.number)+'\n'+ramec)
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
                    if packet.app_protocol == 'ssdp':
                        ssdp_count += 1
                        ssdp['frame_number'] = packet.number
                        ssdp['len_frame_pcap'] = packet.length_pcap_API
                        ssdp['len_frame_medium'] = packet.length_medium
                        ssdp['src_mac'] = source_mac
                        ssdp['dst_mac'] = destination_mac
                        ssdp['ether_type'] = packet.ethertype
                        ssdp['frame_type'] = packet.type
                        ssdp['app_protocol'] = packet.app_protocol
                        ssdp['src_ip'] = packet.src_ip
                        ssdp['dst_ip'] = packet.dst_ip 
                        
        
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
        if packet.app_protocol == 'ssdp':
            ssdp['hexa_frame'] = ruamel.yaml.scalarstring.LiteralScalarString(hexa)
            #find ssdp packets and append them to output
            ssdp_output['packets'].append(ssdp)

        output['packets'].append(out)

    ssdp_output['ssdp_count'] = ssdp_count
    ssdp_output['all_count'] = number
    ssdp_output['percent of ssdp'] = round(ssdp_count/number*100, 2)

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
    
    yaml.dump(ssdp_output, open('ssdp.yaml', 'w'))
    yaml.dump(output, open('output.yaml', 'w'))
    hex_txt.close()
    
# vypisuje icmp komunikacie
def analyseICMP():
    hex_txt = open('./txt/hex_packet.txt', 'r')
    icmp_txt = open('./txt/icmp_packet.txt', 'w')

    dict = read_types()
    number_n = 0
    complete_comms_number = 0
    partial_comms_number = 0
    output = {
    'name': 'PKS2022/23',
    'pcap_name': path,
    'filter_name': 'ICMP',
    'complete_comms': [],
    'partial_comms': []
}
    #write all icmp frames into separate txt file  
    for frame in hex_txt:
        number_n += 1
        # ethernet II and ICMP and is not fragmented
        if frame[24:28]== '0800' and frame[46:48] == '01' and int(frame[40:42], 16) == 0:
            icmp_txt.write(str(number_n) + '\n' + frame)

    icmp_txt.close()
    icmp_txt = open('./txt/icmp_packet.txt', 'r')
    for ramec in icmp_txt:
        ramec = ramec.strip()
        if ramec.isdigit():
            icmp_number = ramec
            continue

        packet = AnalysedPacket(ramec)
    
        out = {}
        reply = {}
        type = int(ramec[68:70], 16)
        typ = find_protocol(type, dict, '#ICMP')
                
        packet.length_pcap_API = int((len(ramec)) / 2)
        packet.length_medium = packet.length_pcap_API + 4
        if packet.length_medium < 64:
            packet.length_medium = 64

        packet.src_ip = convert_hexString_to_IP(ramec[52:60])
        packet.dst_ip = convert_hexString_to_IP(ramec[60:68])

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

        #format hexa_frame 
        hexa = ''
        for i in range(packet.length_pcap_API * 2):
            if i % 2 == 0 and i != 0 and i% 32 != 0:
                hexa += ' '
            if i % 32 == 0 and i != 0:
                hexa += '\n'
            hexa += ramec[i].upper()
        hexa += '\n'

        out['frame_number'] = int(icmp_number)
        out['len_frame_pcap'] = packet.length_pcap_API
        out['len_frame_medium'] = packet.length_medium
        out['frame_type'] = 'Ethernet II'
        out['src_mac'] = source_mac
        out['dst_mac'] = destination_mac
        out['ether_type'] = 'IPv4'
        out['src_ip'] = packet.src_ip
        out['dst_ip'] = packet.dst_ip
        out['id'] = int(ramec[36:38], 16)
        if int(ramec[40:42], 16) == 0:
            out['flags_mf'] = False
        else:
            out['flags_mf'] = True
        out['frag_offset']= int(ramec[40:44], 16)
        out['protocol'] = 'ICMP'
        if typ != '':
            out['icmp_type'] = typ
        out['hexa_frame'] = ruamel.yaml.scalarstring.LiteralScalarString(hexa)

        #if it finds type echo request, find reply to the request
        if type ==  8:
            reply_number = find_ICMP_reply(packet.dst_ip, packet.src_ip,icmp_number)
            #if found reply
            if reply_number != 'not found':
                complete_comms_number += 1
                complete_comm = {
                    'number_comm': complete_comms_number,
                    'src_comm': packet.src_ip,
                    'dst_comm': packet.dst_ip,
                    'packets': []
                }
                complete_comm['packets'].append(out)
                reply_txt = open('./txt/icmp_packet.txt', 'r')

                for frame in reply_txt:
                    frame = frame.strip()
                    if frame.isdigit():
                        frame_number = frame
                        continue
                    if frame_number != reply_number:
                            continue
                    frame_class = AnalysedPacket(frame)

                    type = int(frame[68:70], 16)
                    typ = find_protocol(type, dict, '#ICMP')

                    frame_class.length_pcap_API = int((len(ramec)) / 2)
                    frame_class.length_medium = frame_class.length_pcap_API + 4
                    if frame_class.length_medium < 64:
                        frame_class.length_medium = 64

                    frame_class.src_ip = convert_hexString_to_IP(ramec[52:60])
                    frame_class.dst_ip = convert_hexString_to_IP(ramec[60:68])

                    #format src_mac address
                    source_mac_n = ''
                    for(i, c) in enumerate(frame_class.src_mac):
                        if i % 2 == 0 and i != 0:
                            source_mac_n += ':'
                        source_mac_n += c

                    #format dst_mac address
                    dst_mac_n = ''
                    for(i, c) in enumerate(frame_class.dst_mac):
                        if i % 2 == 0 and i != 0:
                            dst_mac_n += ':'
                        dst_mac_n += c

                    #format hexa_frame 
                    hexa_n = ''
                    for i in range(frame_class.length_pcap_API * 2):
                        if i % 2 == 0 and i != 0 and i% 32 != 0:
                            hexa_n += ' '
                        if i % 32 == 0 and i != 0:
                            hexa_n += '\n'
                        hexa_n += ramec[i].upper()
                    hexa_n += '\n'
                    
                    reply['frame_number'] = int(frame_number)
                    reply['len_frame_pcap'] = frame_class.length_pcap_API
                    reply['len_frame_medium'] = frame_class.length_medium
                    reply['frame_type'] = 'Ethernet II'
                    reply['src_mac'] = source_mac_n
                    reply['dst_mac'] = dst_mac_n
                    reply['ether_type'] = 'IPv4'
                    reply['src_ip'] = frame_class.dst_ip
                    reply['dst_ip'] = frame_class.src_ip
                    reply['id'] = int(ramec[36:38], 16)
                    if int(ramec[40:42], 16) == 0:
                        reply['flags_mf'] = False
                    else:
                        reply['flags_mf'] = True
                    reply['frag_offset']= int(ramec[40:44], 16)
                    reply['protocol'] = 'ICMP'
                    if typ != '':
                        reply['icmp_type'] = typ
                    reply['hexa_frame'] = ruamel.yaml.scalarstring.LiteralScalarString(hexa_n)

                    complete_comm['packets'].append(reply)
                    output['complete_comms'].append(complete_comm)
                    break
            #if did not find reply
            else:
                partial_comms_number += 1
                partial_comm = {
                    'number_comm': partial_comms_number,
                    'packets': []
                }
                partial_comm['packets'].append(out)
                output['partial_comms'].append(partial_comm)
        #other types than request and reply should be ignored as partial comm
        elif type != 0:
            partial_comms_number += 1
            partial_comm = {
                'number_comm': partial_comms_number,
                'packets': []
            }
            partial_comm['packets'].append(out)
            output['partial_comms'].append(partial_comm)
    
    yaml.dump(output, open('output.yaml', 'w'))
    hex_txt.close()
    icmp_txt.close()
                    

def find_ICMP_reply(targetIP,senderIP,number):
    hex_txt = open('./txt/icmp_packet.txt', 'r')
    for ramec in hex_txt:
        ramec = ramec.strip()
        if ramec.isdigit():
            icmp_number = ramec
            continue
        if int(number) >= int(icmp_number):
            continue
        packet = AnalysedPacket(ramec)

        type = int(ramec[68:70], 16)
        packet.src_ip = convert_hexString_to_IP(ramec[52:60])
        packet.dst_ip = convert_hexString_to_IP(ramec[60:68])
        if type == 0 and packet.src_ip == targetIP and packet.dst_ip == senderIP:
            return icmp_number
    return 'not found'
    
ARP_output = {
    'name': 'PKS2022/23',
    'pcap_name': path,
    'filter_name': 'ARP',
    'complete_comms': [],
    'partial_comms': []
}

# organizuje, ci sa vypisuje uplna/neuplna komunikacia
def analyseARP():
    hex_txt = open('./txt/hex_packet.txt', 'r')
    arp_txt = open('./txt/arp_packet.txt', 'w')

    number = 0

    for frame in hex_txt:
        number += 1
        #ARP
        if frame[24:28] == '0806':
            arp_txt.write(str(number) + '\n' + frame)

    arp_txt.close()
    arp_txt = open('./txt/arp_packet.txt', 'r')

    count = 0
    reply_back = 0
    for ramec in arp_txt:
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
                vypis_neuplne_komunikacie(cislo_arp)

        if typ == 'reply' and int(reply_back) != int(cislo_arp):
            vypis_neuplne_komunikacie(cislo_arp, typ)


    yaml.dump(ARP_output, open('output.yaml', 'w'))
    hex_txt.close()

# zisti, ci ma ARP komunikacia reply
def find_reply(target_IP, sender_IP, cislo):
    arp_textak = open('./txt/arp_packet.txt', 'r')
    for ramec in arp_textak:
        ramec = ramec.strip()
        if ramec.isdigit():
            reply = ramec
            continue
        if int(cislo) >= int(reply):
            continue
        if ramec[43] == '2' and target_IP == convert_hexString_to_IP(ramec[56:64]) and sender_IP == convert_hexString_to_IP(ramec[76:84]):
            arp_textak.close()
            return reply
    return ''

# vypise neuplne komunikacie
def vypis_neuplne_komunikacie(cislo):
    arp_packet = open('./txt/arp_packet.txt', 'r')

    number = 0
    for ramec in arp_packet:
        out = {}
        ramec = ramec.strip()
        if ramec.isdigit():
            number += 1
            ciselko = ramec
            continue
        if ciselko == cislo:
            partial_comm = {
            'number_comm': number,
            'packets': []
        }
            dst_mac = ramec[:12]
            src_mac = ramec[12:24]

            length_pcap_API = int((len(ramec) - 1) / 2)
            length_medium = length_pcap_API + 4
            if length_medium < 64:
                length_medium = 64

            target_IP = convert_hexString_to_IP(ramec[76:84])
            sender_IP = convert_hexString_to_IP(ramec[56:64])

            #format src_mac address
            source_mac = ''
            for(i, c) in enumerate(src_mac):
                if i % 2 == 0 and i != 0:
                    source_mac += ':'
                source_mac += c

            #format dst_mac address
            destination_mac = ''
            for(i, c) in enumerate(dst_mac):
                if i % 2 == 0 and i != 0:
                    destination_mac += ':'
                destination_mac += c

            #format hexa_frame 
            hexa = ''
            for i in range(length_pcap_API * 2):
                if i % 2 == 0 and i != 0 and i% 32 != 0:
                    hexa += ' '
                if i % 32 == 0 and i != 0:
                    hexa += '\n'
                hexa += ramec[i].upper()
            hexa += '\n'

            out['frame_number'] = int(ciselko)
            out['len_frame_pcap'] = length_pcap_API
            out['len_frame_medium'] = length_medium
            out['frame_type'] = 'Ethernet II'
            out['src_mac'] = source_mac
            out['dst_mac'] = destination_mac
            out['ether_type'] = 'IPv4'
            out['src_ip'] = sender_IP
            out['dst_ip'] = target_IP
            out['ether_type'] = 'ARP'
            if ramec[43] == '1':
                out['arp_opcode'] = 'REQUEST'
            elif ramec[43] == '2':
                out['arp_opcode'] = 'REPLY'
            out['hexa_frame'] = ruamel.yaml.scalarstring.LiteralScalarString(hexa)

            partial_comm['packets'].append(out)
            ARP_output['partial_comms'].append(partial_comm)
            

    arp_packet.close()

# vypise vsetky ramce uplnych arp komunikacii
def vypis_all_same_req(target_IP, sender_IP, cislo_req, cislo_reply, cislo_komunikacie):
    arp_paket = open('./txt/arp_packet.txt', 'r')
    complete_comm = {
        'number_comm': cislo_komunikacie,
        'src_comm': sender_IP,
        'dst_comm': target_IP,
        'packets': []
        }

    for ramec in arp_paket:
        out = {}
        ramec = ramec.strip()
        if ramec.isdigit():
            number_n = ramec
            continue
        here_sender_IP = convert_hexString_to_IP(ramec[56:64])
        here_target_IP = convert_hexString_to_IP(ramec[76:84])
        #if it is request and it is the same request
        if int(number_n) >= int(cislo_req) and int(number_n) < int(cislo_reply) and target_IP == here_target_IP and sender_IP == here_sender_IP:
            dst_mac = ramec[:12]
            src_mac = ramec[12:24]

            length_pcap_API = int((len(ramec)) / 2)
            length_medium = length_pcap_API + 4
            if length_medium < 64:
                length_medium = 64

            #format src_mac address
            source_mac = ''
            for(i, c) in enumerate(src_mac):
                if i % 2 == 0 and i != 0:
                    source_mac += ':'
                source_mac += c

            #format dst_mac address
            destination_mac = ''
            for(i, c) in enumerate(dst_mac):
                if i % 2 == 0 and i != 0:
                    destination_mac += ':'
                destination_mac += c

            #format hexa_frame 
            hexa = ''
            for i in range(length_pcap_API * 2):
                if i % 2 == 0 and i != 0 and i% 32 != 0:
                    hexa += ' '
                if i % 32 == 0 and i != 0:
                    hexa += '\n'
                hexa += ramec[i].upper()
            hexa += '\n'

            out['frame_number'] = int(number_n)
            out['len_frame_pcap'] = length_pcap_API
            out['len_frame_medium'] = length_medium
            out['frame_type'] = 'Ethernet II'
            out['src_mac'] = source_mac
            out['dst_mac'] = destination_mac
            out['ether_type'] = 'ARP'
            out['arp_opcode'] = 'REQUEST'
            out['src_ip'] = here_sender_IP
            out['dst_ip'] = here_target_IP
            out['hexa_frame'] = ruamel.yaml.scalarstring.LiteralScalarString(hexa)

            complete_comm['packets'].append(out)
            # ARP_output['complete_comms'].append(complete_comm)
        #reply
        elif int(number_n) == int(cislo_reply):
            dst_mac = ramec[:12]
            src_mac = ramec[12:24]

            length_pcap_API = int((len(ramec)) / 2)

            length_medium = length_pcap_API + 4
            if length_medium < 64:
                length_medium = 64

            #format src_mac address
            source_mac = ''
            for(i, c) in enumerate(src_mac):
                if i % 2 == 0 and i != 0:
                    source_mac += ':'
                source_mac += c

            #format dst_mac address
            destination_mac = ''
            for(i, c) in enumerate(dst_mac):
                if i % 2 == 0 and i != 0:
                    destination_mac += ':'
                destination_mac += c

            #format hexa_frame 
            hexa = ''
            for i in range(length_pcap_API * 2):
                if i % 2 == 0 and i != 0 and i% 32 != 0:
                    hexa += ' '
                if i % 32 == 0 and i != 0:
                    hexa += '\n'
                hexa += ramec[i].upper()
            hexa += '\n'

            out['frame_number'] = int(number_n)
            out['len_frame_pcap'] = length_pcap_API
            out['len_frame_medium'] = length_medium
            out['frame_type'] = 'Ethernet II'
            out['src_mac'] = source_mac
            out['dst_mac'] = destination_mac
            out['ether_type'] = 'ARP'
            out['arp_opcode'] = 'REPLY'
            out['src_ip'] = here_sender_IP
            out['dst_ip'] = here_target_IP
            out['hexa_frame'] = ruamel.yaml.scalarstring.LiteralScalarString(hexa)

            complete_comm['packets'].append(out)
            break

        #reply without request
        elif int(number_n) > int(cislo_reply):
            return cislo_reply
        
    ARP_output['complete_comms'].append(complete_comm)
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

#define args
def find_args():
    parser = argparse.ArgumentParser(description='Packet Analyser')
    parser.add_argument('-p','--protocol', help='Protocol name (e.g ARP, TFTP, ICMP)', required=False)
    args = parser.parse_args()
    if args.protocol != None:
        args = args.protocol.upper()
        if(args != 'ARP' and args != 'ICMP'):
            print('Either wrong protocol name, or the protocol is not implemented')
            exit()
        return args

args = find_args()

savePcap()

if args == 'ARP':
    analyseARP()
elif args == 'ICMP':
    analyseICMP()
else:
    analyse()
from ciscoconfparse import CiscoConfParse
import asa
import csv
import time

start_time = time.time()

f = open('./asa.conf')
config_file = f.readlines()
f.close()

asaports = [{"Description": "Echo", "Port": "7", "Name": "echo", "Proto": "TCP, UDP"}, {"Description": "Discard", "Port": "9", "Name": "discard", "Proto": "TCP, UDP"}, {"Description": "Day time, RFC 867", "Port": "13", "Name": "daytime", "Proto": "TCP"}, {"Description": "Character Generator", "Port": "19", "Name": "chargen", "Proto": "TCP"}, {"Description": "File Transfer Protocol (data port)", "Port": "20", "Name": "ftp-data", "Proto": "TCP"}, {"Description": "File Transfer Protocol (control port)", "Port": "21", "Name": "ftp", "Proto": "TCP"}, {"Description": "Secure Shell", "Port": "22", "Name": "ssh", "Proto": "TCP"}, {"Description": "RFC 854 Telnet", "Port": "23", "Name": "telnet", "Proto": "TCP"}, {"Description": "Simple Mail Transport Protocol", "Port": "25", "Name": "smtp", "Proto": "TCP"}, {"Description": "Time", "Port": "37", "Name": "time", "Proto": "UDP"}, {"Description": "Host Name Server", "Port": "42", "Name": "nameserver", "Proto": "UDP"}, {"Description": "Who Is", "Port": "43", "Name": "whois", "Proto": "TCP"}, {"Description": "Terminal Access Controller Access Control System Plus", "Port": "49", "Name": "tacacs", "Proto": "TCP, UDP"}, {"Description": "DNS", "Port": "53", "Name": "domain", "Proto": "TCP, UDP"}, {"Description": "Bootstrap Protocol Server", "Port": "67", "Name": "bootps", "Proto": "UDP"}, {"Description": "Bootstrap Protocol Client", "Port": "68", "Name": "bootpc", "Proto": "UDP"}, {"Description": "Trivial File Transfer Protocol", "Port": "69", "Name": "tftp", "Proto": "UDP"}, {"Description": "Gopher", "Port": "70", "Name": "gopher", "Proto": "TCP"}, {"Description": "Finger", "Port": "79", "Name": "finger", "Proto": "TCP"}, {"Description": "World Wide Web HTTP", "Port": "80", "Name": "http", "Proto": "TCP, UDP"}, {"Description": "World Wide Web", "Port": "80", "Name": "www", "Proto": "TCP, UDP"}, {"Description": "NIC Host Name Server", "Port": "101", "Name": "hostname", "Proto": "TCP"}, {"Description": "Post Office Protocol - Version 2", "Port": "109", "Name": "pop2", "Proto": "TCP"}, {"Description": "Post Office Protocol - Version 3", "Port": "110", "Name": "pop3", "Proto": "TCP"}, {"Description": "Sun Remote Procedure Call", "Port": "111", "Name": "sunrpc", "Proto": "TCP, UDP"}, {"Description": "Ident authentication service", "Port": "113", "Name": "ident", "Proto": "TCP"}, {"Description": "Network News Transfer Protocol", "Port": "119", "Name": "nntp", "Proto": "TCP"}, {"Description": "Network Time Protocol", "Port": "123", "Name": "ntp", "Proto": "UDP"}, {"Description": "NetBIOS Name Service", "Port": "137", "Name": "netbios-ns", "Proto": "UDP"}, {"Description": "NetBIOS Datagram Service", "Port": "138", "Name": "netbios-dgm", "Proto": "UDP"}, {"Description": "NetBIOS Session Service", "Port": "139", "Name": "netbios-ssn", "Proto": "TCP"}, {"Description": "Internet Message Access Protocol, version 4", "Port": "143", "Name": "imap4", "Proto": "TCP"}, {"Description": "Simple Network Management Protocol", "Port": "161", "Name": "snmp", "Proto": "UDP"}, {"Description": "Simple Network Management Protocol - Trap", "Port": "162", "Name": "snmptrap", "Proto": "UDP"}, {"Description": "X Display Manager Control Protocol", "Port": "177", "Name": "xdmcp", "Proto": "UDP"}, {"Description": "Internet Relay Chat protocol", "Port": "194", "Name": "irc", "Proto": "TCP"}, {"Description": "DNSIX Session Management Module Audit Redirector", "Port": "195", "Name": "dnsix", "Proto": "UDP"}, {"Description": "Lightweight Directory Access Protocol", "Port": "389", "Name": "ldap", "Proto": "TCP"}, {"Description": "Mobile IP-Agent", "Port": "434", "Name": "mobile-ip", "Proto": "UDP"}, {"Description": "HTTP over SSL", "Port": "443", "Name": "https", "Proto": "TCP"}, {"Description": "Protocol Independent Multicast, reverse path flooding, dense mode", "Port": "496", "Name": "pim-auto-rp", "Proto": "TCP, UDP"}, {"Description": "Internet Security Association and Key Management Protocol", "Port": "500", "Name": "isakmp", "Proto": "UDP"}, {"Description": "Used by mail system to notify users that new mail is received", "Port": "512", "Name": "biff", "Proto": "UDP"}, {"Description": "Remote process execution", "Port": "512", "Name": "exec", "Proto": "TCP"}, {"Description": "Remote login", "Port": "513", "Name": "login", "Proto": "TCP"}, {"Description": "Who", "Port": "513", "Name": "who", "Proto": "UDP"}, {"Description": "Remote Shell", "Port": "514", "Name": "rsh", "Proto": "TCP"}, {"Description": "Similar to exec except that cmd has automatic authentication", "Port": "514", "Name": "cmd", "Proto": "TCP"}, {"Description": "System Log", "Port": "514", "Name": "syslog", "Proto": "UDP"}, {"Description": "Line Printer Daemon - printer spooler", "Port": "515", "Name": "lpd", "Proto": "TCP"}, {"Description": "Talk", "Port": "517", "Name": "talk", "Proto": "TCP, UDP"}, {"Description": "Routing Information Protocol", "Port": "520", "Name": "rip", "Proto": "UDP"}, {"Description": "UNIX-to-UNIX Copy Program", "Port": "540", "Name": "uucp", "Proto": "TCP"}, {"Description": "KLOGIN", "Port": "543", "Name": "klogin", "Proto": "TCP"}, {"Description": "Korn Shell", "Port": "544", "Name": "kshell", "Proto": "TCP"}, {"Description": "Real Time Streaming Protocol", "Port": "554", "Name": "rtsp", "Proto": "TCP"}, {"Description": "Lightweight Directory Access Protocol (SSL)", "Port": "636", "Name": "ldaps", "Proto": "TCP"}, {"Description": "Kerberos", "Port": "750", "Name": "kerberos", "Proto": "TCP, UDP"}, {"Description": "IBM Lotus Notes", "Port": "1352", "Name": "lotusnotes", "Proto": "TCP"}, {"Description": "Citrix Independent Computing Architecture (ICA) protocol", "Port": "1494", "Name": "citrix-ica", "Proto": "TCP"}, {"Description": "Structured Query Language Network", "Port": "1521", "Name": "sqlnet", "Proto": "TCP"}, {"Description": "Remote Authentication Dial-In User Service", "Port": "1645", "Name": "radius", "Proto": "UDP"}, {"Description": "Remote Authentication Dial-In User Service (accounting)", "Port": "1646", "Name": "radius-acct", "Proto": "UDP"}, {"Description": "H.323 call signaling", "Port": "1720", "Name": "h323", "Proto": "TCP"}, {"Description": "Point-to-Point Tunneling Protocol", "Port": "1723", "Name": "pptp", "Proto": "TCP"}, {"Description": "Network File System - Sun Microsystems", "Port": "2049", "Name": "nfs", "Proto": "TCP, UDP"}, {"Description": "Computer Telephony Interface Quick Buffer Encoding", "Port": "2748", "Name": "ctiqbe", "Proto": "TCP"}, {"Description": "Common Internet File System", "Port": "3020", "Name": "cifs", "Proto": "TCP, UDP"}, {"Description": "Virtual eXtensible Local Area Network (VXLAN)", "Port": "4789", "Name": "vxlan", "Proto": "UDP"}, {"Description": "Session Initiation Protocol", "Port": "5060", "Name": "sip", "Proto": "TCP, UDP"}, {"Description": "America Online", "Port": "5190", "Name": "aol", "Proto": "TCP"}, {"Description": "SecureID over UDP", "Port": "5510", "Name": "secureid-udp", "Proto": "UDP"}, {"Description": "pcAnywhere data", "Port": "5631", "Name": "pcanywhere-data", "Proto": "TCP"}, {"Description": "pcAnywhere status", "Port": "5632", "Name": "pcanywhere-status", "Proto": "UDP"}, {"Description": "Border Gateway Protocol, RFC 1163", "Port": "179", "Name": "bgp", "Proto": "TCP"}]

parse = CiscoConfParse(config_file)

# Load Network Objects
external = asa.NetworkObject(name = 'External')
external.addNetwork(ip = '0.0.0.0',mask='0.0.0.0')

lines = parse.find_objects(r"object network")
netobjects = {}

for netobject in parse.find_objects(r"object network"):
    obj = asa.NetworkObject(name = netobject.text.split(' ')[2].strip())
    for child in netobject.children:
        components = child.text.strip().split(' ')
        if components[0] == 'host':
            obj.addNetwork(ip = components[1], mask = '255.255.255.255')
        elif components[0] == 'subnet':
            obj.addNetwork(ip = components[1], mask = components[2])
    netobjects[obj.name] = obj

# Load ASA Ports/Text Translation
#asaports = []
#with open('asa_ports.csv') as protocol_file:
#    reader = csv.DictReader(protocol_file)
#    for row in reader:
#        asaports.append(row)

# Load in the IANA Protocols
protocols = {}
with open('protocol-numbers-1.csv') as protocol_file:
    reader = csv.DictReader(protocol_file)
    for row in reader:
        protocols[row['Keyword'].lower()]=row

# Load Access Lists
acl_lines = parse.find_objects(r"access-list")
acls = {}

for line in acl_lines:
    words = line.text.strip().split(' ')
    if words[1] not in acls.keys():
        acls[words[1]] = asa.AccessList(name = words[1])
    if words[3] == 'permit':
        permit = True
    else:
        permit = False
    protocol = protocols[words[4].lower()]['Decimal']
    i = 5
    if words[5] == 'any':
        source = external
        i += 1
    else:
        source = netobjects[words[6]]
        i += 2
    if words[i] == 'any':
        dest = external
        i += 1
    else:
        dest = netobjects[words[i+1]]
        i += 2
    if i >= len(words):
        port_min = None
        port_max = None
    elif words[i] == 'eq':
        if len([x for x in asaports if x['Name'] == words[i+1]]) == 1:
            port_min = [x for x in asaports if x['Name'] == words[i+1]][0]['Port']
        else:
            port_min = (int(words[i+1]))
        port_max = None
    elif words[i] == 'range':
        ports = words[i+1].strip().split('-')
        port_min = ports[0]
        port_max = ports[1]

    acls[words[1]].addRule(asa.Rule(text = line.text.strip(), source = source, dest = dest, port_min = port_min, port_max = port_max, permit = permit))



print acls.keys()
#for rule in acls['ACL_IN'].rules:
#    print rule

print("--- %s seconds ---" % (time.time() - start_time))

import ipcalc
import ipaddress
from ciscoconfparse import CiscoConfParse
import csv
import json

class Rule(object):
    def __init__(self, text, source, dest, permit, port_min, port_max,protocol):
        self._policy = {}
        self._policy['text'] = text
        self._policy['source'] = source
        self._policy['dest'] = dest
        self._policy['port_min'] = port_min
        self._policy['port_max'] = port_max
        self._policy['protocol'] = protocol
        self._applications = []
        self._srcClusters = []
        self._dstClusters = []
        self._permit = permit

    def __eq__(self, other):
        return self._policy == other._policy

    def __str__(self):
        return str(self._policy)

    @property
    def source(self):
        return self._policy['source']

    @source.setter
    def source(self, value):
        self._policy['source'] = value

    @property
    def dest(self):
        return self._policy['dest']

    @dest.setter
    def dest(self, value):
        self._policy['dest'] = value

    @property
    def port_min(self):
        return self._policy['port_min']

    @port_min.setter
    def port_min(self, value):
        self._policy['port_min'] = value

    @property
    def port_max(self):
        return self._policy['port_max']

    @port_max.setter
    def port_max(self, value):
        self._policy['port_max'] = value

    @property
    def protocol(self):
        return self._policy['protocol']

    @protocol.setter
    def protocol(self, value):
        self._policy['protocol'] = value

    @property
    def permit(self):
        return self._policy['permit']

    @permit.setter
    def permit(self, value):
        self._policy['permit'] = value

    @property
    def applications(self):
        return self._applications

    @applications.setter
    def applications(self, value):
        self._applications = value

    @property
    def srcClusters(self):
        return self._srcClusters

    @srcClusters.setter
    def srcClusters(self, value):
        self._srcClusters = value

    @property
    def dstClusters(self):
        return self._dstClusters

    @dstClusters.setter
    def dstClusters(self, value):
        self._dstClusters = value

    @property
    def text(self):
        return self._policy['text']

    @text.setter
    def text(self, value):
        self._policy['text'] = value



class NetworkObject(object):
    def __init__(self, name):
        self._objects = []
        self._name = name

    def __str__(self):
        return str({'name':self._name, 'objects':self._objects})

    @property
    def networks(self):
        return self._objects

    def addNetwork(self, ip, mask):
        self._objects.append({'ip':ip,'mask':mask})

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def applications(self):
        return self._applications

    @applications.setter
    def applications(self, value):
        self._applications = value

    @property
    def clusters(self):
        return self._clusters

    @clusters.setter
    def clusters(self, value):
        self._clusters = value


class AccessList(object):
    def __init__(self, name):
        self._rules = []
        self._name = name

    def __str__(self):
        return str({'name':self._name, 'rules':self._rules})

    @property
    def rules(self):
        return self._rules

    def addRule(self, rule):
        self._rules.append(rule)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value


class ObjectGroup(object):
    def __init__(self, policy):
        self._policy = policy

    def __eq__(self, other):
        return self._policy == other._policy

    def __str__(self):
        return str(self._policy)

class ASA(object):
    def __init__(self):
        self._networkObjects = {}
        self._accessLists = {}
        self._objectGroups = {}

    @property
    def networkObjects(self):
        return self._networkObjects

    @property
    def accessLists(self):
        return self._accessLists

    @property
    def objectGroups(self):
        return self._objectGroups

    def loadConfig(self, config_file):

        parse = CiscoConfParse(config_file)

        # Load Network Objects
        external = NetworkObject(name = 'External')
        external.addNetwork(ip = '0.0.0.0',mask='0.0.0.0')

        lines = parse.find_objects(r"object network")
        self._networkObjects = {}

        for netobject in parse.find_objects(r"object network"):
            obj = NetworkObject(name = netobject.text.split(' ')[2].strip())
            for child in netobject.children:
                components = child.text.strip().split(' ')
                if components[0] == 'host':
                    obj.addNetwork(ip = components[1], mask = '255.255.255.255')
                elif components[0] == 'subnet':
                    obj.addNetwork(ip = components[1], mask = components[2])
            self._networkObjects[obj.name] = obj

        # Load ASA Ports/Text Translation
        asaports = [{"Description": "Echo", "Port": "7", "Name": "echo", "Proto": "TCP, UDP"}, {"Description": "Discard", "Port": "9", "Name": "discard", "Proto": "TCP, UDP"}, {"Description": "Day time, RFC 867", "Port": "13", "Name": "daytime", "Proto": "TCP"}, {"Description": "Character Generator", "Port": "19", "Name": "chargen", "Proto": "TCP"}, {"Description": "File Transfer Protocol (data port)", "Port": "20", "Name": "ftp-data", "Proto": "TCP"}, {"Description": "File Transfer Protocol (control port)", "Port": "21", "Name": "ftp", "Proto": "TCP"}, {"Description": "Secure Shell", "Port": "22", "Name": "ssh", "Proto": "TCP"}, {"Description": "RFC 854 Telnet", "Port": "23", "Name": "telnet", "Proto": "TCP"}, {"Description": "Simple Mail Transport Protocol", "Port": "25", "Name": "smtp", "Proto": "TCP"}, {"Description": "Time", "Port": "37", "Name": "time", "Proto": "UDP"}, {"Description": "Host Name Server", "Port": "42", "Name": "nameserver", "Proto": "UDP"}, {"Description": "Who Is", "Port": "43", "Name": "whois", "Proto": "TCP"}, {"Description": "Terminal Access Controller Access Control System Plus", "Port": "49", "Name": "tacacs", "Proto": "TCP, UDP"}, {"Description": "DNS", "Port": "53", "Name": "domain", "Proto": "TCP, UDP"}, {"Description": "Bootstrap Protocol Server", "Port": "67", "Name": "bootps", "Proto": "UDP"}, {"Description": "Bootstrap Protocol Client", "Port": "68", "Name": "bootpc", "Proto": "UDP"}, {"Description": "Trivial File Transfer Protocol", "Port": "69", "Name": "tftp", "Proto": "UDP"}, {"Description": "Gopher", "Port": "70", "Name": "gopher", "Proto": "TCP"}, {"Description": "Finger", "Port": "79", "Name": "finger", "Proto": "TCP"}, {"Description": "World Wide Web HTTP", "Port": "80", "Name": "http", "Proto": "TCP, UDP"}, {"Description": "World Wide Web", "Port": "80", "Name": "www", "Proto": "TCP, UDP"}, {"Description": "NIC Host Name Server", "Port": "101", "Name": "hostname", "Proto": "TCP"}, {"Description": "Post Office Protocol - Version 2", "Port": "109", "Name": "pop2", "Proto": "TCP"}, {"Description": "Post Office Protocol - Version 3", "Port": "110", "Name": "pop3", "Proto": "TCP"}, {"Description": "Sun Remote Procedure Call", "Port": "111", "Name": "sunrpc", "Proto": "TCP, UDP"}, {"Description": "Ident authentication service", "Port": "113", "Name": "ident", "Proto": "TCP"}, {"Description": "Network News Transfer Protocol", "Port": "119", "Name": "nntp", "Proto": "TCP"}, {"Description": "Network Time Protocol", "Port": "123", "Name": "ntp", "Proto": "UDP"}, {"Description": "NetBIOS Name Service", "Port": "137", "Name": "netbios-ns", "Proto": "UDP"}, {"Description": "NetBIOS Datagram Service", "Port": "138", "Name": "netbios-dgm", "Proto": "UDP"}, {"Description": "NetBIOS Session Service", "Port": "139", "Name": "netbios-ssn", "Proto": "TCP"}, {"Description": "Internet Message Access Protocol, version 4", "Port": "143", "Name": "imap4", "Proto": "TCP"}, {"Description": "Simple Network Management Protocol", "Port": "161", "Name": "snmp", "Proto": "UDP"}, {"Description": "Simple Network Management Protocol - Trap", "Port": "162", "Name": "snmptrap", "Proto": "UDP"}, {"Description": "X Display Manager Control Protocol", "Port": "177", "Name": "xdmcp", "Proto": "UDP"}, {"Description": "Internet Relay Chat protocol", "Port": "194", "Name": "irc", "Proto": "TCP"}, {"Description": "DNSIX Session Management Module Audit Redirector", "Port": "195", "Name": "dnsix", "Proto": "UDP"}, {"Description": "Lightweight Directory Access Protocol", "Port": "389", "Name": "ldap", "Proto": "TCP"}, {"Description": "Mobile IP-Agent", "Port": "434", "Name": "mobile-ip", "Proto": "UDP"}, {"Description": "HTTP over SSL", "Port": "443", "Name": "https", "Proto": "TCP"}, {"Description": "Protocol Independent Multicast, reverse path flooding, dense mode", "Port": "496", "Name": "pim-auto-rp", "Proto": "TCP, UDP"}, {"Description": "Internet Security Association and Key Management Protocol", "Port": "500", "Name": "isakmp", "Proto": "UDP"}, {"Description": "Used by mail system to notify users that new mail is received", "Port": "512", "Name": "biff", "Proto": "UDP"}, {"Description": "Remote process execution", "Port": "512", "Name": "exec", "Proto": "TCP"}, {"Description": "Remote login", "Port": "513", "Name": "login", "Proto": "TCP"}, {"Description": "Who", "Port": "513", "Name": "who", "Proto": "UDP"}, {"Description": "Remote Shell", "Port": "514", "Name": "rsh", "Proto": "TCP"}, {"Description": "Similar to exec except that cmd has automatic authentication", "Port": "514", "Name": "cmd", "Proto": "TCP"}, {"Description": "System Log", "Port": "514", "Name": "syslog", "Proto": "UDP"}, {"Description": "Line Printer Daemon - printer spooler", "Port": "515", "Name": "lpd", "Proto": "TCP"}, {"Description": "Talk", "Port": "517", "Name": "talk", "Proto": "TCP, UDP"}, {"Description": "Routing Information Protocol", "Port": "520", "Name": "rip", "Proto": "UDP"}, {"Description": "UNIX-to-UNIX Copy Program", "Port": "540", "Name": "uucp", "Proto": "TCP"}, {"Description": "KLOGIN", "Port": "543", "Name": "klogin", "Proto": "TCP"}, {"Description": "Korn Shell", "Port": "544", "Name": "kshell", "Proto": "TCP"}, {"Description": "Real Time Streaming Protocol", "Port": "554", "Name": "rtsp", "Proto": "TCP"}, {"Description": "Lightweight Directory Access Protocol (SSL)", "Port": "636", "Name": "ldaps", "Proto": "TCP"}, {"Description": "Kerberos", "Port": "750", "Name": "kerberos", "Proto": "TCP, UDP"}, {"Description": "IBM Lotus Notes", "Port": "1352", "Name": "lotusnotes", "Proto": "TCP"}, {"Description": "Citrix Independent Computing Architecture (ICA) protocol", "Port": "1494", "Name": "citrix-ica", "Proto": "TCP"}, {"Description": "Structured Query Language Network", "Port": "1521", "Name": "sqlnet", "Proto": "TCP"}, {"Description": "Remote Authentication Dial-In User Service", "Port": "1645", "Name": "radius", "Proto": "UDP"}, {"Description": "Remote Authentication Dial-In User Service (accounting)", "Port": "1646", "Name": "radius-acct", "Proto": "UDP"}, {"Description": "H.323 call signaling", "Port": "1720", "Name": "h323", "Proto": "TCP"}, {"Description": "Point-to-Point Tunneling Protocol", "Port": "1723", "Name": "pptp", "Proto": "TCP"}, {"Description": "Network File System - Sun Microsystems", "Port": "2049", "Name": "nfs", "Proto": "TCP, UDP"}, {"Description": "Computer Telephony Interface Quick Buffer Encoding", "Port": "2748", "Name": "ctiqbe", "Proto": "TCP"}, {"Description": "Common Internet File System", "Port": "3020", "Name": "cifs", "Proto": "TCP, UDP"}, {"Description": "Virtual eXtensible Local Area Network (VXLAN)", "Port": "4789", "Name": "vxlan", "Proto": "UDP"}, {"Description": "Session Initiation Protocol", "Port": "5060", "Name": "sip", "Proto": "TCP, UDP"}, {"Description": "America Online", "Port": "5190", "Name": "aol", "Proto": "TCP"}, {"Description": "SecureID over UDP", "Port": "5510", "Name": "secureid-udp", "Proto": "UDP"}, {"Description": "pcAnywhere data", "Port": "5631", "Name": "pcanywhere-data", "Proto": "TCP"}, {"Description": "pcAnywhere status", "Port": "5632", "Name": "pcanywhere-status", "Proto": "UDP"}, {"Description": "Border Gateway Protocol, RFC 1163", "Port": "179", "Name": "bgp", "Proto": "TCP"}]

        # Load in the IANA Protocols
        protocols = {"": {"Decimal": "254", "Protocol": "Use for experimentation and testing", "IPv6 Extension Header": "Y", "Keyword": "", "Reference": "[RFC3692]"}, "skip": {"Decimal": "57", "Protocol": "SKIP", "IPv6 Extension Header": "", "Keyword": "SKIP", "Reference": "[Tom_Markson]"}, "ttp": {"Decimal": "84", "Protocol": "Transaction Transport Protocol", "IPv6 Extension Header": "", "Keyword": "TTP", "Reference": "[Jim_Stevens]"}, "tcp": {"Decimal": "6", "Protocol": "Transmission Control", "IPv6 Extension Header": "", "Keyword": "TCP", "Reference": "[RFC793]"}, "chaos": {"Decimal": "16", "Protocol": "Chaos", "IPv6 Extension Header": "", "Keyword": "CHAOS", "Reference": "[J_Noel_Chiappa]"}, "iptm": {"Decimal": "84", "Protocol": "Internet Protocol Traffic Manager", "IPv6 Extension Header": "", "Keyword": "IPTM", "Reference": "[Jim_Stevens]"}, "netblt": {"Decimal": "30", "Protocol": "Bulk Data Transfer Protocol", "IPv6 Extension Header": "", "Keyword": "NETBLT", "Reference": "[RFC969][David_Clark]"}, "tcf": {"Decimal": "87", "Protocol": "TCF", "IPv6 Extension Header": "", "Keyword": "TCF", "Reference": "[Guillermo_A_Loyola]"}, "crtp": {"Decimal": "126", "Protocol": "Combat Radio Transport Protocol", "IPv6 Extension Header": "", "Keyword": "CRTP", "Reference": "[Robert_Sautter]"}, "ax.25": {"Decimal": "93", "Protocol": "AX.25 Frames", "IPv6 Extension Header": "", "Keyword": "AX.25", "Reference": "[Brian_Kantor]"}, "ptp": {"Decimal": "123", "Protocol": "Performance Transparency Protocol", "IPv6 Extension Header": "", "Keyword": "PTP", "Reference": "[Michael_Welzl]"}, "merit-inp": {"Decimal": "32", "Protocol": "MERIT Internodal Protocol", "IPv6 Extension Header": "", "Keyword": "MERIT-INP", "Reference": "[Hans_Werner_Braun]"}, "xtp": {"Decimal": "36", "Protocol": "XTP", "IPv6 Extension Header": "", "Keyword": "XTP", "Reference": "[Greg_Chesson]"}, "crudp": {"Decimal": "127", "Protocol": "Combat Radio User Datagram", "IPv6 Extension Header": "", "Keyword": "CRUDP", "Reference": "[Robert_Sautter]"}, "argus (deprecated)": {"Decimal": "13", "Protocol": "ARGUS", "IPv6 Extension Header": "", "Keyword": "ARGUS (deprecated)", "Reference": "[Robert_W_Scheifler]"}, "ipcomp": {"Decimal": "108", "Protocol": "IP Payload Compression Protocol", "IPv6 Extension Header": "", "Keyword": "IPComp", "Reference": "[RFC2393]"}, "a/n": {"Decimal": "107", "Protocol": "Active Networks", "IPv6 Extension Header": "", "Keyword": "A/N", "Reference": "[Bob_Braden]"}, "aris": {"Decimal": "104", "Protocol": "ARIS", "IPv6 Extension Header": "", "Keyword": "ARIS", "Reference": "[Nancy_Feldman]"}, "bna": {"Decimal": "49", "Protocol": "BNA", "IPv6 Extension Header": "", "Keyword": "BNA", "Reference": "[Gary Salamon]"}, "rsvp": {"Decimal": "46", "Protocol": "Reservation Protocol", "IPv6 Extension Header": "", "Keyword": "RSVP", "Reference": "[RFC2205][RFC3209][Bob_Braden]"}, "hip": {"Decimal": "139", "Protocol": "Host Identity Protocol", "IPv6 Extension Header": "Y", "Keyword": "HIP", "Reference": "[RFC7401]"}, "iatp": {"Decimal": "117", "Protocol": "Interactive Agent Transfer Protocol", "IPv6 Extension Header": "", "Keyword": "IATP", "Reference": "[John_Murphy]"}, "3pc": {"Decimal": "34", "Protocol": "Third Party Connect Protocol", "IPv6 Extension Header": "", "Keyword": "3PC", "Reference": "[Stuart_A_Friedberg]"}, "iso-ip": {"Decimal": "80", "Protocol": "ISO Internet Protocol", "IPv6 Extension Header": "", "Keyword": "ISO-IP", "Reference": "[Marshall_T_Rose]"}, "udplite": {"Decimal": "136", "Protocol": "", "IPv6 Extension Header": "", "Keyword": "UDPLite", "Reference": "[RFC3828]"}, "emcon": {"Decimal": "14", "Protocol": "EMCON", "IPv6 Extension Header": "", "Keyword": "EMCON", "Reference": "[<mystery contact>]"}, "wsn": {"Decimal": "74", "Protocol": "Wang Span Network", "IPv6 Extension Header": "", "Keyword": "WSN", "Reference": "[Victor Dafoulas]"}, "idpr": {"Decimal": "35", "Protocol": "Inter-Domain Policy Routing Protocol", "IPv6 Extension Header": "", "Keyword": "IDPR", "Reference": "[Martha_Steenstrup]"}, "br-sat-mon": {"Decimal": "76", "Protocol": "Backroom SATNET Monitoring", "IPv6 Extension Header": "", "Keyword": "BR-SAT-MON", "Reference": "[Steven_Blumenthal]"}, "cftp": {"Decimal": "62", "Protocol": "CFTP", "IPv6 Extension Header": "", "Keyword": "CFTP", "Reference": "[Forsdick, H., \"CFTP\", Network Message, Bolt Beranek and\nNewman, January 1982.][Harry_Forsdick]"}, "pvp": {"Decimal": "75", "Protocol": "Packet Video Protocol", "IPv6 Extension Header": "", "Keyword": "PVP", "Reference": "[Steve_Casner]"}, "sm (deprecated)": {"Decimal": "122", "Protocol": "Simple Multicast Protocol", "IPv6 Extension Header": "", "Keyword": "SM (deprecated)", "Reference": "[Jon_Crowcroft][draft-perlman-simple-multicast]"}, "ipip": {"Decimal": "94", "Protocol": "IP-within-IP Encapsulation Protocol", "IPv6 Extension Header": "", "Keyword": "IPIP", "Reference": "[John_Ioannidis]"}, "iplt": {"Decimal": "129", "Protocol": "", "IPv6 Extension Header": "", "Keyword": "IPLT", "Reference": "[[Hollbach]]"}, "leaf-1": {"Decimal": "25", "Protocol": "Leaf-1", "IPv6 Extension Header": "", "Keyword": "LEAF-1", "Reference": "[Barry_Boehm]"}, "pnni": {"Decimal": "102", "Protocol": "PNNI over IP", "IPv6 Extension Header": "", "Keyword": "PNNI", "Reference": "[Ross_Callon]"}, "cpnx": {"Decimal": "72", "Protocol": "Computer Protocol Network Executive", "IPv6 Extension Header": "", "Keyword": "CPNX", "Reference": "[David Mittnacht]"}, "isis over ipv4": {"Decimal": "124", "Protocol": "", "IPv6 Extension Header": "", "Keyword": "ISIS over IPv4", "Reference": "[Tony_Przygienda]"}, "larp": {"Decimal": "91", "Protocol": "Locus Address Resolution Protocol", "IPv6 Extension Header": "", "Keyword": "LARP", "Reference": "[Brian Horn]"}, "esp": {"Decimal": "50", "Protocol": "Encap Security Payload", "IPv6 Extension Header": "Y", "Keyword": "ESP", "Reference": "[RFC4303]"}, "ddp": {"Decimal": "37", "Protocol": "Datagram Delivery Protocol", "IPv6 Extension Header": "", "Keyword": "DDP", "Reference": "[Wesley_Craig]"}, "dsr": {"Decimal": "48", "Protocol": "Dynamic Source Routing Protocol", "IPv6 Extension Header": "", "Keyword": "DSR", "Reference": "[RFC4728]"}, "mux": {"Decimal": "18", "Protocol": "Multiplexing", "IPv6 Extension Header": "", "Keyword": "MUX", "Reference": "[Cohen, D. and J. Postel, \"Multiplexing Protocol\", IEN 90,\nUSC/Information Sciences Institute, May 1979.][Jon_Postel]"}, "rohc": {"Decimal": "142", "Protocol": "Robust Header Compression", "IPv6 Extension Header": "", "Keyword": "ROHC", "Reference": "[RFC5858]"}, "smp": {"Decimal": "121", "Protocol": "Simple Message Protocol", "IPv6 Extension Header": "", "Keyword": "SMP", "Reference": "[Leif_Ekblad]"}, "xns-idp": {"Decimal": "22", "Protocol": "XEROX NS IDP", "IPv6 Extension Header": "", "Keyword": "XNS-IDP", "Reference": "[\"The Ethernet, A Local Area Network: Data Link Layer and\nPhysical Layer Specification\", AA-K759B-TK, Digital\nEquipment Corporation, Maynard, MA.  Also as: \"The\nEthernet - A Local Area Network\", Version 1.0, Digital\nEquipment Corporation, Intel Corporation, Xerox\nCorporation, September 1980.  And: \"The Ethernet, A Local\nArea Network: Data Link Layer and Physical Layer\nSpecifications\", Digital, Intel and Xerox, November 1982.\nAnd: XEROX, \"The Ethernet, A Local Area Network: Data Link\nLayer and Physical Layer Specification\", X3T51/80-50,\nXerox Corporation, Stamford, CT., October 1980.][[XEROX]]"}, "vrrp": {"Decimal": "112", "Protocol": "Virtual Router Redundancy Protocol", "IPv6 Extension Header": "", "Keyword": "VRRP", "Reference": "[RFC5798]"}, "sctp": {"Decimal": "132", "Protocol": "Stream Control Transmission Protocol", "IPv6 Extension Header": "", "Keyword": "SCTP", "Reference": "[Randall_R_Stewart]"}, "idpr-cmtp": {"Decimal": "38", "Protocol": "IDPR Control Message Transport Proto", "IPv6 Extension Header": "", "Keyword": "IDPR-CMTP", "Reference": "[Martha_Steenstrup]"}, "ipv6-route": {"Decimal": "43", "Protocol": "Routing Header for IPv6", "IPv6 Extension Header": "Y", "Keyword": "IPv6-Route", "Reference": "[Steve_Deering]"}, "ggp": {"Decimal": "3", "Protocol": "Gateway-to-Gateway", "IPv6 Extension Header": "", "Keyword": "GGP", "Reference": "[RFC823]"}, "qnx": {"Decimal": "106", "Protocol": "QNX", "IPv6 Extension Header": "", "Keyword": "QNX", "Reference": "[Michael_Hunter]"}, "ddx": {"Decimal": "116", "Protocol": "D-II Data Exchange (DDX)", "IPv6 Extension Header": "", "Keyword": "DDX", "Reference": "[John_Worley]"}, "hopopt": {"Decimal": "0", "Protocol": "IPv6 Hop-by-Hop Option", "IPv6 Extension Header": "Y", "Keyword": "HOPOPT", "Reference": "[RFC2460]"}, "xnet": {"Decimal": "15", "Protocol": "Cross Net Debugger", "IPv6 Extension Header": "", "Keyword": "XNET", "Reference": "[Haverty, J., \"XNET Formats for Internet Protocol Version 4\",\nIEN 158, October 1980.][Jack_Haverty]"}, "pup": {"Decimal": "12", "Protocol": "PUP", "IPv6 Extension Header": "", "Keyword": "PUP", "Reference": "[Boggs, D., J. Shoch, E. Taft, and R. Metcalfe, \"PUP: An\nInternetwork Architecture\", XEROX Palo Alto Research Center,\nCSL-79-10, July 1979; also in IEEE Transactions on\nCommunication, Volume COM-28, Number 4, April 1980.][[XEROX]]"}, "tp++": {"Decimal": "39", "Protocol": "TP++ Transport Protocol", "IPv6 Extension Header": "", "Keyword": "TP++", "Reference": "[Dirk_Fromhein]"}, "rdp": {"Decimal": "27", "Protocol": "Reliable Data Protocol", "IPv6 Extension Header": "", "Keyword": "RDP", "Reference": "[RFC908][Bob_Hinden]"}, "rsvp-e2e-ignore": {"Decimal": "134", "Protocol": "", "IPv6 Extension Header": "", "Keyword": "RSVP-E2E-IGNORE", "Reference": "[RFC3175]"}, "mfe-nsp": {"Decimal": "31", "Protocol": "MFE Network Services Protocol", "IPv6 Extension Header": "", "Keyword": "MFE-NSP", "Reference": "[Shuttleworth, B., \"A Documentary of MFENet, a National\nComputer Network\", UCRL-52317, Lawrence Livermore Labs,\nLivermore, California, June 1977.][Barry_Howard]"}, "sun-nd": {"Decimal": "77", "Protocol": "SUN ND PROTOCOL-Temporary", "IPv6 Extension Header": "", "Keyword": "SUN-ND", "Reference": "[William_Melohn]"}, "srp": {"Decimal": "119", "Protocol": "SpectraLink Radio Protocol", "IPv6 Extension Header": "", "Keyword": "SRP", "Reference": "[Mark_Hamilton]"}, "fc": {"Decimal": "133", "Protocol": "Fibre Channel", "IPv6 Extension Header": "", "Keyword": "FC", "Reference": "[Murali_Rajagopal][RFC6172]"}, "idrp": {"Decimal": "45", "Protocol": "Inter-Domain Routing Protocol", "IPv6 Extension Header": "", "Keyword": "IDRP", "Reference": "[Sue_Hares]"}, "vmtp": {"Decimal": "81", "Protocol": "VMTP", "IPv6 Extension Header": "", "Keyword": "VMTP", "Reference": "[Dave_Cheriton]"}, "dcn-meas": {"Decimal": "19", "Protocol": "DCN Measurement Subsystems", "IPv6 Extension Header": "", "Keyword": "DCN-MEAS", "Reference": "[David_Mills]"}, "nsfnet-igp": {"Decimal": "85", "Protocol": "NSFNET-IGP", "IPv6 Extension Header": "", "Keyword": "NSFNET-IGP", "Reference": "[Hans_Werner_Braun]"}, "pgm": {"Decimal": "113", "Protocol": "PGM Reliable Transport Protocol", "IPv6 Extension Header": "", "Keyword": "PGM", "Reference": "[Tony_Speakman]"}, "wesp": {"Decimal": "141", "Protocol": "Wrapped Encapsulating Security Payload", "IPv6 Extension Header": "", "Keyword": "WESP", "Reference": "[RFC5840]"}, "wb-expak": {"Decimal": "79", "Protocol": "WIDEBAND EXPAK", "IPv6 Extension Header": "", "Keyword": "WB-EXPAK", "Reference": "[Steven_Blumenthal]"}, "ippc": {"Decimal": "67", "Protocol": "Internet Pluribus Packet Core", "IPv6 Extension Header": "", "Keyword": "IPPC", "Reference": "[Steven_Blumenthal]"}, "tlsp": {"Decimal": "56", "Protocol": "Transport Layer Security Protocol        \nusing Kryptonet key management", "IPv6 Extension Header": "", "Keyword": "TLSP", "Reference": "[Christer_Oberg]"}, "igmp": {"Decimal": "2", "Protocol": "Internet Group Management", "IPv6 Extension Header": "", "Keyword": "IGMP", "Reference": "[RFC1112]"}, "fire": {"Decimal": "125", "Protocol": "", "IPv6 Extension Header": "", "Keyword": "FIRE", "Reference": "[Criag_Partridge]"}, "bbn-rcc-mon": {"Decimal": "10", "Protocol": "BBN RCC Monitoring", "IPv6 Extension Header": "", "Keyword": "BBN-RCC-MON", "Reference": "[Steve_Chipman]"}, "ipx-in-ip": {"Decimal": "111", "Protocol": "IPX in IP", "IPv6 Extension Header": "", "Keyword": "IPX-in-IP", "Reference": "[CJ_Lee]"}, "iso-tp4": {"Decimal": "29", "Protocol": "ISO Transport Protocol Class 4", "IPv6 Extension Header": "", "Keyword": "ISO-TP4", "Reference": "[RFC905][<mystery contact>]"}, "ipv6-icmp": {"Decimal": "58", "Protocol": "ICMP for IPv6", "IPv6 Extension Header": "", "Keyword": "IPv6-ICMP", "Reference": "[RFC2460]"}, "ipv4": {"Decimal": "4", "Protocol": "IPv4 encapsulation", "IPv6 Extension Header": "", "Keyword": "IPv4", "Reference": "[RFC2003]"}, "l2tp": {"Decimal": "115", "Protocol": "Layer Two Tunneling Protocol", "IPv6 Extension Header": "", "Keyword": "L2TP", "Reference": "[RFC3931][Bernard_Aboba]"}, "ipv6": {"Decimal": "41", "Protocol": "IPv6 encapsulation", "IPv6 Extension Header": "", "Keyword": "IPv6", "Reference": "[RFC2473]"}, "cphb": {"Decimal": "73", "Protocol": "Computer Protocol Heart Beat", "IPv6 Extension Header": "", "Keyword": "CPHB", "Reference": "[David Mittnacht]"}, "compaq-peer": {"Decimal": "110", "Protocol": "Compaq Peer Protocol", "IPv6 Extension Header": "", "Keyword": "Compaq-Peer", "Reference": "[Victor_Volpe]"}, "udp": {"Decimal": "17", "Protocol": "User Datagram", "IPv6 Extension Header": "", "Keyword": "UDP", "Reference": "[RFC768][Jon_Postel]"}, "sps": {"Decimal": "130", "Protocol": "Secure Packet Shield", "IPv6 Extension Header": "", "Keyword": "SPS", "Reference": "[Bill_McIntosh]"}, "micp (deprecated)": {"Decimal": "95", "Protocol": "Mobile Internetworking Control Pro.", "IPv6 Extension Header": "", "Keyword": "MICP (deprecated)", "Reference": "[John_Ioannidis]"}, "hmp": {"Decimal": "20", "Protocol": "Host Monitoring", "IPv6 Extension Header": "", "Keyword": "HMP", "Reference": "[RFC869][Bob_Hinden]"}, "ipv6-opts": {"Decimal": "60", "Protocol": "Destination Options for IPv6", "IPv6 Extension Header": "Y", "Keyword": "IPv6-Opts", "Reference": "[RFC2460]"}, "icmp": {"Decimal": "1", "Protocol": "Internet Control Message", "IPv6 Extension Header": "", "Keyword": "ICMP", "Reference": "[RFC792]"}, "manet": {"Decimal": "138", "Protocol": "MANET Protocols", "IPv6 Extension Header": "", "Keyword": "manet", "Reference": "[RFC5498]"}, "trunk-2": {"Decimal": "24", "Protocol": "Trunk-2", "IPv6 Extension Header": "", "Keyword": "TRUNK-2", "Reference": "[Barry_Boehm]"}, "trunk-1": {"Decimal": "23", "Protocol": "Trunk-1", "IPv6 Extension Header": "", "Keyword": "TRUNK-1", "Reference": "[Barry_Boehm]"}, "mtp": {"Decimal": "92", "Protocol": "Multicast Transport Protocol", "IPv6 Extension Header": "", "Keyword": "MTP", "Reference": "[Susie_Armstrong]"}, "uti": {"Decimal": "120", "Protocol": "UTI", "IPv6 Extension Header": "", "Keyword": "UTI", "Reference": "[Peter_Lothberg]"}, "secure-vmtp": {"Decimal": "82", "Protocol": "SECURE-VMTP", "IPv6 Extension Header": "", "Keyword": "SECURE-VMTP", "Reference": "[Dave_Cheriton]"}, "nvp-ii": {"Decimal": "11", "Protocol": "Network Voice Protocol", "IPv6 Extension Header": "", "Keyword": "NVP-II", "Reference": "[RFC741][Steve_Casner]"}, "eigrp": {"Decimal": "88", "Protocol": "EIGRP", "IPv6 Extension Header": "", "Keyword": "EIGRP", "Reference": "[RFC7868]"}, "leaf-2": {"Decimal": "26", "Protocol": "Leaf-2", "IPv6 Extension Header": "", "Keyword": "LEAF-2", "Reference": "[Barry_Boehm]"}, "stp": {"Decimal": "118", "Protocol": "Schedule Transfer Protocol", "IPv6 Extension Header": "", "Keyword": "STP", "Reference": "[Jean_Michel_Pittet]"}, "shim6": {"Decimal": "140", "Protocol": "Shim6 Protocol", "IPv6 Extension Header": "Y", "Keyword": "Shim6", "Reference": "[RFC5533]"}, "sdrp": {"Decimal": "42", "Protocol": "Source Demand Routing Protocol", "IPv6 Extension Header": "", "Keyword": "SDRP", "Reference": "[Deborah_Estrin]"}, "reserved": {"Decimal": "255", "Protocol": "", "IPv6 Extension Header": "", "Keyword": "Reserved", "Reference": "[Internet_Assigned_Numbers_Authority]"}, "pim": {"Decimal": "103", "Protocol": "Protocol Independent Multicast", "IPv6 Extension Header": "", "Keyword": "PIM", "Reference": "[RFC7761][Dino_Farinacci]"}, "rvd": {"Decimal": "66", "Protocol": "MIT Remote Virtual Disk Protocol", "IPv6 Extension Header": "", "Keyword": "RVD", "Reference": "[Michael_Greenwald]"}, "prm": {"Decimal": "21", "Protocol": "Packet Radio Measurement", "IPv6 Extension Header": "", "Keyword": "PRM", "Reference": "[Zaw_Sing_Su]"}, "ah": {"Decimal": "51", "Protocol": "Authentication Header", "IPv6 Extension Header": "Y", "Keyword": "AH", "Reference": "[RFC4302]"}, "sprite-rpc": {"Decimal": "90", "Protocol": "Sprite RPC Protocol", "IPv6 Extension Header": "", "Keyword": "Sprite-RPC", "Reference": "[Welch, B., \"The Sprite Remote Procedure Call System\",\nTechnical Report, UCB/Computer Science Dept., 86/302,\nUniversity of California at Berkeley, June 1986.][Bruce Willins]"}, "mpls-in-ip": {"Decimal": "137", "Protocol": "", "IPv6 Extension Header": "", "Keyword": "MPLS-in-IP", "Reference": "[RFC4023]"}, "swipe (deprecated)": {"Decimal": "53", "Protocol": "IP with Encryption", "IPv6 Extension Header": "", "Keyword": "SWIPE (deprecated)", "Reference": "[John_Ioannidis]"}, "il": {"Decimal": "40", "Protocol": "IL Transport Protocol", "IPv6 Extension Header": "", "Keyword": "IL", "Reference": "[Dave_Presotto]"}, "cbt": {"Decimal": "7", "Protocol": "CBT", "IPv6 Extension Header": "", "Keyword": "CBT", "Reference": "[Tony_Ballardie]"}, "i-nlsp": {"Decimal": "52", "Protocol": "Integrated Net Layer Security  TUBA", "IPv6 Extension Header": "", "Keyword": "I-NLSP", "Reference": "[K_Robert_Glenn]"}, "ifmp": {"Decimal": "101", "Protocol": "Ipsilon Flow Management Protocol", "IPv6 Extension Header": "", "Keyword": "IFMP", "Reference": "[Bob_Hinden][November 1995, 1997.]"}, "ospfigp": {"Decimal": "89", "Protocol": "OSPFIGP", "IPv6 Extension Header": "", "Keyword": "OSPFIGP", "Reference": "[RFC1583][RFC2328][RFC5340][John_Moy]"}, "dccp": {"Decimal": "33", "Protocol": "Datagram Congestion Control Protocol", "IPv6 Extension Header": "", "Keyword": "DCCP", "Reference": "[RFC4340]"}, "igp": {"Decimal": "9", "Protocol": "any private interior gateway             \n(used by Cisco for their IGRP)", "IPv6 Extension Header": "", "Keyword": "IGP", "Reference": "[Internet_Assigned_Numbers_Authority]"}, "narp": {"Decimal": "54", "Protocol": "NBMA Address Resolution Protocol", "IPv6 Extension Header": "", "Keyword": "NARP", "Reference": "[RFC1735]"}, "scc-sp": {"Decimal": "96", "Protocol": "Semaphore Communications Sec. Pro.", "IPv6 Extension Header": "", "Keyword": "SCC-SP", "Reference": "[Howard_Hart]"}, "gre": {"Decimal": "47", "Protocol": "Generic Routing Encapsulation", "IPv6 Extension Header": "", "Keyword": "GRE", "Reference": "[RFC2784][Tony_Li]"}, "sat-mon": {"Decimal": "69", "Protocol": "SATNET Monitoring", "IPv6 Extension Header": "", "Keyword": "SAT-MON", "Reference": "[Steven_Blumenthal]"}, "encap": {"Decimal": "98", "Protocol": "Encapsulation Header", "IPv6 Extension Header": "", "Keyword": "ENCAP", "Reference": "[RFC1241][Robert_Woodburn]"}, "irtp": {"Decimal": "28", "Protocol": "Internet Reliable Transaction", "IPv6 Extension Header": "", "Keyword": "IRTP", "Reference": "[RFC938][Trudy_Miller]"}, "sat-expak": {"Decimal": "64", "Protocol": "SATNET and Backroom EXPAK", "IPv6 Extension Header": "", "Keyword": "SAT-EXPAK", "Reference": "[Steven_Blumenthal]"}, "gmtp": {"Decimal": "100", "Protocol": "GMTP", "IPv6 Extension Header": "", "Keyword": "GMTP", "Reference": "[[RXB5]]"}, "wb-mon": {"Decimal": "78", "Protocol": "WIDEBAND Monitoring", "IPv6 Extension Header": "", "Keyword": "WB-MON", "Reference": "[Steven_Blumenthal]"}, "sscopmce": {"Decimal": "128", "Protocol": "", "IPv6 Extension Header": "", "Keyword": "SSCOPMCE", "Reference": "[Kurt_Waber]"}, "dgp": {"Decimal": "86", "Protocol": "Dissimilar Gateway Protocol", "IPv6 Extension Header": "", "Keyword": "DGP", "Reference": "[M/A-COM Government Systems, \"Dissimilar Gateway Protocol\nSpecification, Draft Version\", Contract no. CS901145,\nNovember 16, 1987.][Mike_Little]"}, "visa": {"Decimal": "70", "Protocol": "VISA Protocol", "IPv6 Extension Header": "", "Keyword": "VISA", "Reference": "[Gene_Tsudik]"}, "etherip": {"Decimal": "97", "Protocol": "Ethernet-within-IP Encapsulation", "IPv6 Extension Header": "", "Keyword": "ETHERIP", "Reference": "[RFC3378]"}, "snp": {"Decimal": "109", "Protocol": "Sitara Networks Protocol", "IPv6 Extension Header": "", "Keyword": "SNP", "Reference": "[Manickam_R_Sridhar]"}, "ipv6-nonxt": {"Decimal": "59", "Protocol": "No Next Header for IPv6", "IPv6 Extension Header": "", "Keyword": "IPv6-NoNxt", "Reference": "[RFC2460]"}, "mobility header": {"Decimal": "135", "Protocol": "", "IPv6 Extension Header": "Y", "Keyword": "Mobility Header", "Reference": "[RFC6275]"}, "mobile": {"Decimal": "55", "Protocol": "IP Mobility", "IPv6 Extension Header": "", "Keyword": "MOBILE", "Reference": "[Charlie_Perkins]"}, "scps": {"Decimal": "105", "Protocol": "SCPS", "IPv6 Extension Header": "", "Keyword": "SCPS", "Reference": "[Robert_Durst]"}, "egp": {"Decimal": "8", "Protocol": "Exterior Gateway Protocol", "IPv6 Extension Header": "", "Keyword": "EGP", "Reference": "[RFC888][David_Mills]"}, "kryptolan": {"Decimal": "65", "Protocol": "Kryptolan", "IPv6 Extension Header": "", "Keyword": "KRYPTOLAN", "Reference": "[Paul Liu]"}, "vines": {"Decimal": "83", "Protocol": "VINES", "IPv6 Extension Header": "", "Keyword": "VINES", "Reference": "[Brian Horn]"}, "st": {"Decimal": "5", "Protocol": "Stream", "IPv6 Extension Header": "", "Keyword": "ST", "Reference": "[RFC1190][RFC1819]"}, "pipe": {"Decimal": "131", "Protocol": "Private IP Encapsulation within IP", "IPv6 Extension Header": "", "Keyword": "PIPE", "Reference": "[Bernhard_Petri]"}, "ipv6-frag": {"Decimal": "44", "Protocol": "Fragment Header for IPv6", "IPv6 Extension Header": "Y", "Keyword": "IPv6-Frag", "Reference": "[Steve_Deering]"}, "ipcv": {"Decimal": "71", "Protocol": "Internet Packet Core Utility", "IPv6 Extension Header": "", "Keyword": "IPCV", "Reference": "[Steven_Blumenthal]"}}

        # Load Access Lists
        acl_lines = parse.find_objects(r"access-list")
        self._accessLists = {}

        for line in acl_lines:
            words = line.text.strip().split(' ')
            if words[1] not in self._accessLists.keys():
                self._accessLists[words[1]] = AccessList(name = words[1])
            if words[3] == 'permit':
                permit = True
            else:
                permit = False
            if words[4] == 'any':
                protocol = 0
            else:
                protocol = int(protocols[words[4].lower()]['Decimal'])
            i = 5
            if words[5] == 'any':
                source = external
                i += 1
            else:
                source = self._networkObjects[words[6]]
                i += 2
            if words[i] == 'any':
                dest = external
                i += 1
            else:
                dest = self._networkObjects[words[i+1]]
                i += 2
            if i >= len(words):
                port_min = 0
                port_max = 0
            elif words[i] == 'eq':
                if len([x for x in asaports if x['Name'] == words[i+1]]) == 1:
                    port_min = [x for x in asaports if x['Name'] == words[i+1]][0]['Port']
                else:
                    port_min = (int(words[i+1]))
                port_max = port_min
            elif words[i] == 'range':
                ports = words[i+1].strip().split('-')
                port_min = ports[0]
                port_max = ports[1]

            self._accessLists[words[1]].addRule(Rule(text = line.text.strip(), source = source, dest = dest, port_min = port_min, port_max = port_max, permit = permit, protocol = protocol))


#TESTING
#f = open('./asa.conf')
#config_file = f.readlines()
#f.close()

#asav = ASA()
#asav.loadConfig(config_file)
#print(asav.accessLists.keys())
#print(len(asav.accessLists['ACL_IN'].rules))

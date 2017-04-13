import ipcalc
import random
import csv

totalNetObjects = 500
totalNetACLs = 10000

subnets = []
hosts = []
acls = []

i = 0

while i < totalNetObjects:
    if random.randint(1,20) == 1:
        subnet = ipcalc.Network('7.0.' + str(random.randint(1,100)) + '.0/24')
        while subnet in subnets:
            subnet = ipcalc.Network('7.0.' + str(random.randint(1,100)) + '.0/24')
        subnets.append(subnet)
        print "object network obj_" + str(subnet.network())
        print "  subnet " + str(subnet.network()) + ' ' + str(subnet.netmask())
    else:
        IP = "7.0." + str(random.randint(1,100)) + '.' + str(random.randint(2,254))
        while IP in hosts:
            IP = "7.0." + str(random.randint(1,100)) + '.' + str(random.randint(2,254))
        hosts.append(IP)
        print "object network obj_" + IP
        print "  host " + IP
    i += 1

# Load in the IANA Known Ports
ports = []
try:
    with open('service-names-port-numbers.csv') as protocol_file:
        reader = csv.DictReader(protocol_file)
        for row in reader:
            ports.append(row)
except:
    print 'failed loading IANA'
# Load in ASA Known Ports
asaports = []
with open('asa_ports.csv') as protocol_file:
    reader = csv.DictReader(protocol_file)
    for row in reader:
        asaports.append(row)

print '!'

i = 0
while i < totalNetACLs:
    if random.randint(1,20) == 1:
        source = 'any'
    elif random.randint(1,5) == 1 and len(subnets) > 0:
        source = subnets[random.randint(0,len(subnets)-1)]
        source = "object obj_" + str(source.network())
    else:
        source = hosts[random.randint(0,len(hosts)-1)]
        source = "object obj_" + str(source)

    if random.randint(1,20) == 1:
        dest = 'any'
    elif random.randint(1,5) == 1 and len(subnets) > 0:
        dest = subnets[random.randint(0,len(subnets)-1)]
        dest = "object obj_" + str(dest.network())
    else:
        dest = hosts[random.randint(0,len(hosts)-1)]
        dest = "object obj_" + str(dest)

    #print source + ' ' + dest

    if random.randint(1,20) == 1:
        print "access-list ACL_IN extended permit icmp " + source + " " + dest
    elif random.randint(1,3) == 1:
        port = asaports[random.randint(0,len(asaports)-1)]
        if port['Proto'] == 'TCP, UDP':
            proto = 'TCP'
        else:
            proto = port['Proto']
        print "access-list ACL_IN extended permit " + proto.lower() + " " + source + " " + dest + " eq " + port['Name']
    else:
        port = ports[random.randint(1,100)]
        while port['Transport Protocol'] != 'tcp' and port['Transport Protocol'] != 'udp':
            port = ports[random.randint(1,100)]
        #print port
        print "access-list ACL_IN extended permit " + port['Transport Protocol'] + " " + source + " " + dest + " eq " + port['Port Number']

    i += 1

"""
Standalone application to convert Tetration Policy to CSV
"""
import json
import csv
from tetpyclient import RestClient
import requests.packages.urllib3
from TetPolicy2 import Environment
from terminaltables import AsciiTable
import os
import ipaddress

def selectTetrationApps(endpoint,credentials):

    restclient = RestClient(endpoint,
                            credentials_file=credentials,
                            verify=False)

    requests.packages.urllib3.disable_warnings()
    resp = restclient.get('/openapi/v1/applications')

    if not resp:
        sys.exit("No data returned for Tetration Apps! HTTP {}".format(resp.status_code))

    app_table = []
    app_table.append(['Number','Name','Author','Primary'])
    for i,app in enumerate(resp.json()):
        app_table.append([i+1,app['name'],app['author'],app['primary']])
    print(AsciiTable(app_table).table)
    choice = raw_input('\nSelect Tetration App: ')

    choice = choice.split(',')
    appIDs = []
    for app in choice:
        if '-' in app:
            for app in range(int(app.split('-')[0])-1,int(app.split('-')[1])):
                appIDs.append(resp.json()[int(app)-1]['id'])
        else:
            appIDs.append(resp.json()[int(app)-1]['id'])

    return appIDs


def main():
    """
    Main execution routine
    """

    #Tetration Access Information
    API_ENDPOINT="https://perseus-aus.cisco.com"
    API_CREDS="/Users/christophermchenry/Documents/Scripting/tetration-api/perseus_credentials.json"
    #API_ENDPOINT="https://medusa-cpoc.cisco.com"
    #API_CREDS="/Users/christophermchenry/Documents/Scripting/tetration-api/medusa_credentials.json"

    #Select Tetration Apps and Load Tet Object Model
    tetEnv = Environment(API_ENDPOINT,API_CREDS)
    tetEnv.loadPolicy(appIDs=selectTetrationApps(endpoint=API_ENDPOINT,credentials=API_CREDS))
    app = tetEnv.primaryApps[tetEnv.primaryApps.keys()[0]]
    clusters = app.clusters
    filters = app.inventoryFilters
    policies = app.defaultPolicies

    configtext = ''


    # Load in the IANA Protocols
    protocols = {}
    try:
        with open('protocol-numbers-1.csv') as protocol_file:
            reader = csv.DictReader(protocol_file)
            for row in reader:
                protocols[row['Decimal']]=row
    except IOError:
        print '%% Could not load protocols file'
        return
    except ValueError:
        print 'Could not load improperly formatted protocols file'
        return

    # Load in ASA known ports
    ports = {}
    try:
        with open('asa_ports.csv') as protocol_file:
            reader = csv.DictReader(protocol_file)
            for row in reader:
                ports[row['Port']]=row
    except IOError:
        print '%% Could not load protocols file'
        return
    except ValueError:
        print 'Could not load improperly formatted protocols file'
        return

    #print('\nASA ACL Config\n---------------------------------------\n\n')
    #Process nodes and output information to ASA Objects
    for key in clusters.keys():
        cluster = clusters[key]
        configtext = configtext + "\nobject-group network " + cluster.name.replace(' ','_')
        for ip in cluster.ipSet:
            #UPDATE TO ACCOUNT FOR SUBNETS
            configtext = configtext +  "\n  host " + ip

    for key in filters.keys():
        invFilter = filters[key]
        if invFilter.name != 'Default':
            configtext = configtext +  "\nobject-group network " + invFilter.name.replace(' ','_')
            query = invFilter.filter
            del query[0]
            del query[0]

            if len(query) == 1 and query[0]['type']=='or':
                query = query[0]['filters']
            if len([item for item in query if item['field'] != 'ip']) == 0:
                for item in query:
                    if item['type'] == 'eq':
                        configtext = configtext + "\n  host " + item['value']
                    elif item['type'] == 'subnet':
                        net = ipaddress.ip_network(unicode(item['value']))
                        configtext = configtext + "\n  subnet " + ' '.join(net.with_netmask.split('/'))
            else:
                for ip in invFilter.ipSet:
                    configtext = configtext +  "\n  host " + ip

    configtext = configtext +  '\n!'

    #Process policies and output information as ASA ACL Lines
    for policy in policies:
        for rule in policy.l4params:
            #if policy.consumerFilterName == 'Default' and policy.providerFilterName != 'Default':
            if policy.consumerFilterName != policy.providerFilterName:
                if rule['proto'] == 1:
                    configtext = configtext +  "\naccess-list ACL_IN extended permit " + protocols[str(rule['proto'])]['Keyword'] + ((" object " + policy.consumerFilterName.replace(' ','_')) if policy.providerFilterName != 'Default' else " any") + ((" object " + policy.providerFilterName.replace(' ','_')) if policy.providerFilterName != 'Default' else " any")
                elif (rule['proto'] == 6) or (rule['proto'] == 17):
                    if rule['port_min'] == rule['port_max']:
                        if (str(rule['port_min']) in ports.keys()) and (ports[str(rule['port_min'])]['Proto'] == protocols[str(rule['proto'])]['Keyword'] or ports[str(rule['port_min'])]['Proto'] == 'TCP, UDP'):
                            port = ports[str(rule['port_min'])]['Name']
                        else:
                            port = rule['port_min']
                        configtext = configtext +  "\naccess-list ACL_IN extended permit " + protocols[str(rule['proto'])]['Keyword'] + ((" object " + policy.consumerFilterName.replace(' ','_')) if policy.consumerFilterName != 'Default' else " any") + ((" object " + policy.providerFilterName.replace(' ','_')) if policy.providerFilterName != 'Default' else " any") + " eq " + str(port)
                    else:
                        configtext = configtext +  "\naccess-list ACL_IN extended permit " + protocols[str(rule['proto'])]['Keyword'] + ((" object " + policy.consumerFilterName.replace(' ','_')) if policy.consumerFilterName != 'Default' else " any") + ((" object " + policy.providerFilterName.replace(' ','_')) if policy.providerFilterName != 'Default' else " any") + " range " + str(rule['port_min']) + "-" + str(rule['port_max'])

    configtext = configtext +  "\naccess-list ACL_IN extended deny ip any any\n!\n\n"

    f = open("./Examples/asa.cfg", "w")
    f.write(configtext)
    f.close()

    os.system('open ./Examples/asa.cfg -a "Sublime Text"')


if __name__ == '__main__':
    main()

"""
Standalone application to convert Tetration Policy to CSV
"""
from apicservice import ConfigDB
import json
import argparse
import csv
import asa
#import ipaddress
#Using ipcalc for Python 2.x compatibility
import ipcalc
from tqdm import tqdm


def main():
    """
    Main execution routine
    """
    parser = argparse.ArgumentParser(description='Tetration Policy to CSV')
    parser.add_argument('--maxlogfiles', type=int, default=10, help='Maximum number of log files (default is 10)')
    parser.add_argument('--debug', nargs='?',
                        choices=['verbose', 'warnings', 'critical'],
                        const='critical',
                        help='Enable debug messages.')
    parser.add_argument('--tetconfig', default=None, help='Configuration file')
    parser.add_argument('--asaconfig', default=None, help='Configuration file')
    args = parser.parse_args()

    if args.tetconfig is None:
        print '%% No Tetration JSON file given'
        return

    if args.asaconfig is None:
        print '%% No ASA configuration file given'
        return

    # Load in the Tetration JSON
    try:
        with open(args.tetconfig) as config_file:
            config = json.load(config_file)
    except IOError:
        print '%% Could not load Tetration JSON file'
        return
    except ValueError:
        print 'Could not load improperly formatted Tetration JSON file'
        return

    cdb = ConfigDB()
    cdb.store_config(config)
    epgs = cdb.get_epg_policies()
    #Create Cluster Dictionary
    clusters = {}
    for epg in epgs:
        clusters[epg.id] = epg
    policies = cdb.get_contract_policies()
    applications = cdb.get_application_policies()

    # Load in the ASA Configuration
    fw = asa.ASA()
    try:
        with open(args.asaconfig) as config_file:
            config_file = config_file.readlines()
            fw.loadConfig(config_file)
    except IOError:
        print '%% Could not load ASA Config file'
        return
    except ValueError:
        print 'Could not load improperly formatted ASA Config file'
        return


    for acl in fw.accessLists.keys():
        print 'Analyzing %d rules in Access List "%s"'%(len(fw.accessLists[acl].rules),acl)
        for fwrule in tqdm(fw.accessLists[acl].rules):
            for policy in policies:
                for tetrule in policy.get_whitelist_policies():
                    if fwrule.protocol == 0 or int(tetrule.proto) == int(fwrule.protocol):
                        if int(fwrule.port_min) == int(tetrule.port_min) and int(tetrule.port_max) == int(fwrule.port_max):
                            if compareNetworkObjects(fwrule.source,clusters[policy.src_id]):
                                if compareNetworkObjects(fwrule.dest,clusters[policy.dst_id]):
                                    if policy.src_name not in fwrule.srcClusters:
                                        fwrule.srcClusters.append(policy.src_name)
                                    if policy.dst_name not in fwrule.dstClusters:
                                        fwrule.dstClusters.append(policy.dst_name)

            if 'External' in fwrule.srcClusters:
                fwrule.srcClusters = ['External']
            if 'External' in fwrule.dstClusters:
                fwrule.dstClusters = ['External']

    #Write CSV Analysis
    with open('audit.csv', 'wb') as csvfile:
        auditwriter = csv.writer(csvfile, delimiter=',',
                                quotechar='|', quoting=csv.QUOTE_MINIMAL)
        auditwriter.writerow(['ACL Name','Line','Line Text','In Use','Too General?','Source Clusters','Destination Clusters'])
        for acl in fw.accessLists.keys():
            for i, fwrule in enumerate(fw.accessLists[acl].rules):
                tooGeneral = (len(fwrule.srcClusters)+ len(fwrule.dstClusters))>2
                inUse = (len(fwrule.srcClusters)+ len(fwrule.dstClusters))>=2
                auditwriter.writerow([acl,i,fwrule.text,inUse,tooGeneral,'; '.join(fwrule.srcClusters),'; '.join(fwrule.dstClusters)])

    print("Succcess!")


def compareNetworkObjects(fwobject, tetcluster):

    tetInFW = []
    for node in tetcluster.get_node_policies():
        for netobj in fwobject.networks:
            if node.ip in ipcalc.Network(netobj['ip']+'/'+netobj['mask']):
                tetInFW.append(1)
            else:
                tetInFW.append(0)

    if 1 in tetInFW:
        match = True
    else:
        match = False

    fwInTet = []

    #match = True

    return match


if __name__ == '__main__':
    main()

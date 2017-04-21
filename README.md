# Tetration ASA Configuration Generator

Usage:

```
python policy_asa.py --config 'JSON_FILE_EXPORT_FROM_TETRATION'
```

Currently this script only generates object groups and access lists between internal clusters in a Tetration workspace and the "External" cluster.  It could be easily altered to generate rules between route-tags that are imported into a Tetration workspace.


# Tetration ASA Configuration Auditor

Usage:

```
python asa_audit.py --tetconfig 'JSON_FILE_EXPORT_FROM_TETRATION' --asaconfig 'ASA_CONFIG_FILE'
```

This script is intended to compare ADM policy discovered in Tetration and use that data
to audit rules in an existing ASA configuration.  It will then label the ACL rules
with context information as to whether it's being used, if so by which Tetration discovered clusters, and whether the rule is too general.  

Additional comparison code needed to determine partial match scenarios.  Currently comparison is done by using the Python set library for high performance, so additional comparison logic should be simple to add.

# Prerequisite Packages
```
pip install ipcalc tqdm ciscoconfparse
```

# File Descriptions

- asa_audit.py: Primary file for comparing Tetration configuration to Firewall config.
- policy_asa.py: Primary file for generating firewall configuration from Tetration config.
- asa.py: Python class library for ingesting an ASA configuration and transforming it into an in-memory object model of an ASA.
- apicservice.py: Pulled from the Cisco ACI toolkit.  Provides a service for building an in-memory object model from an exported Tetration policy.  Both apps leverage the "configdb" feature in this library.
- asa_ports.csv: CSV file that contains the ASA lexicon for translating word-based services to ports
- protocol-numbers-1.csv: IANA protocol numbers list to translate a protocol number to a protocol name (i.e. 1 is ICMP)

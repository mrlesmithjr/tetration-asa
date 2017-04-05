# Tetration ASA Configuration Generator

Usage:

```
python policy_asa.py --config 'JSON_FILE_EXPORT_FROM_TETRATION'
```

Currently this script only generates rules between internal clusters in a Tetration
workspace and the "External" cluster.  It could be easily altered to generate
rules between route-tags that are imported into a Tetration workspace.

# PrettyMap
Generates a word doc table based on nmap results.
- removes duplicate scans
- combines multiple vhosts under same IP
- compares duplicate scans and adds missing services
- generates table with both TCP and UDP services, including banners
### Dependencies
Needs python nmap and docx libraries
```sh
$ pip install python-libnmap
$ pip install python-docx
```

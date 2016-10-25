#!/usr/bin/python

import sys

from functions import VirusTotal,SafeSearch, Cymon

url=sys.argv[1]

virustotal=VirusTotal(url)
safesearch=SafeSearch(url)
cymon=Cymon(url)

print "Malicious website analysis for %s" %(sys.argv[1])
print "VirusTotal count: %s" %(virustotal)
print safesearch
print cymon

#!/usr/bin/python

import cgi
import requests
import json
from bs4 import BeautifulSoup
import re

form=cgi.FieldStorage()
domain=cgi.escape(str(form["domain"].value).lower())

print "Content-Type: text/html"
print

pattern="(?=^([a-z]|[0-9]|\.|\-)*$)"
match=re.search(pattern,domain)
if not match:
        print "BAD HACKER NO DONUT"
        quit()


print "<html><head><title>Malicious website report for %s</title></head>" %(domain)
print "<body>"
print "<pre>"
def checkit(method, url,parameters,json,data):
        proxy={'http':'<my proxy>','https':'<my proxy>'}
        try:
                if method=="get":
                        r=requests.get(url,proxies=proxy)
                elif method=="post":
                        if parameters:
                                r=requests.post(url,params=parameters,proxies=proxy)
                        elif json:
                                r=requests.post(url,json=json,proxies=proxy)
                        elif data:
                                r=requests.post(url,data=data,proxies=proxy)
        except r.ConnectionError:
                return "[-] Connection Error"
                quit()

        #if r.status_code !=200:
        #       return "[-] HTTP error %s" %(r.status_code)
        #       quit()
        #else:
                #return r.text
        return r.text

def Cymon():
        a=checkit("get","https://cymon.io/api/nexus/v1/domain/"+domain,"","","")
        j=json.loads(a)
        try:
                if j["detail"]:
                        return "Not found in Cymon"
        except:
                sources="Found in Cymon:\n"
                for source in j["sources"]:
                        sources=sources+"     "+source+"<br>"
        return sources



def VirusTotal():
        api_key="<api_key>"
        parameters = {"resource": domain,
                        "apikey": api_key}

        a=checkit("post","http://www.virustotal.com/vtapi/v2/url/report",parameters,"","")
        j=json.loads(a)
        virus_total_results=0
        try:
                for engine in j["scans"]:
                        if j["scans"][engine]["detected"]:
                                virus_total_results +=1
                return "Domain is in VirusTotal %s times" %(virus_total_results)
        except:
                return "Domain is not in VirusTotal"

def SafeBrowsing():
        api_key="<api_key>"
        payload={
                "client": {
                        "clientId":      "me",
                        "clientVersion": "1"
                        },
                        "threatInfo": {
                                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING"],
                                "platformTypes":    ["WINDOWS"],
                                "threatEntryTypes": ["URL"],
                                "threatEntries": [
                                        {"url": domain}
                                ]
                        }
                }
        a=checkit("post","https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+api_key,"",payload,"")
        j=json.loads(a)
        if j:
                return "In Google Safebrowsing Blacklist"
        else:
                return "Not in Google Safebrowsing Blacklist"

def BlueCoat():
        payload={"url":domain}
        a=checkit("post","http://sitereview.bluecoat.com/rest/categorization","","",payload)
        j=json.loads(a)

        category=BeautifulSoup(j["categorization"],"lxml").get_text()
        date=BeautifulSoup(j["ratedate"],"lxml").get_text()[0:35]
        return "BlueCoat<br>     Site is in category: %s<br>     Date: %s" %(category,date)


print "<b>Malicious website report for %s</b><br>" %(domain)
cymon=Cymon()
print cymon+"<br>"

virustotal=VirusTotal()
print virustotal+"<br>"

safebrowsing=SafeBrowsing()
print safebrowsing+"<br>"

bluecoat=BlueCoat()
print bluecoat+"<br>"


print "</pre></body></html>"

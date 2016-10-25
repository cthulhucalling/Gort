import requests
import json

def VirusTotal(url):
	api_key="<api key>"
	parameters = {"resource": url,
			"apikey": api_key}
	r=requests.post("http://www.virustotal.com/vtapi/v2/url/report",params=parameters)
	#j=json.dumps(json.loads(r.text),indent=4,sort_keys=True)
	j=json.loads(r.text)
	virus_total_results=0
	for engine in j["scans"]:
		if j["scans"][engine]["detected"]:
			virus_total_results +=1
	return virus_total_results

def SafeSearch(url):
	api_key="<api_key>"
	headers={"Content-Type":"application/json"}
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
        {"url": url}
      ]
    }
  }
	r=requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+api_key,headers=headers,json=payload)
	j=json.loads(r.text)
	if j:
		return "In Google Safebrowsing Blacklist"
	else:
		return "Not in Google Safebrowsing Blacklist"

def Cymon(url):
	api_key="" #500 anonymous lookups a day
	r=requests.get("https://cymon.io/api/nexus/v1/domain/"+url)
	j=json.loads(r.text)
	try:
		if j["detail"]:
			return "Not found in Cymon"
	except:
		sources="Found in Cymon:\n"
		for source in j["sources"]:
			sources=sources+"\t"+source+"\n"
		return sources

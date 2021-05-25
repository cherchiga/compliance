import asyncio
import json
import string
import urllib3
import utils

cvp_data_file = "data/nodes.txt"
cvp_nodes = list()
with open(cvp_data_file, "r") as f1:
    for json_payload in f1.readlines():
        cvp_nodes.append(json.loads(json_payload))

http = urllib3.PoolManager(cert_reqs = 'CERT_NONE')
urllib3.disable_warnings()
auth_token = ''
index = -1

while (not auth_token) and index < len(cvp_nodes):
    index = index + 1
    try:
        node = cvp_nodes[index]
        cvp_base_url = "https://" + node["ip"] + "/cvpservice"
        cvp_login_url = cvp_base_url + "/login/authenticate.do"
        payload = {'password': node["credentials"][1], 
                   'userId': node["credentials"][0]}
        encoded_payload = json.dumps(payload).encode('utf-8')

        r = http.request("POST", cvp_login_url,
                         body = encoded_payload,
                         headers = {"Content-Type": "application/json",
                                    "Accept": "application/json"})
        login_json = json.loads(r.data.decode("utf-8"))
        auth_token = login_json["cookie"]["Value"]

    except:
        print(f"Could not authenticate against CVP node {node}.")
    index = index + 1

if auth_token:
    cvp_inventory_url = cvp_base_url + "/inventory/devices?provisioned=true"
    r = http.request("GET", cvp_inventory_url,
                     headers = {"Accept": "application/json",
                                "access_token": auth_token})
    inventory_json = json.loads(r.data.decode("utf-8"))
    system_macs = list()
    for device in inventory_json: 
        system_macs.append(device["systemMacAddress"])

    MAX_RUNNERS = 10
    counter = 0
    batch = list()
    devices_non_compliant = list()
    while system_macs:
        while counter < 5 and system_macs:
            batch.append(system_macs.pop())
            counter = counter + 1
        result = asyncio.run(utils.scheduler(cvp_base_url, batch, 
                                             auth_token, counter))
        for item in result:
            compliance_json = json.loads(item)
            if (compliance_json["complianceIndication"] and
                "WARNING" in compliance_json["complianceIndication"]):
               devices_non_compliant.append(compliance_json["fqdn"] + 
               " : " + compliance_json["ipAddress"])
        counter = 0
        batch.clear()

slack_webhook_url = ("https://hooks.slack.com/services/T0534H08D/" + 
                     "B022UCBPU06/ueaohNoGR6Tz5x0ms9p4MYT5")
if devices_non_compliant:
    slack_message = ("The following devices are out of compliance:\n" + 
                 "\n".join(devices_non_compliant))
    print(slack_message)
    payload = {"text": slack_message}
    encoded_payload = json.dumps(payload).encode('utf-8')
    r = http.request("POST", slack_webhook_url,
                     body = encoded_payload,
                     headers = {"Content-Type": "application/json"})
else:
    slack_message = ("No devices are out of compliance.\n")
    payload = {"text": slack_message}
    encoded_payload = json.dumps(payload).encode('utf-8')
    r = http.request("POST", slack_webhook_url,
                     body = encoded_payload,
                     headers = {"Content-Type": "application/json"})
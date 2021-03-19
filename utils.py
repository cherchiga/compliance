import asyncio
import aiohttp
import json

async def compliance_check(cvp, sys_mac, token):
    cvp_compliance_url = cvp + "/provisioning/checkCompliance.do"
    payload = {"nodeId": sys_mac, 
               "nodeType": "netelement"}
    encoded_payload = json.dumps(payload).encode('utf-8')
    async with aiohttp.ClientSession() as session:
        async with session.post(cvp_compliance_url,
                                data = encoded_payload,
                                headers = {"Content-Type": "application/json",
                                           "Accept": "application/json",
                                           "access_token": token},
                                ssl=False) as response:
            html = await response.text()
    return html

async def scheduler(cvp, macs, token, batch):
    result = await asyncio.gather(*[compliance_check(cvp, macs[i], 
                                  token) for i in range (0, batch)])
    return result
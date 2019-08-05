import os
import time
import json
import virustotal3.core

API_KEY = os.environ['VT_API']

vt = virustotal3.core.Files(API_KEY)

response = vt.upload('7z1900-x64.exe')
analysis_id = response['data']['id']
print('Analysis ID: {}'.format(analysis_id))
results = virustotal3.core.get_analysis(API_KEY, analysis_id)
status = results['data']['attributes']['status']

print('Waiting for results...')
while 'completed' not in status:
    results = virustotal3.core.get_analysis(API_KEY, analysis_id)
    status = results['data']['attributes']['status']
    print('Current status: {}'.format(status))
    time.sleep(10)

results = virustotal3.core.get_analysis(API_KEY, analysis_id)
print(json.dumps(results, indent=4, sort_keys=True))
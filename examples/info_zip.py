import os
import virustotal3.enterprise

API_KEY = os.environ['VT_API']

vt = virustotal3.enterprise.ZipFiles(API_KEY)

results = vt.info_zip(zip_id)
print(results['data']['attributes']['status'])  # Prints the status
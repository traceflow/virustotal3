import os
import virustotal3.enterprise

API_KEY = os.environ['VT_API']
results = virustotal3.enterprise.search(API_KEY, 'evil.exe', order='size-',limit=10)
print(results)
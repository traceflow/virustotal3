import os
import virustotal3.enterprise

API_KEY = os.environ['VT_API']

vt = virustotal3.enterprise.ZipFiles(API_KEY)

data = {
        "data": {
            "password": "mysecretpassword",
            "hashes":[
            "3c7c3d72f7a4cb0dc1b421fb1774fd875ca1c11afd1bc0c3200765a1d0c70007"]
            }
        }

results = vt.create_zip(data)
print(results['data']['id'])  # Prints the ID returned by the response.
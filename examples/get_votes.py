import os
import virustotal3.core

API_KEY = os.environ['VT_API']

vt = virustotal3.core.Files(API_KEY)

comment = {
            "data": {
                "type": "comment",
                "attributes": {
                    "text": "Lorem #ipsum dolor sit ..."
                }
            }
        }

votes = vt.get_votes('f03fb0970be1a728e8ad1632c1d3d1c16af8fa298e0d9984795934478dfdf4d1')

print(votes)
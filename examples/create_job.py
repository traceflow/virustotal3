import os
import virustotal3

API_KEY = os.environ['VT_API']
Retrohunt = virustotal3.Retrohunt(API_KEY)

data = {
        "data": {
            "type": "Retrohunt_job",
            "attributes": {
            "rules": "rule foobar { strings: $ = \"hello\" condition: all of them }",
            "notification_email": "notifications@acme.com",
            "corpus": "main",
            "time_range": {
                "start": 1560023731,
                "end": 1562615731
            }
        }
    }
}

Retrohunt.create_job(data)
import json
import virustotal3.core
import virustotal3.errors
import pandas as pd

#from tabulate import tabulate
pd.set_option('display.max_colwidth', 40)

# Subcommands
class Commands:
    def __init__(self, api_key):
        self.api_key = api_key
        self.vt_domains = virustotal3.core.Domains(self.api_key)
        self.vt_ip = virustotal3.core.IP(self.api_key)
        self.vt_url = virustotal3.core.URL(self.api_key)
        self.vt_files = virustotal3.core.Files(self.api_key)

    def info(self, type, indicator):
        try:
            if type == 'domain':
                results = self.vt_domains.info_domain(indicator)
                #print(json.dumps(results, indent=4))
                for key, value in results['data']['attributes']['last_analysis_stats'].items():
                    detections = results['data']['attributes']['last_analysis_stats']
            if type == 'ip':
                results = self.vt_ip.info_ip(indicator)
                # Get all attributes returned by the API
                attributes = results['data']['attributes']
                # Create dataframe for ASN
                pd.set_option('display.width', 200)
                df = pd.DataFrame(columns=['as_owner','asn', 'country', 'last_modification_date', 'network', 'regional_internet_registry', 'reputation'], data=pd.json_normalize(attributes))
                print(df.to_string(index=False, justify='left') + '\n\n')
                
        except virustotal3.errors.VirusTotalApiError as e:
            print(e)
            exit(1)

    def relationships(self, type, indicator):
        pass
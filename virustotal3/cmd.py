import json
from prettytable import PrettyTable
import virustotal3.core
import virustotal3.errors

pt_info = PrettyTable


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
                print(json.dumps(results, indent=4))
                #for key, value in results['data']['attributes']['last_analysis_stats'].items():
                #    print(key, value)

            if type == 'ip':
                results = self.vt_ip.info_ip(indicator)
                print(json.dumps(results, indent=4))
                #for key, value in results['data']['attributes']['last_analysis_stats'].items():
                #    print(key, value)
        except virustotal3.errors.VirusTotalApiError as e:
            print(e)
            exit(1)

    def relationships(self, type, indicator):
        pass
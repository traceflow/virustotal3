import os
import virustotal3.core

API_KEY = os.environ['VT_API']
vt_files = virustotal3.core.Files(API_KEY)
info = vt_files.info_file('e86d4eb1e888bd625389f2e50644be67a6bdbd77ff3bceaaf182d45860b88d80')
print(info)
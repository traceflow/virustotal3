import os
import virustotal3.core

API_KEY = os.environ['VT_API']

vt = virustotal3.core.Files(API_KEY)

vt.add_vote('6e7785213d6af20f376a909c1ecb6c9bddec70049764f08e5054a52997241e3d', 'malicious')
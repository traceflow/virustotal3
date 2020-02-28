import os
import getpass
import argparse

#try:
#    API_KEY = os.environ['VT_API']
#except KeyError:
#    print("Please set the API key in the VT_API environment variable")

# USAGE EXAMPLE
# python3 virustotal.py info --ip

# sub-command functions
def info(ioc_type):
    pass

def relationships(ioc_type):
    pass

# create the top-level parser
parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(title='commands', dest='command')

# create the parser for the "domain" command
parser_info = subparsers.add_parser('info')
parser_info.add_argument('--domain')
parser_info.add_argument('--ip')
parser_info.add_argument('--file')
#parser_info.set_defaults(func=bar)

# create the parser for the "relationships" command
parser_relationships = subparsers.add_parser('relationships')
parser_relationships.add_argument('--domain')
parser_relationships.add_argument('--ip')
parser_relationships.add_argument('--file')
#parser_relationships.set_defaults(func=bar)


# parse the args and call whatever function was selected
args = parser.parse_args()

if args.command == 'info':
    if args.domain:
        pass
    if args.ip:
        pass
    if args.file:
        pass
if args.command == 'relationships':
    if args.domain:
        pass
    if args.ip:
        pass
    if args.file:
        pass
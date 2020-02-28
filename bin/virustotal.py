import os
import getpass
import argparse


API_KEY = None

# USAGE EXAMPLE
# python3 virustotal.py info --ip

# sub-command functions
def info(ioc_type):
    pass

def relationships(ioc_type):
    pass

# create the top-level parser
parser = argparse.ArgumentParser()
parser.add_argument('--key')
subparsers = parser.add_subparsers(title='commands', dest='command')

# create the parser for the "info" command
parser_info = subparsers.add_parser('info')
parser_info.add_argument('--domain')
parser_info.add_argument('--ip')
parser_info.add_argument('--file')

# create the parser for the "relationships" command
parser_relationships = subparsers.add_parser('relationships')
parser_relationships.add_argument('--domain')
parser_relationships.add_argument('--ip')
parser_relationships.add_argument('--file')


# parse the args and call whatever function was selected
args = parser.parse_args()
if not args.key:
    try:
        API_KEY = os.environ['VT_API_KEY']
    except KeyError:
        print("Set the API key in the VT_API_KEY environment variable for permanent storage or use the --key argument")

if args.key:
    API_KEY = args.key
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
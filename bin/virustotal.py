import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
import argparse
import json
from virustotal3 import cmd

# USAGE EXAMPLE
# python3 virustotal.py info --ip

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

# SET API KEY 
try:
    API_KEY = os.environ['VT_API_KEY']
except KeyError:
    if args.key:
        API_KEY = args.key
    else:
        print("Set the API key in the VT_API_KEY environment variable for permanent storage or use the --key argument")
        exit(1)

# Init commands
cmd = cmd.Commands(API_KEY)

# Parse commands
if args.command == 'info':
    if args.domain:
        cmd.info('domain', args.domain)

    if args.ip:
        cmd.info('ip', args.ip)
    if args.file:
        pass
if args.command == 'relationships':
    if args.domain:
        pass
    if args.ip:
        pass
    if args.file:
        pass




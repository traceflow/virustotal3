import os
import getpass
import argparse


# USAGE EXAMPLE
# python3 virustotal.py info --ip

# sub-command functions
def info(ioc_type):
    pass

def relationships(ioc_type):
    pass

# create the top-level parser
parser = argparse.ArgumentParser()
parser.add_argument('--key' )
subparsers = parser.add_subparsers(title='commands', dest='command')

# create the parser for the "info" command
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
if args.api_key
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
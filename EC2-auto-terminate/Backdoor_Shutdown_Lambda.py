# Backdoor_Shutdown_Lambda.py || part of ZocSec.SecurityAsCode.AWS 
#
# An AWS Lambda for terminating EC2 instances for which GuardDuty detects malware.
#
# Owner:	Copyright 2018 Zocdoc Inc.  www.zocdoc.com 
# Author:	Jay Ball  @veggiespam
#

import boto3
from botocore.exceptions import ClientError
import json

def lambda_handler(event, context):
    print("Event is: ",  json.dumps(event))
    
    source = event['source']
    if source != "aws.guardduty":
        # wrong caller, just silently return
        print("Wrong Filter on CW Events, source=", source)
        return
    
    detail_type = event['detail-type']    
    if detail_type != 'GuardDuty Finding':
        # wrong caller, just silently return
        print("Wrong Filter on CW Events, source=", source, " / detail_type=", detail_type)
        return
    
    event_type = event['detail']['type']
    
    # https://docs.aws.amazon.com/guardduty/latest/ug//guardduty_finding-types.html
    bad_event_list = [ 
        'Backdoor:EC2/XORDDOS', 
	    'Backdoor:EC2/Spambot', 
	    'Backdoor:EC2/C&CActivity.B!DNS', 
	    'CryptoCurrency:EC2/BitcoinTool.B!DNS', 
	    'Trojan:EC2/BlackholeTraffic', 
	    'Trojan:EC2/DropPoint', 
	    'Trojan:EC2/BlackholeTraffic!DNS', 
	    'Trojan:EC2/DriveBySourceTraffic!DNS', 
	    'Trojan:EC2/DropPoint!DNS', 
	    'Trojan:EC2/DGADomainRequest.B', 
	    'Trojan:EC2/DGADomainRequest.C!DNS', 
	    'Trojan:EC2/DNSDataExfiltration', 
	    'Trojan:EC2/PhishingDomainRequest!DNS' ]

    if not(event_type in bad_event_list):
        # single event example:
        #if event_type != 'Backdoor:EC2/C&CActivity.B!DNS':
        print("We received the wrong event type: " , event_type)
        return
    
    # we will shut this one down   
    instance_id = event['detail']['resource']['instanceDetails']['instanceId']
    
    # only shutdown certain tags:
    taglist = event['detail']['resource']['instanceDetails']['tags']
    runme=False
    
    for nvp in taglist:
        if "infosecadmin" == nvp['key'].lower():
            runme=True
            
    if not(runme):
        print("We are not part of our auto-shutdown EC2 group")
        return
    
    
    print("Shutting down instance ", instance_id)

    ec2 = boto3.client('ec2')
    
    try:
        response = ec2.stop_instances(InstanceIds=[ instance_id ])
        # ec2.reboot_instances(InstanceIds=['INSTANCE_ID'], DryRun=True)
    except ClientError as e:
        if 'DryRunOperation' not in str(e):
            print("You don't have permission to reboot instances.")
            raise
        else:
            print('Error', e)

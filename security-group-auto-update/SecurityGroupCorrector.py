# SecurityGroupCorrector.py || part of ZocSec.SecurityAsCode.AWS 
#
# An AWS Lambda for removing security groups that expose sensitive ports to the entire Internet
#
# Owner:	Copyright © 2018 Zocdoc Inc.  www.zocdoc.com 
# Author:	Jay Ball  @veggiespam
#

import boto3
from botocore.exceptions import ClientError
import json

def lambda_handler(event, context):
    
    print("Event is: ",  json.dumps(event))
    
    source = event['detail']['eventSource']
    if source != "ec2.amazonaws.com":
        # wrong caller, just silently return
        print("Wrong Filter on CT Events, source=", source)
        return
    
    allowed_event_list =  [ 
        'CreateSecurityGroup', 
        "AuthorizeSecurityGroupIngress"
    ]
    
    event_name = event['detail']['eventName']    

    if not(event_name in allowed_event_list):
        # wrong event, just silently return
        print("Wrong Filter on CT Events, source=", source, " / event_name=", event_name)
        return

    resp = event['detail']['responseElements']
    
    if (resp["_return"] != True):
        # event was not a successful update, so we can ignore it.
        print("event was not a successful update, so we can ignore it")
        return
    
    
    SG_id = 'invalid'
    if event_name == 'CreateSecurityGroup':
        SG_id = resp["groupId"]
    elif event_name == 'AuthorizeSecurityGroupIngress':
        SG_id = event['detail']['requestParameters']['groupId']
    else:
        # We shouldn't actually get here.
        return

    print("groupID = ", SG_id)

    ec2 = boto3.resource('ec2')
    security_group = ec2.SecurityGroup(SG_id)
    
    sensitive_ports = [ 22, 3389, 54321 ]    ; # your sensitive ports
    ingress_list = security_group.ip_permissions
    
    for perm in ingress_list:
        # print(json.dumps(perm))
        
        fromport=0
        toport=0
        ipprot=0
        sensitive=False
        
        if 'FromPort' in perm:
            fromport = perm['FromPort']
        if 'ToPort' in perm:
            toport = perm['ToPort']
            
        if 'IpProtocol' in perm:
            ipprot = perm['IpProtocol']
            if ipprot == "-1":
                sensitive = True
            
        # print("F:",fromport," T:",toport)
        
        if fromport > 0:
            for p in sensitive_ports:
                if fromport <= p and p <= toport:
                    sensitive = True
        
        if sensitive:
            for r in perm['IpRanges']:
                # this could be more complex, but 0000/0 catches 90% of the cases
                if r['CidrIp'] == "0.0.0.0/0":
                    print("Ingress Rule violates policy, removed: ", json.dumps(perm))
                    
                    try:
                        security_group.revoke_ingress(
                            CidrIp = r['CidrIp'],
                            IpProtocol = perm['IpProtocol'],
                            FromPort = fromport,
                            ToPort = toport,
                            # , DryRun = True
                        )
                    except ClientError as e:
                        if 'DryRunOperation' not in str(e):
                            print("Error: ", e)
                            raise
                        else:
                            print('DryRun: ', e)

    print(json.dumps(ingress_list))
    return

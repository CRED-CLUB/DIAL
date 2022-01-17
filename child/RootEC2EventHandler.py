#! /usr/bin/python3

from EC2EventHandler import EC2EventHandler
from sgAlertclass import securityGroup
from vpcAlertClass import vpcEventHandler

def handle_parent_ec2_event(event, aws_account, ec2_app_config):
    # Global events
    ec2_event_map = ec2_app_config['Static']['EC2']['Event-Map']
    sg_events = ec2_event_map['SG']
    ec2_events = ec2_event_map['EC2']
    vpc_events = ec2_event_map['VPC']
    eventName = event['eventName']

    if eventName in sg_events:
        print('[+]Found event in security groups file: sgAlert')
        event_handler = securityGroup(ec2_app_config)
        return event_handler.handle_event(event, aws_account)

    elif eventName in ec2_events:
        ec2_event_handler = EC2EventHandler(ec2_app_config)
        print('[+]Found event in ec2 asset tracker file: EC2 Asset Tracker')
        return ec2_event_handler.handle_event(event, aws_account)

    elif eventName in vpc_events:
        print('[+]Found event in vpc alert file: vpcAlert')
        event_handler = vpcEventHandler(ec2_app_config)
        return event_handler.handle_event(event, aws_account)
        
    else:
        print(f'[+]Got unknown event at EC2 Root Event Handler: {eventName}')
        exit(-1)

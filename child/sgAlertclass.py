#! /usr/bin/python3

import json
import os
from utils import EventHandler, EventResponse

class securityGroup(EventHandler):
    def __init__(self, appConfig):
        name = "Security Group"
        super().__init__(name, appConfig)
        self.severity_map = appConfig['Severity']['SG']
        
    def handle_event(self, event_data, aws_account):
        response = self.get_event_response(event_data, aws_account)
        print(f"[+]VPC Classifier Response: {response.get_response_dict()}")
        return response
    
    def get_event_response(self, event, aws_account):
        eventResponse = EventResponse('SG Event')
        eventResponse.userName = self.utils.username_fetch(event['userIdentity'])
        eventResponse.eventName = event["eventName"]
        eventResponse.eventId = event['eventID']
        eventResponse.userIp = event['sourceIPAddress']
        eventResponse.other_data['eventTime'] = event['eventTime']
        eventResponse.aws_region = event['awsRegion']
        eventResponse.location = self.utils.get_location(eventResponse.userIp)
        eventResponse.aws_account = aws_account
        error = "errorMessage" in event
        eventResponse.error = error
        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
        if error:
            error_message = event['errorMessage']
            eventResponse.author_name = f"Security Group Error [{eventResponse.aws_account}]"
            eventResponse.title = f"[{eventResponse.eventName}] - {error_message}"
            eventResponse.text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
            eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            return eventResponse
        
        #create security group
        if eventResponse.eventName == "CreateSecurityGroup":
            print(f"[+]Processing event for message parsing: {eventResponse.eventName}")
            try:
                if "groupName" in event["requestParameters"]:
                    group_name = event["requestParameters"]["groupName"]
                    group_desc = event["requestParameters"]["groupDescription"]
                    vpc_id = event["requestParameters"]["vpcId"]
                    group_id = event["responseElements"]["groupId"]
                    eventResponse.author_name = f"Security group - New sg group created [{eventResponse.aws_account}]"
                    eventResponse.title = f"Security group [{group_name} ({group_id})] created"
                    eventResponse.text = f"*Description:* {group_desc}\n*VPC-ID:* {vpc_id}\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
            
            except KeyError:
                if "groupName" in event["requestParameters"]:
                    group_name = event["requestParameters"]["groupName"]
                    group_desc = event["requestParameters"]["groupDescription"]
                    group_id = event["responseElements"]["groupId"]
                    eventResponse.author_name = f"Security group - New sg group created [{eventResponse.aws_account}]"
                    eventResponse.title = f"Security group [{group_name} ({group_id})] created"
                    eventResponse.text = f"*Description:* {group_desc}\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
        
        #add inbound rules
        elif eventResponse.eventName == "AuthorizeSecurityGroupIngress":
            print(f"[+]Processing event for message parsing: {eventResponse.eventName}")
            try:
                if "ipProtocol" in event["requestParameters"]:
                    group_id = event["requestParameters"]["groupId"]
                    rules = str(event["requestParameters"])
                    public = ['0.0.0.0','::/0']
                    text_warning = f"*WARNING:* This sg group will expose the attached resource to the world!\n*Rules added:*\n```{rules}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    text_normal = f"*Rules added:*\n```{rules}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
        
                    if public[0] in rules:
                        eventResponse.text = text_warning
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    elif public[1] in rules:
                        eventResponse.text = text_warning
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    elif public[2] in rules:
                        eventResponse.text = text_warning
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    else:
                        eventResponse.text = text_normal
                    eventResponse.author_name = f"Security group - Inbound rules added [{eventResponse.aws_account}]"
                    eventResponse.title = f"Security group [{group_id}] Inbound rules added"
            
            except KeyError:
                if ("ipProtocol" in event["requestParameters"]) and ("groupName" in event["requestParameters"]):
                    group_id = event["requestParameters"]["groupName"]
                    rules = str(event["requestParameters"])
                    public = ['0.0.0.0','::/0']
                    text_warning = f"*WARNING:* This sg group will expose the attached resource to the world!\n*Rules added:*\n```{rules}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    text_normal = f"*Rules added:*\n```{rules}```\n*Initiator:* {eventResponse.eventName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
        
                    if public[0] in rules:
                        eventResponse.text = text_warning
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    elif public[1] in rules:
                        eventResponse.text = text_warning
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    elif public[2] in rules:
                        eventResponse.text = text_warning
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    else:
                        eventResponse.text = text_normal
                    eventResponse.author_name = f"Security group - Inbound rules added [{eventResponse.aws_account}]"
                    eventResponse.title = f"Security group [{group_id}] - Inbound rules added"

            else:
                rules = self.utils.rules_extraction(event["requestParameters"])
                group_id = event["requestParameters"]["groupId"]
                if rules != None:
                    group_id = rules[-1]
                    rules = '\n'.join(rules[0:-1])
                    public = ['0.0.0.0','::/0']
                        
                    text_warning = f"*WARNING:* This sg group will expose the attached resource to the world!\n*Rules added:*\n```{rules}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    text_normal = f"*Rules added:*\n```{rules}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                        
                    if public[0] in rules:
                        eventResponse.text = text_warning
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    elif public[1] in rules:
                        eventResponse.text = text_warning
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    elif public[2] in rules:
                        eventResponse.text = text_warning
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    else:
                        eventResponse.text = text_normal
                    eventResponse.author_name = f"Security group - Inbound rules added [{eventResponse.aws_account}]"
                    eventResponse.title = f"Security group [{group_id}] - Inbound rules added"
                else:
                    eventResponse.text = f"*Rules added:*\n```{rules}```\n*Initiator:* {eventResponse.userName}"
                    eventResponse.author_name = f"Security group - Inbound rules added [{eventResponse.aws_account}]"
                    eventResponse.title = f"Security group [{group_id}] - Inbound rules added"

        #remove inbound rules
        elif eventResponse.eventName == "RevokeSecurityGroupIngress":
            print(f"[+]Processing event for message parsing: {eventResponse.eventName}")
            rules = self.utils.rules_extraction(event["requestParameters"])
            group_id = event["requestParameters"]["groupId"]
            if rules != None:
                eventResponse.author_name = f"Security group - Inbound rules removed [{eventResponse.aws_account}]"
                eventResponse.title = f"Security group [{group_id}] - Inbound rules removed"
                eventResponse.text = f"*Rules removed:*\n```{rules}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
            else:
                eventResponse.author_name = f"Security group - Inbound rules removed [{eventResponse.aws_account}]"
                eventResponse.title = f"Security group [{group_id}] - Inbound rules removed"
                eventResponse.text = f"*Rules removed:*\n```{rules}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"

        #add outbound rules
        elif eventResponse.eventName == "AuthorizeSecurityGroupEgress":
            print(f"[+]Processing event for message parsing: {eventResponse.eventName}")
            rules = self.utils.rules_extraction(event["requestParameters"])
            group_id = event["requestParameters"]["groupId"]
            if rules != None:
                group_id = rules[-1]
                rules = '\n'.join(rules[0:-1])
                eventResponse.author_name = f"Security group - Outbound rules added [{eventResponse.aws_account}]"
                eventResponse.title = f"Security group [{group_id}] - Outbound rules added"
                eventResponse.text = f"*Rules added:*\n```{rules}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
            else:
                eventResponse.author_name = f"Security group - Outbound rules added [{eventResponse.aws_account}]"
                eventResponse.title = f"Security group [{group_id}] - Outbound rules added"
                eventResponse.text = f"*Rules added:*\n```{rules}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"

        #remove outbound rules
        elif eventResponse.eventName == "RevokeSecurityGroupEgress":
            print(f"[+]Processing event for message parsing: {eventResponse.eventName}")
            rules = self.utils.rules_extraction(event["requestParameters"])
            group_id = event["requestParameters"]["groupId"]
            if rules != None:
                group_id = rules[-1]
                rules = '\n'.join(rules[0:-1])
                eventResponse.author_name = f"Security group - Outbound rules removed [{eventResponse.aws_account}]"
                eventResponse.title = f"Security group [{group_id}] - Outbound rules removed"
                eventResponse.text = f"*Rules removed:*\n```{rules}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
            else:
                eventResponse.author_name = f"Security group - Outbound rules removed [{eventResponse.aws_account}]"
                eventResponse.title = f"Security group [{group_id}] - Outbound rules removed"
                eventResponse.text = f"*Rules removed:*\n```{rules}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"

        #delete security group
        elif eventResponse.eventName == "DeleteSecurityGroup":
            print(f"[+]Processing event for message parsing: {eventResponse.eventName}")
            group_id = event["requestParameters"]["groupId"]
            eventResponse.author_name = f"Security group - Group deleted [{eventResponse.aws_account}]"
            eventResponse.title = f"Security group [{group_id}] deleted"
            eventResponse.text = f"\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"

        return eventResponse
    
    def get_event_severity(self, eventName, error=False, extras=False):
        if error:
            return self.severity_map[eventName]['Error']
        elif extras:
            return self.severity_map[eventName]['Dangerous']
        return self.severity_map[eventName]['Default']
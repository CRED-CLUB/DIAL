#! /usr/bin/python3

import sys
import json
import re
from datetime import datetime
from utils import EventHandler, EventResponse, Utils


class S3AccessAlerts(EventHandler):
    def __init__(self, appConfig):
        name = "S3"
        super().__init__(name, appConfig)
        self.severity_map = appConfig['Severity']['S3']
        self.neglected_users = self.appConfig['Static']['S3']['Whitelisted-Users']
    
    def handle_event(self, event_data, aws_account):
        response = self.get_event_response(event_data, aws_account)
        print(f"[+]S3 classifier response: {response.get_response_dict()}")
        return response
    
    def get_event_response(self, event, aws_account):
        eventResponse = EventResponse('S3 Event')
        try:
            eventResponse.userName = event['userIdentity']['arn']
        except KeyError:
            eventResponse.userName = event['userIdentity']['accountId']
        eventResponse.eventName = event["eventName"]
        eventResponse.eventId = event['eventID']
        eventResponse.userIp = event['sourceIPAddress']
        eventResponse.other_data['eventTime'] = event['eventTime']
        eventResponse.env = self.utils.get_account_name_from_arn(eventResponse.userName)
        eventResponse.aws_region = event['awsRegion']
        eventResponse.location = self.utils.get_location(eventResponse.userIp)
        eventResponse.aws_account = aws_account
        bucket_name = event["requestParameters"]["bucketName"]
        request = event['requestParameters']
        EXPLAINED = {
            "READ": "Public Read",
            "WRITE": "Public Write",
            "READ_ACP": "Permissions Readable",
            "WRITE_ACP": "Permissions Writeable",
            "FULL_CONTROL": "Full Control"
        }
        error = "errorMessage" in event
        eventResponse.error = error

        if ("invokedBy" in event['userIdentity']) and (event["userIdentity"]["invokedBy"] == "cloudtrail.amazonaws.com"):
            print("[+]Got Cloudtrail's invocation, hence skipping!")
            eventResponse.skipped = True
            return eventResponse
        
        if eventResponse.userName in self.neglected_users or eventResponse.userIp in self.neglected_users:
            print("[+]Got whitelisted user/ip hence skipping")
            eventResponse.skipped = True
            return eventResponse
        
        if error:
            error_message = event['errorMessage']
            eventResponse.author_name = f"S3 Error [{eventResponse.aws_account}]"
            eventResponse.title = f"[{eventResponse.eventName}] - {error_message}"
            eventResponse.text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
            eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            return eventResponse
        
        if eventResponse.eventName == "PutBucketAcl":
            bucket_name = event["requestParameters"]["bucketName"]
            blacklist_uri = ["http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"]
            uri = []
            uri_perms = []
            email = []
            email_perms = []
            if ("AccessControlPolicy" in request) and ("Grant" in request["AccessControlPolicy"]["AccessControlList"]):
                grants = request["AccessControlPolicy"]["AccessControlList"]["Grant"]
                if type(grants) == dict:
                    perm = grants["Permission"]
                    if grants["Grantee"]["xsi:type"] == "CanonicalUser":
                        return 0
                    elif "EmailAddress" in grants["Grantee"]:
                        email_perms.append(perm)
                        email.append(grants["Grantee"]["EmailAddress"])
                    elif "URI" in grants["Grantee"]:
                        uri_perms.append(perm)
                        uri.append(grants["Grantee"]["URI"])
                    else:
                        return 0 
                    
                    if (len(uri) >= 1 and len(set(blacklist_uri).intersection(uri)) >= 1) and (len(email) >= 1):
                        perms_uri, uris = self.check_perms_uris(uri_perms, uri)
                        perms_email, emails = self.check_perms_uris(email_perms, email)
                        eventResponse.author_name = f"S3 Bucket made public [{eventResponse.aws_account}]"
                        eventResponse.title = f"[{bucket_name}] was made public"
                        eventResponse.text = f"*URI Permissions Added:* {perms_uri}\n*EMAIL Permissions Added:* {perms_email}\n*Email:* {emails}\n*Groups:* {uris}\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    
                    # If URI is present and no email   
                    elif len(uri) >= 1 and len(set(blacklist_uri).intersection(uri)) >= 1 and len(email) == 0:
                        perms, uris = self.check_perms_uris(uri_perms, uri)
                        eventResponse.author_name = f"S3 Bucket made public [{eventResponse.aws_account}]"
                        eventResponse.title = f"[{bucket_name}] was made public"
                        eventResponse.text = f"*Permissions Added:* {perms}\n*Groups:* {uris}\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    
                    # If Email is present and no uri
                    elif (len(uri) == 0 and len(email) >= 1):
                        perms_email, emails = self.check_perms_uris(email_perms, email)
                        eventResponse.author_name = f"S3 Bucket made public [{eventResponse.aws_account}]"
                        eventResponse.title = f"[{bucket_name}] was made public"
                        eventResponse.text = f"*EMAIL Permissions Added:* {perms_email}\n*Email:* {emails}\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                        
                    else:
                        eventResponse.skipped = True
                        return eventResponse
                        
                if len(grants) > 1:
                    for grant in grants:
                        perm = grant["Permission"]
                        if grant["Grantee"]["xsi:type"] == "CanonicalUser":
                            pass
                        elif "EmailAddress" in grant["Grantee"]:
                            email_perms.append(perm)
                            email.append(grant["Grantee"]["EmailAddress"])
                        elif "URI" in grant["Grantee"]:
                            uri_perms.append(perm)
                            uri.append(grant["Grantee"]["URI"])
                        else:
                            eventResponse.skipped = True
                            pass
                    
                    # If URI and Email are both present
                    if (len(uri) >= 1 and len(set(blacklist_uri).intersection(uri)) >= 1) and (len(email) >= 1):
                        perms_uri, uris = self.check_perms_uris(uri_perms, uri)
                        perms_email, emails = self.check_perms_uris(email_perms, email)
                        eventResponse.author_name = f"S3 Bucket made public [{eventResponse.aws_account}]"
                        eventResponse.title = f"[{bucket_name}] was made public"
                        eventResponse.text = f"*URI Permissions Added:* {perms_uri}\n*EMAIL Permissions Added:* {perms_email}\n*Email:* {emails}\n*Groups:* {uris}\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    
                    # If URI is present and no email   
                    elif len(uri) >= 1 and len(set(blacklist_uri).intersection(uri)) >= 1 and len(email) == 0:
                        perms, uris = self.check_perms_uris(uri_perms, uri)
                        eventResponse.author_name = f"S3 Bucket made public [{eventResponse.aws_account}]"
                        eventResponse.title = f"[{bucket_name}] was made public"
                        eventResponse.text = f"*Permissions Added:* {perms}\n*Groups:* {uris}\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    
                    # If Email is present and no uri
                    elif (len(uri) == 0 and len(email) >= 1):
                        perms_email, emails = self.check_perms_uris(email_perms, email)
                        eventResponse.author_name = f"S3 Bucket made public [{eventResponse.aws_account}]"
                        eventResponse.title = f"[{bucket_name}] was made public"
                        eventResponse.text = f"*EMAIL Permissions Added:* {perms_email}\n*Email:* {emails}\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                    else:
                        eventResponse.skipped = True
            
            elif "x-amz-acl" in event["requestParameters"]:
                acl_string = str(event["requestParameters"]["x-amz-acl"])
                if ('private' not in acl_string) and ("bucket-owner" not in acl_string):
                        eventResponse.author_name = f"S3 Bucket made public [{eventResponse.aws_account}]"
                        eventResponse.title = f"[{bucket_name}] was made public by adding dangerous permissions(ACL)"
                        eventResponse.text = f"*Permissions Added:* {acl_string}\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
            elif re.findall(r"x-amz-grant", str(event["requestParameters"])):
                whole_grant_string = []
                r = re.findall(r"x-amz-grant\S*\b", str(event["requestParameters"]))
                for grant in r:
                    uri = event["requestParameters"][grant]
                    whole_grant_string.append(grant +' '+ str(uri))
                
                grant_string = ', '.join(whole_grant_string)
                eventResponse.author_name = f"S3 Bucket made public [{eventResponse.aws_account}]"
                eventResponse.title = f"[{bucket_name}] was made public by adding dangerous grants"
                eventResponse.text = f"*Grants Added:* {grant_string} \n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
            else:
                eventResponse.skipped = True
                pass
        
        #Bucket Policy added/changed
        elif eventResponse.eventName == "PutBucketPolicy":
            print(f'[+]At event handler, parsing message: {eventResponse.eventName}')
            bucket_policy = event["requestParameters"]["bucketPolicy"]["Statement"][0]
            #if bucket policy exposed the bucket to public
            if (bucket_policy["Effect"] == "Allow") and (bucket_policy["Principal"] == "*" or bucket_policy["Principal"] == "{'AWS': '*'}"):
                eventResponse.author_name = f"S3 Bucket made public [{eventResponse.aws_account}]"
                eventResponse.title = f"[{bucket_name}] was made public by adding dangerous bucket policy"
                eventResponse.text = f"*Bucket policy added:* \n```{json.dumps(bucket_policy, indent=2)}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
            else:
                print(f'[+]At event handler, parsing message: {eventResponse.eventName}')
                eventName = "normal_bucket_policy_update"
                eventResponse.author_name = f"S3 Bucket policy updated [{eventResponse.aws_account}]"
                eventResponse.title = f"[{bucket_name}] bucket policy got updated"
                eventResponse.text = f"*Bucket policy added:* \n```{json.dumps(bucket_policy, indent=2)}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)

        
        elif eventResponse.eventName == "CreateBucket":
            print('[+]Checking bucket')
            eventResponse.author_name = f"S3 Bucket created [{eventResponse.aws_account}]"
            eventResponse.title = f"{bucket_name} s3 bucket created"
            eventResponse.text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
            eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            
            #when --acl is added while creating bucket through s3api
            if "x-amz-acl" in event["requestParameters"]:
                acl_string = str(event["requestParameters"]["x-amz-acl"])
                if ('private' not in acl_string) and ("bucket-owner" not in acl_string):
                    eventResponse.author_name = f"S3 Bucket made public [{eventResponse.aws_account}]"
                    eventResponse.title = f"{bucket_name} created with dangerous permissions(ACL)"
                    eventResponse.text = f"*Permissions Added:* {acl_string}\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
            
            #When grant-* is added while adding grants through s3api
            elif re.findall(r"x-amz-grant", str(event["requestParameters"])):
                whole_grant_string = []
                r = re.findall(r"x-amz-grant\S*\b", str(event["requestParameters"]))
                for grant in r:
                    uri = event["requestParameters"][grant]
                    whole_grant_string.append(grant +' '+ str(uri))
                
                grant_string = ', '.join(whole_grant_string)
                eventResponse.author_name = f"S3 Bucket made public [{eventResponse.aws_account}]"
                eventResponse.title = f"{bucket_name}  created with dangerous grants"
                eventResponse.text = f"*Grants Added:*  {grant_string}\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
            else:
                pass
        
        #if any bucket was deleted via any means
        elif eventResponse.eventName == "DeleteBucket":
            eventResponse.author_name = f"S3 Bucket Deleted [{eventResponse.aws_account}]"
            eventResponse.title = f"[{bucket_name}] was deleted"
            eventResponse.text = f"\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
            eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)

        elif eventResponse.eventName == "PutObject":
            file_name = event["requestParameters"]["key"]
            eventResponse.author_name,eventResponse.title, eventResponse.text, severity = self.utils.putobject_scanner(event["requestParameters"], bucket_name, file_name, eventResponse.aws_account, eventResponse.userName, eventResponse.userIp, eventResponse.location)
            eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, severity)
        elif eventResponse.eventName == "PutObjectAcl":  
            file_name = event["requestParameters"]["key"]
            eventResponse.author_name,eventResponse.title, eventResponse.text, severity = self.utils.putobjectacl_scanner(event["requestParameters"], bucket_name, file_name, eventResponse.aws_account, eventResponse.userName, eventResponse.userIp, eventResponse.location)
            eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, severity)
        else:
            eventResponse.skipped = True
            pass
        return eventResponse
    
    def get_event_severity(self, eventName, error=False, extras=False):
        if error:
            return self.severity_map[eventName]['Error']
        elif extras:
            return self.severity_map[eventName]['Dangerous']
        return self.severity_map[eventName]['Default']
import os
import boto3
import yaml
import socket
import json
import sys
import requests
from urllib import request
from datetime import datetime

from abc import abstractmethod

class EventResponse:
    def __init__(self, event_type):
        self.event_type = event_type
        self.severity = "MEDIUM"            # default severity if no classification is done.
        self.eventName = ""
        self.userName = "Unknown"
        self.userIp = ""
        self.aws_region = "us-east-1"
        self.location = "unknown"
        self.title = ""
        self.text = ""
        self.author_name = ""
        self.arn = ""
        self.aws_account = ""
        self.aws_resources = ""
        self.skipped = False
        self.error = False
        self.bottom_text = ""
        self.other_data = {}
        self.eventId = ""
        self.eventTime = ""
    
    def get_response_dict(self):
        response = {'eventType': self.event_type, 'severity': self.severity, 'eventName': self.eventName, 'aws_account': self.aws_account}
        response.update({'userIp': self.userIp, 'aws_region': self.aws_region, 'location': self.location})
        response.update({'title': self.title, 'text': self.text, 'author_name': self.author_name, 'arn': self.arn, 'eventId': self.eventId})
        response.update({'skipped': self.skipped, 'error': self.error, 'bottom_text': self.bottom_text, 'aws_resources': self.aws_resources})
        response.update(self.other_data)    
        return response


class EventHandler:
    def __init__(self, name, appConfig):
        self.name = name
        self.appConfig = appConfig
        self.utils = Utils(appConfig)
    
    @abstractmethod
    def handle_event(self, event_data):
        pass



class Utils:
    def __init__(self,appConfig):
        self.appConfig = appConfig
        self.enrichment_service_url = appConfig['Static']['Enrichment-URL']
        self.account_id_map = appConfig['Static']['Account-Id-Map']
    
    # needed ? 
    def get_value(self, key,property):
        config = Configruation()
        appConfig = config.load_config()
        return appConfig[key][property]
    
    #Process aws_account name and 
    def user_type(self, identity):
        if "accountId" in identity:
            aws_account = identity['accountId']
            aws_account = self.get_aws_account_name(aws_account)
            return aws_account
        else:
            if "arn" in identity:
                aws_account = identity['arn']
                aws_account = self.get_account_name_from_arn(aws_account)
                return aws_account
            else:
                return "Could not process aws account number from user identity"
    
    # Check username from useridentity
    def username_fetch(self, identity):
        if "arn" in identity:
            username = identity["arn"]
            return username
        elif "userName" in identity:
            username = identity["userName"]
            return username
        else:
            return "Could not process username from useridentity"
    
    # Get IP location
    def get_geoip_details(self, ip):
        try:
            socket.inet_aton(ip)
        except socket.error:
            return 'null'
        if ip.startswith('172.') or ip.startswith('192.168.') or ip.startswith('10.'):
            return 'null'
        enrichment_service = self.enrichment_service_url + str(ip)
        try:
            req = request.Request(enrichment_service, headers={'Content-Type': 'application/json'})
            response = request.urlopen(req)
            s = response.read().decode('utf-8')
            if '{' not in s:
                return 'null'
            else:
                geoip = json.loads(s)
                return geoip
        except Exception as em:
                print('[+]EXCEPTION at GEOIP Func: {}'.format(str(em)))
                return 'null'
    
    # Extract Account id from incoming username
    def get_account_name_from_arn(self, arn):
        account_id = self.get_aws_account_number_from_arn(arn)
        return self.get_aws_account_name(account_id)
    
    # Fetch Account id from incoming username
    def get_aws_account_number_from_arn(self, arn):
        print(f'Fetching aws accountId from ARN: {arn}')
        aws_account_id = arn.split("/")
        aws_account_id = aws_account_id[0]
        aws_account_id = aws_account_id.split("::")
        aws_account_id = aws_account_id[1]
        aws_account_id = aws_account_id.split(":")
        aws_account_id = aws_account_id[0]
        print(f'Aws AccountId: {aws_account_id}')
        return aws_account_id

    # Extract AWS account name from incoming account id
    def get_aws_account_name(self, accountId):
        print(f"[!]At requestHandler function processing the account rxd: {accountId}")
        aws_account = []
        try:
            for key in self.account_id_map:
                if accountId == self.account_id_map[key]:
                    aws_account.append(key)
            aws_account = aws_account[0]
            return aws_account
        except Exception:
            return accountId
    
    # Returns location details post sending it to geop ip enrichment service
    def get_location(self, userIP):
        if "amazonaws" in userIP:
            userIP = userIP.split(".")[0]
            return f"Amazon Internal Service: {userIP}"
        location = ''
        geoip = self.get_geoip_details(userIP)
        if 'null' in geoip:
            location = 'N/A'
        elif 'exception' in geoip:
            location = 'Exception occured'
        else:
            if geoip['org'] != '':
                location = geoip['city'] + ', ' + geoip['country'] + ' | ' + geoip['org']
            else:
                location = geoip['city'] + ', ' + geoip['country']
        return location
    
    # Modify VPC Peer connection function
    def get_modifyvpc_details(self, requestparameters):
        answer = {}
        for key in requestparameters:
            if key == 'AccepterPeeringConnectionOptions':
                value = requestparameters[key]
                for keys in value:
                    if value[keys] == True:
                        answer['Acceptor'] = keys
            elif key == 'RequesterPeeringConnectionOptions':
                value = requestparameters[key]
                for keys in value:
                    if value[keys] == True:
                        answer['Requester'] = keys
        return answer
    
    # Fetch VPC Name
    def vpc_name(self, vpcid):
        ec2 = boto3.client('ec2')
        try:
            vpcs = ec2.describe_vpcs(
                Filters=[{
                    "Name": "vpc-id",
                    "Values": [
                        vpcid
                    ]
                }]
            )
            vpcs = vpcs['Vpcs']
            vpcs = vpcs[0]
            tags = vpcs['Tags']
            answer = self.get_tagSet_name(tags)
            return answer
        except: 
            return vpcid
    
    # TagSet nam extractor
    def get_tagSet_name(self, tagset):
        answer = []
        if len(tagset) == 1:
            try:
                name = tagset[0]['key']
                if name == 'Name':
                    value = tagset[0]['value']
                    answer.append(value)
            except KeyError:
                name = tagset[0]['Key']
                if name == 'Name':
                    value = tagset[0]['Value']
                    answer.append(value)
            except KeyError:
                pass
        else:
            for i in range(len(tagset)):
                name = tagset[i]['key']
                if name == 'Name':
                    value = tagset[i]['value']
                    answer.append(value)
        if len(answer) == 1:
            answer = answer[0]
            print(answer)
            return answer
        elif len(answer) > 1:
            return answer
    
    # Check Route Table Public Access
    def check_route_access(self, routeTable):
        try:
            ec2 = boto3.client('ec2')
            rTable = ec2.describe_route_tables(
                Filters=[{
                    'Name': 'route-table-id',
                    'Values':[
                        routeTable
                    ]
                }])
            rTable = rTable['RouteTables']
            if len(rTable) == 1:
                rTable = rTable[0]
                route = rTable['Routes']
                gateway = []
                for i in range(len(route)):
                    if route[i]['DestinationCidrBlock'].startswith("0.0"):
                        gateway.append(route[i]['GatewayId'])
                if len(gateway) == 1:
                    gateway = gateway[0]
                    return gateway
                elif len(gateway) > 1:
                    return gateway
        except Exception as em:
            print(em)
            return None
    
    # Create Route main differentiator
    def create_route_runner(self, requestparameters):
        answer = {}
        for key in requestparameters:
            testkey = key.lower()
            if testkey.startswith("vpcpeeringconnection"):
                answer = {
                    "vpcPeeringConnectionId": f"{requestparameters[key]}"
                }
            elif "gatewayid" in testkey:
                answer = {
                    "gatewayId": f"{requestparameters[key]}"
                }
        print(f"TestUtils: {answer}")
        return answer
    
   # Return perms and uris for S3 bucket
    def check_perms_uris(self, permissions, uri):
        EXPLAINED = {
                "READ": "Public Read",
                "WRITE": "Public Write",
                "READ_ACP": "Permissions Readable",
                "WRITE_ACP": "Permissions Writeable",
                "FULL_CONTROL": "Full Control"
        }
        p = []
        for perm in permissions:
            p.append(EXPLAINED[perm])
        
        perms = ", ".join(p)
        uris = ", ".join(uri)
        return perms, uris
    
    # Scans Policy Statement
    def statement_scanner(self, policy):
        #print(policy)
        if type(policy) == list and len(policy) > 1:
            print(policy)
            vuln = []
            for statement in policy:
                try:
                    sid = statement['Sid']   
                    action = statement['Action']
                    resource = statement['Resource']

                    # Checks if action is list or string
                    if type(action) == str and resource == "*":
                        if action == "*":
                            vuln.append(sid)
                    elif type(action) == list and resource == "*":
                        for action_values in action:
                            if action_values == "*":
                                vuln.append(sid)
                except:
                    action = statement['Action']
                    resource = statement['Resource']
                    # Checks if action is a  list or string
                    if type(resource) == list and "*" in resource:
                        if type(action) == str and action == "*":
                            vuln.append(action)
                        elif type(action) == list and "*" in action:
                            vuln.append(action)
            
                    elif type(resource) == str and resource == "*":
                        if type(action) == str and action == "*":
                            vuln.append(action)
                        elif type(action) == list and "*" in action:
                            vuln.append(action)
            if len(vuln) != 0:
                return "Admin Access"
        
        elif type(policy) == list and len(policy) == 1:
            print("here")
            policy = policy[0]
            action = policy['Action']
            resource = policy['Resource']

            # Checks if action is a list or string
            if type(resource) == list and "*" in resource:
                if type(action) == str and action == "*":
                    return "Admin Access"
                elif type(action) == list and "*" in action:
                    return "Admin Access"
                else:
                    print("Safe policy")
                    return "Safe"
            
            elif type(resource) == str and resource == "*":
                if type(action) == str and action == "*":
                    return "Admin Access"
                elif type(action) == list and "*" in action:
                    return "Admin Access"
                else:
                    print("Safe policy")
                    return "Safe"
    
    # Policy Name extractor
    def policy_name_extractor(self, policyARN):
        arn = policyARN
        arn = policyARN.split("/")[-1]
        return arn
    
    #PutObject scanner
    def putobject_scanner(self, request, bucket_name, filename, aws_account, username, userip, location):
        acl = []
        uri = []
        if "accessControlList" in request:
            for grant in request["accessControlList"]:
                for name in ("http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers", "emailaddress"):
                    if name in request["accessControlList"][grant]:
                        acl.append(grant)
                        uri_string = request["accessControlList"][grant]
                        if (',' in uri_string) and ("emailaddress" not in uri_string):
                            u = uri_string.split(',')
                            for i in u:
                                if ("acs.amazonaws.com") in i:
                                    if ("http://acs.amazonaws.com/groups/global/AllUsers" or "http://acs.amazonaws.com/groups/global/AuthenticatedUsers") not in uri:
                                        i = i.split('=')[1]
                                        i = i.replace('"', '')
                                        uri.append(i)
                        else:
                            uri.append(uri_string)

            if len(uri) >= 1:
                a = ', '.join(acl)
                u = ', '.join(uri)
                author_name = f"S3 Object made public [{aws_account}]"
                title = f"[{filename}] was uploaded with dangerous permissions in bucket [{bucket_name}]"
                text = f"*ACL's Added:* {a}\n*URI:* {u}\n*Initiator:* {username}\n*Source IP:* {userip}\n*Location:* {location}"
                severity = True
                #Send to notify service   
                return author_name, title, text, severity     
            else:
                return 0

        elif "x-amz-acl" in request:
            acl = request["x-amz-acl"]
            if len(acl) > 0:
                if ('private' not in acl) and ("bucket-owner" not in acl):
                    author_name = f"S3 Object made public [{aws_account}]"
                    title = f"[{filename}] was uploaded with dangerous permissions in bucket [{bucket_name}]"
                    text = f"*ACL's Added:* {acl}\n*Initiator:* {username}\n*Source IP:* {userip}\n*Location:* {location}"
                    severity = True 
                    #Send to notify service
                    return author_name, title, text, severity 
        else:
            pass
    
    # putObjectACL scanner S3
    def putobjectacl_scanner(self, request, bucket_name, filename, aws_account, username, userip, location):
        print("tests3putobjectacl")
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
                    author_name = f"S3 Object made public [{aws_account}]"
                    title = f"[{filename}] was made public in bucket [{bucket_name}]"
                    text = f"*URI Permissions Added:* {perms_uri}\n*EMAIL Permissions Added:* {perms_email}\n*Email:* {emails}\n*Groups:* {uris}\n*Initiator:* {username}\n*Source IP:* {userip}\n*Location:* {location}"
                    severity = True
                    #Send to notify service
                    return author_name, title, text, severity
                
                # If URI is present and no email   
                elif len(uri) >= 1 and len(set(blacklist_uri).intersection(uri)) >= 1 and len(email) == 0:
                    perms, uris = self.check_perms_uris(uri_perms, uri)
                    author_name = f"S3 Object made public [{aws_account}]"
                    title = f"[{filename}] was made public in bucket [{bucket_name}]"
                    text = f"*Permissions Added:* {perms}\n*Groups:* {uris}\n*Initiator:* {username}\n*Source IP:* {userip}\n*Location:* {location}"
                    severity = True
                    #Send to notify service
                    return author_name, title, text, severity 
                
                # If Email is present and no uri
                elif (len(uri) == 0 and len(email) >= 1):
                    perms_email, emails = self.check_perms_uris(email_perms, email)
                    author_name = f"S3 Object made public [{aws_account}]"
                    title = f"[{filename}] was made public in bucket [{bucket_name}]"
                    text = f"*EMAIL Permissions Added:* {perms_email}\n*Email:* {emails}\n*Initiator:* {username}\n*Source IP:* {userip}\n*Location:* {location}"
                    severity = True
                    #Send to notify service
                    return author_name, title, text, severity 
                    
                else:
                    print("test123456")
                    return 0
                    
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
                        pass
                
                # If URI and Email are both present
                if (len(uri) >= 1 and len(set(blacklist_uri).intersection(uri)) >= 1) and (len(email) >= 1):
                    perms_uri, uris = self.check_perms_uris(uri_perms, uri)
                    perms_email, emails = self.check_perms_uris(email_perms, email)
                    author_name = f"S3 Object made public [{aws_account}]"
                    title = f"[{filename}] was made public in bucket [{bucket_name}]"
                    text = f"*URI Permissions Added:* {perms_uri}\n*EMAIL Permissions Added:* {perms_email}\n*Email:* {emails}\n*Groups:* {uris}\n*Initiator:* {username}\n*Source IP:* {userip}\n*Location:* {location}"
                    severity = True
            
                    #Send to notify service
                    return author_name, title, text, severity
                
                # If URI is present and no email   
                elif len(uri) >= 1 and len(set(blacklist_uri).intersection(uri)) >= 1 and len(email) == 0:
                    perms, uris = self.check_perms_uris(uri_perms, uri)
                    author_name = f"S3 Object made public [{aws_account}]"
                    title = f"[{filename}] was made public in bucket [{bucket_name}]"
                    text = f"*Permissions Added:* {perms}\n*Groups:* {uris}\n*Initiator:* {username}\n*Source IP:* {userip}\n*Location:* {location}"
                    severity = True
                    #Send to notify service
                    return author_name, title, text, severity 
                
                # If Email is present and no uri
                elif (len(uri) == 0 and len(email) >= 1):
                    perms_email, emails = self.check_perms_uris(email_perms, email)
                    author_name = f"S3 Object made public [{aws_account}]"
                    title = f"[{filename}] was made public in bucket [{bucket_name}]"
                    text = f"*EMAIL Permissions Added:* {perms_email}\n*Email:* {emails}\n*Initiator:* {username}\n*Source IP:* {userip}\n*Location:* {location}"
                    severity = True
                    #Send to notify service
                    return author_name, title, text, severity 
                    
                else:
                    print("test123456")
                    return 0

        elif "accessControlList" in request:
            blacklisted = ["uri=http://acs.amazonaws.com/groups/global/AllUsers,uri=http://acs.amazonaws.com/groups/global/AuthenticatedUsers","uri=http://acs.amazonaws.com/groups/global/AllUsers", "uri=http://acs.amazonaws.com/groups/global/AuthenticatedUsers"]
            final_result = []
            for acl in request["accessControlList"]:   
                u = request["accessControlList"][acl]
                print(acl)
                if acl == "x-amz-grant-read" and request["accessControlList"][acl] in blacklisted:
                    print('tette')
                    final_result.append(request["accessControlList"][acl])
                elif acl == "x-amz-grant-full-control" and request["accessControlList"][acl] != "":
                    final_result.append(request["accessControlList"][acl])
                else:
                    print("none caught")
                    pass
            if len(final_result) >= 1:
                author_name = f"S3 Object made public [{aws_account}]"
                title = f"[{filename}] was made public in bucket [{bucket_name}]"
                text = f"*Permissions Added:* ```\n{final_result}```\n*Initiator:* {username}\n*Source IP:* {userip}\n*Location:* {location}"
                severity = True
                #Send to notify service
                return author_name, title, text, severity 
            
        else:
            print("duh!")
            pass
    
    # Security Groups Rule Extraction
    def rules_extraction(self, request):
        try:
            group_id = request["groupId"]
        except KeyError:
            group_id = request['groupName']
        try:
            if len(request["ipPermissions"]) > 0:
                items = request["ipPermissions"]["items"]
                raw_list = []
                for item in items:
                    data = {}

                    protocol = item["ipProtocol"]
                    if protocol == '-1':
                        protocol = "All traffic"

                    if "fromPort" in item:
                        from_port = item["fromPort"]
                        to_port = item["toPort"]

                        if from_port == -1:
                            port = 'NA'
                        elif from_port == to_port:
                            port = from_port
                        elif to_port > from_port:
                            port = str(from_port)+'-'+str(to_port)
                    
                    else:
                        port = 'N/A'

                    data['protocol'] = protocol
                    data['port'] = port

                    #adding another security group inside anoter security group as ingress rule 
                    ingress_group_id = []
                    if "items" in item["groups"]:
                        for k in item["groups"]["items"]:
                            if "groupId" in k:
                                ingress_group_id.append(k["groupId"])

                        data['ingress_group_id'] = ingress_group_id

                    #all the ipv4 ranges
                    ipv4_ranges = []
                    if "items" in item["ipRanges"]:
                        for k in item["ipRanges"]["items"]:
                            ipv4_ranges.append(k)

                        data['ipv4_ranges'] = ipv4_ranges

                    #all the ipv6 ranges
                    ipv6_ranges = []
                    if "items" in item["ipv6Ranges"]:
                        for k in item["ipv6Ranges"]["items"]:
                            ipv6_ranges.append(k)

                        data['ipv6_ranges'] = ipv6_ranges

                    raw_list.append(data)

                #This section converts the raw_string dictionary to a readable string
                string = '' 
                rules = []
                for k in raw_list:
                    if "protocol" in k:
                        string = 'Protocol: ' + k["protocol"] + ' | '
                    
                    if "port" in k:
                        string+= 'Port: ' + str(k["port"]) + ' | '
                    
                    if "ingress_group_id" in k:
                        string+= 'security group: ' + str(k["ingress_group_id"]) + ' | '
                    
                    if 'ipv4_ranges' in k:
                        
                        value = k['ipv4_ranges']

                        final_tmp = ''
                        for v in value:
                            tmp = ''
                            if 'cidrIp' in v:
                                tmp+= v['cidrIp']
                            if 'description' in v:
                                tmp+= ' ('+v['description'] + ')'

                            final_tmp+=tmp+', '

                        if final_tmp.endswith(', '):
                            final_tmp = final_tmp[0:len(final_tmp)-2]

                        string+= 'IPv4 range: [' + final_tmp + '] | '
                        # print(final_tmp)

                    if 'ipv6_ranges' in k:

                        value = k['ipv6_ranges']
                        final_tmp = ''
                        for v in value:
                            tmp = ''
                            if 'cidrIpv6' in v:
                                tmp+= v['cidrIpv6']
                            if 'description' in v:
                                tmp+= ' ('+v['description'] + ')'

                            final_tmp+=tmp+', '

                        if final_tmp.endswith(', '):
                            final_tmp = final_tmp[0:len(final_tmp)-2]

                        string+= 'IPv6 range: [' + final_tmp + '] | '

                    if string.endswith('| '):
                        string = string[0:len(string)-2]

                    rules.append(string)

                # for i in rules:
                #   print(i + '\n')
                rules.append(group_id)
                return rules
            elif len(request['ipPermissions']) == 0 and bool(request['securityGroupRuleIds']):
                items = request['securityGroupRuleIds']['items']
                groups = []
                for item in items:
                    groupID = item['securityGroupRuleId']
                    groups.append(groupID)
                print(groups)
                return groups

        except Exception as em:
            return None

class Configruation:
    def __init__(self, profile='default', config_folder=''):
        self.profile = profile
        self.CONFIG = os.path.join(config_folder, "config.yaml")
        print(f"[+]Loading profile '{profile}' from '{self.CONFIG}' ")
        self.load_config()

    def load_config(self):
        with open(self.CONFIG, 'r') as config_file:
            self.appConfig = yaml.safe_load(config_file.read())
            self.appConfig = self.appConfig[self.profile]


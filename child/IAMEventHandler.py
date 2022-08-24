from utils import EventHandler, Configruation, EventResponse
from GenericEventClassifier import GenericEventClassifier
import unittest
import datetime
import json

class IAMEventHandler(EventHandler):
    def __init__(self, appConfig):
        self.name = 'IAM Event Handler'
        super().__init__(self.name, appConfig)
        self.severity_map = self.appConfig['Severity']['IAM']
        print("[*]IAM Event Classifier loaded with required configuration")
    
    def handle_event(self, event, aws_account):
        eventResponse = self.get_basic_event_information(event, aws_account)

        if "arn" in event["userIdentity"]:
            self.parse_iam_event(event, eventResponse, aws_account)

        elif event["userIdentity"]["userName"] == "HIDDEN_DUE_TO_SECURITY_REASONS":
            self.wrong_username_console_login(event, eventResponse, aws_account)

        elif "errorMessage" in event:
            if event["errorMessage"] == "Failed authentication":
                self.wrong_username_console_login(event, eventResponse, aws_account)
        else:
            return eventResponse
        
        self.classify_event(event, eventResponse)
        print(f"[*]IAM Event Response : {eventResponse.get_response_dict()}")
        return eventResponse
    
    def get_basic_event_information(self, event, aws_account):
        resp = EventResponse('IAM Event')
        # check usage of time variable
        time = event["eventTime"]
        format = "%Y-%m-%dT%H:%M:%S%z"
        time = str(datetime.datetime.strptime(time, format))
        resp.userIp = event["sourceIPAddress"]
        resp.eventId = event['eventID']
        resp.location = self.utils.get_location(resp.userIp)
        resp.other_data['user_agent'] = event["userAgent"]
        resp.eventName = event["eventName"]
        resp.userName = self.utils.username_fetch(event['userIdentity'])
        resp.aws_account = aws_account
        return resp

    def parse_iam_event(self, event, resp, aws_account):
        resp.aws_account = aws_account
        aws_account_id = event['userIdentity']['accountId']
        if "errorMessage" in event:
            error_msg = event["errorMessage"]
            event_name_original = event["eventName"]
            event_name_error = 'error'
            event_name = event_name_original + ' ' + event_name_error
            #pass actual event name as well
            resp.eventName = event_name
            resp.author_name = f"IAM error [{aws_account}]"
            resp.title = '['+event_name+']'+ " - "+error_msg
            resp.text = f"*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
            return resp
            
        # User Alerts
        elif resp.eventName == "CreateUser":
            userName = event["responseElements"]["user"]["userName"]
            print(resp.userName + ' - IAM username was created')
            resp.author_name = f"IAM user created [{aws_account}]"
            resp.title = '['+userName+']'+ " - new user was created"
            resp.text = f"*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"

        elif resp.eventName ==  "DeleteUser":
            userName = event["requestParameters"]["userName"]
            print(resp.userName + " has been deleted")
            resp.author_name = f"IAM user deleted [{aws_account}]"
            resp.title = '['+userName+']'+ " - user got deleted"
            resp.text = f"*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
        
        # Login Profile Alerts
        elif resp.eventName == "CreateLoginProfile":
            userName = event["responseElements"]["loginProfile"]["userName"]
            pwd_reset_boolean = str(event["responseElements"]["loginProfile"]["passwordResetRequired"])
            print("A new Login profile & password has been created for ["+ resp.userName +"] to access AWS services through the management console.")
            print("passwordResetRequired: "+ pwd_reset_boolean)
            resp.author_name = f"IAM login profile created [{aws_account}]"
            resp.title = "New console password for user" + ' ['+ userName +'] ' + "got created"
            resp.text = f"*NOTE:* A new password has been created for a user to access AWS services through the management console.\n*Password reset required:* {pwd_reset_boolean}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"

        elif resp.eventName == "DeleteLoginProfile":
            userName = event["requestParameters"]["userName"]
            print("Login profile & password for "+ userName +" has been deleted thus removing that user's ability to access services through the console.")
            resp.author_name = f"IAM login profile deleted [{aws_account}]"
            resp.title = "Login profile for user" + ' ['+userName+'] ' + "got deleted"
            resp.text = f"*NOTE:* Login profile & password has been deleted for the above user, thus removing the user's ability to access services through the console.\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"

        # Virtual MFA Alerts  
        elif resp.eventName == "CreateVirtualMFADevice":
            mfa_device_name = event["requestParameters"]["virtualMFADeviceName"]
            mfa_arn = event["responseElements"]["virtualMFADevice"]["serialNumber"]
            print("MFA enabled for user "+mfa_device_name)
            print("A new virtual MFA device [" + mfa_arn + "] has been created for this AWS account.")
            resp.author_name = f"IAM MFA created [{aws_account}]"
            resp.title = "MFA enabled for user: " + ' ['+mfa_device_name+'] '
            resp.text = f"*MFA arn:* {mfa_arn}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
  
        elif resp.eventName == "DeleteVirtualMFADevice":
            mfa_arn = event["requestParameters"]["serialNumber"]
            print("MFA deleted for user "+mfa_arn)
            resp.author_name = f"IAM MFA deleted [{aws_account}]"
            resp.title = f"MFA deleted for user arn: [{mfa_arn.split('mfa/')[1]}]"
            resp.text = f"\n*MFA arn:* {mfa_arn}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
        
        # Group Alerts
        elif resp.eventName == "CreateGroup":
            group_name = event["requestParameters"]["groupName"]
            print(group_name + " - new group was created")
            resp.author_name = f"IAM group created [{aws_account}]"
            resp.title = "New group created: "+group_name
            resp.text = f"*IAM-Group:* {group_name}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
    
        elif resp.eventName == "AddUserToGroup":
            group_name = event["requestParameters"]["groupName"]
            userName = event["requestParameters"]["userName"]
            print(resp.userName + ' was added to group: ' + group_name)
            resp.author_name = f"IAM user added to group [{aws_account}]"
            resp.title = "User ["+ resp.userName +"] added to group: "+group_name
            resp.text = f"*IAM-User:* {userName}\n*IAM-Group:* {group_name}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
            

        elif resp.eventName == "RemoveUserFromGroup":
            group_name = event["requestParameters"]["groupName"]
            userName = event["requestParameters"]["userName"]
            print(resp.userName + " was removed from the group: "+ group_name)
            resp.author_name = f"IAM user removed from group [{aws_account}]"
            resp.title = "User ["+ userName +"] removed from group: "+group_name
            resp.text = f"*IAM-User:* {userName}\n*IAM-Group:* {group_name}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"

        elif resp.eventName == "AttachGroupPolicy":
            group_name = event["requestParameters"]["groupName"]
            policy_arn = event["requestParameters"]["policyArn"]
            print(policy_arn + " was attached to group: " + group_name)
            policy_arn = policy_arn.split("policy/")[1]
            resp.author_name = f"IAM policy attached to group [{aws_account}]"
            resp.title = "Policy ["+ policy_arn +"] attached to group: "+group_name
            resp.text = f"*IAM-Group:* {group_name}\n*IAM-Policy:* {policy_arn}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
            
        elif resp.eventName == "DetachGroupPolicy":
            group_name = event["requestParameters"]["groupName"]
            policy_arn = event["requestParameters"]["policyArn"]
            print(policy_arn + " was detached from group: " + group_name)
            policy_arn = policy_arn.split("policy/")[1]
            resp.author_name = f"IAM policy detached from group [{aws_account}]"
            resp.title = "Policy ["+ policy_arn +"] detached from group: "+group_name
            resp.text = f"*IAM-Group:* {group_name}\n*IAM-Policy:* {policy_arn}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
            
        elif resp.eventName == "DeleteGroup":
            group_name = event["requestParameters"]["groupName"]
            print(group_name + " - group was deleted")
            resp.author_name = f"IAM group deleted [{aws_account}]"
            resp.title = "Group deleted: "+group_name
            resp.text = f"*IAM-Group:* {group_name}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"

        # Access Key Alerts
        elif resp.eventName == "CreateAccessKey":
            userName = event["responseElements"]["accessKey"]["userName"]
            accesskey_id = event["responseElements"]["accessKey"]["accessKeyId"]
            print("a new access key [Id: "+ accesskey_id +"] was created for " + userName)
            resp.author_name = f"IAM Access key created [{aws_account}]"
            resp.title = "New Access key ["+accesskey_id+"] created for user ["+userName+"]"
            resp.text = f"*Access-Key:* {accesskey_id}\n*IAM-User:* {userName}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
            
        elif resp.eventName == "UpdateAccessKey":
            userName = event["requestParameters"]["userName"]
            accesskey_id = event["requestParameters"]["accessKeyId"]
            accesskey_status = event["requestParameters"]["status"]
            print(resp.userName + " access key [Id: "+ accesskey_id +"] state has been changed. ")
            print("access key status: " + accesskey_status)
            resp.author_name = f"IAM Access key state changed [{aws_account}]"
            resp.title = " State of Access key ["+accesskey_id+"] belonging to user ["+userName+"] got changed"
            resp.text = f"*New state:* {accesskey_status}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"

        elif resp.eventName == "DeleteAccessKey":
            userName = event["requestParameters"]["userName"]
            accesskey_id = event["requestParameters"]["accessKeyId"]
            print(resp.userName + " access key [Id: "+ accesskey_id +"] has been deleted ")
            resp.author_name = f"IAM Access key deleted [{aws_account}]"
            resp.title = "Access key ["+accesskey_id+"] deleted for user ["+userName+"]"
            resp.text = f"*Access-Key:* {accesskey_id}\n*IAM-User:* {userName}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"

        # Policy Alerts
        elif resp.eventName == "CreatePolicy":
            policy_name = event["requestParameters"]["policyName"]
            policy_document = json.loads(event['requestParameters']['policyDocument'])
            if event['responseElements'] != None:
                policyARN = event['responseElements']['policy']['arn']
                print(policyARN)
            else:
                try:
                    if event['requestParameters']['path'] == "/service-role/":
                        policyARN = f"arn:aws:iam::{aws_account_id}:policy/service-role/{policy_name}"
                except Exception as em:
                    print(em)
            statement = policy_document['Statement']
            status = self.utils.statement_scanner(statement)
            print('sending for admin checks')
            print(status)
            if status == "Admin Access":
                resp.author_name = f"Admin Policy Created [{aws_account}]"
                resp.title = f"Admin Policy Created: {policy_name}"
                resp.text = f"\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
            else:
                print(policy_name+ " was created")
                resp.author_name = f"IAM policy created [{aws_account}]"
                resp.title = "New IAM policy ["+policy_name+"] created"
                resp.text = f"*Policy added:*\n```{policy_document}```\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
        
        elif resp.eventName == "CreatePolicyVersion":
            policy = json.loads(event['requestParameters']['policyDocument'])
            policyARN = event['requestParameters']['policyArn']
            policyName = self.utils.policy_name_extractor(policyARN)
            statement = policy['Statement']
            status = self.utils.statement_scanner(statement)
            if status == "Admin Access":
                resp.author_name = f"New Policy Version Created with ADMIN Access [{aws_account}]"
                resp.title = f"Admin Policy version created: {policyName}"
                resp.text = f"\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
        
        elif resp.eventName == "AttachUserPolicy":
            userName = event["requestParameters"]["userName"]
            policy_arn = event["requestParameters"]["policyArn"]
            print(policy_arn + " was attached to user: " + userName)
            policy_arn = policy_arn.split("policy/")[1]
            resp.author_name = f"IAM policy attached to user [{aws_account}]"
            resp.title = "Policy ["+policy_arn+"] attached to ["+ resp.userName +"]"
            resp.text = f"*IAM-Policy:* {policy_arn}\n*IAM-User:* {userName}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"

        elif resp.eventName == "DetachUserPolicy":
            userName = event["requestParameters"]["userName"]
            policy_arn = event["requestParameters"]["policyArn"]
            print(policy_arn + " was detached from user: " + userName)
            policy_arn = policy_arn.split("policy/")[1]
            resp.author_name = f"IAM policy detached from user [{aws_account}]"
            resp.title = "Policy ["+policy_arn+"] detached from ["+ resp.userName +"]"
            resp.text = f"*IAM-Policy:* {policy_arn}\n*IAM-User:* {userName}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"

        elif resp.eventName == "DeletePolicy":
            policy_arn = event["requestParameters"]["policyArn"]
            print(policy_arn + " was deleted")
            policy_arn = policy_arn.split("policy/")[1]
            resp.author_name = f"IAM policy deleted [{aws_account}]"
            resp.title = "IAM policy ["+policy_arn+"] deleted"
            resp.text = f"*IAM-Policy:* {policy_arn}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
        
        # Role Alerts
        elif resp.eventName == "CreateRole":
            role_name = event["requestParameters"]["roleName"]
            role_policy = event["requestParameters"]["assumeRolePolicyDocument"]
            role_description = ""
            if "description" in event["requestParameters"]:
                role_description = event["requestParameters"]["description"]
                #print("Role Description: " + role_description)
            print(role_name + " role was created")
            #print("Role policy: "+ role_policy)
            parsed_json = json.loads(role_policy)
            role_policy = (json.dumps(parsed_json, indent = 2,sort_keys=False))
            resp.author_name = f"IAM role created [{aws_account}]"
            resp.title = "New IAM role ["+role_name+"] created"
            resp.text = f"*Role Policy:*\n```{role_policy}```\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"

        elif resp.eventName == "AttachRolePolicy":
            role_name = event["requestParameters"]["roleName"]
            policy_arn = event["requestParameters"]["policyArn"]
            #print(policy_arn + " attached to role: " + role_name)
            policy_arn = policy_arn.split("policy/")[1]
            resp.author_name = f"IAM policy attached to role [{aws_account}]"
            resp.title = "Policy ["+policy_arn+"] attached to role: ["+ role_name +"]"
            resp.text = f"*IAM-Policy:*\n{policy_arn}\n*IAM-Role:* {role_name}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"

        elif resp.eventName == "DetachRolePolicy":
            role_name = event["requestParameters"]["roleName"]
            policy_arn = event["requestParameters"]["policyArn"]
            #print(policy_arn + " detached from role: " + role_name)
            policy_arn = policy_arn.split("policy/")[1]
            resp.author_name = f"IAM policy detached from role [{aws_account}]"
            resp.title = "Policy ["+policy_arn+"] detached from role: ["+ role_name +"]"
            resp.text = f"*IAM-Policy:*\n{policy_arn}\n*IAM-Role:* {role_name}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"

        elif resp.eventName == "DeleteRole":
            role_name = event["requestParameters"]["roleName"]
            #print(role_name + " role was deleted")
            resp.author_name = f"IAM role deleted [{aws_account}]"
            resp.title = "IAM role ["+role_name+"] deleted"
            resp.text = f"*IAM-Role:* {role_name}\n*Initiator:* {resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"
        
        elif resp.eventName == "CheckMfa":
            print("[+]CheckMFA requested")
            role_name = event["userIdentity"]["userName"]
            event_type = event["eventType"]
            resp.author_name = f"CheckMFA requested for {aws_account}"
            resp.title = "IAM role requested CheckMfa"
            resp.text = f"*IAM-Role:* {role_name}\n*Event Type:* {event_type}\n*Initiator:*{resp.userName}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}"         
        # Console Login Alerts
        elif resp.eventName == "ConsoleLogin":
            print('[+]Checking consolelogin')
            if 'assumed-role' not in resp.userName:
                consolelogin_status = event["responseElements"]["ConsoleLogin"]
                additional_event_data = str(event["additionalEventData"])
                print("User logged in through console bypassing Identity provider")
                print("Login Status: " + consolelogin_status)
                print(additional_event_data)

                if "root" in resp.userName:
                    resp.author_name = f"Root user login [{aws_account}]"
                else:
                    resp.author_name = f"User console login [{aws_account}]"

                resp.title = "User logged in through console bypassing OKTA"
                resp.text = f"*Console login status:* {consolelogin_status}\n*Event data:* ```{additional_event_data}```\n*User Agent:* {resp.other_data['user_agent']}\n*User name:* {resp.userName}"

            else:
                print('[+]Got assumed role, bypassing the alert')
                resp.skipped = True

        
    def classify_event(self, event, resp):
        if resp.skipped == False:
            eventClassifier = GenericEventClassifier(self.severity_map)
            data = eventClassifier.classify_event(resp.author_name, resp.eventName)
            resp.severity = data['severity']
        else:
            resp.severity = 'LOW'
        print(f'[*] IAM Event has severity [{resp.severity}]')
    
    def wrong_username_console_login(self, event, resp, aws_account):
        print("[+] Someone trying to login through console bypassing Identity provider!")
        print("[+] Login Failed: Wrong username entered")
        consolelogin_status = event["responseElements"]["ConsoleLogin"]
        additional_event_data = str(event["additionalEventData"])
        if event["errorMessage"] == "Failed authentication":
            title = "Console Login attempt with wrong password"
            user = event["userIdentity"]["userName"]
            resp.userName = user
        else:
            title = "Console Login attempt with unknown username."
            user = event["userIdentity"]["userName"]
        author_name = f"Failed console Login attempt [{aws_account}]"
        text = "*WARNING:* Could be a possible bruteforce if number of event exceeds too much!\n*Console login status:* "+ consolelogin_status +"\n*Event data:* ```"+additional_event_data+"```\n*User Agent:* "+ resp.other_data['user_agent'] +" \n*User name:* " + user
        resp.other_data['consolelogin_status'] = consolelogin_status
        resp.other_data['additional_event_data'] = additional_event_data
        resp.title = title
        resp.author_name = author_name
        resp.text = text
        resp.aws_account = aws_account
        return resp

    

class IAMEventHandlerTest(unittest.TestCase):
    def test_load_default_application_config(self):
        conf = Configruation()
        IAMEventHandler(conf.appConfig)
                         
if __name__ == '__main__':
    unittest.main()
from utils import EventHandler, Configruation, EventResponse
import unittest
import datetime
import re
import json

class EC2EventHandler(EventHandler):
    def __init__(self, appConfig):
        self.name = 'EC2 Event Handler'
        super().__init__(self.name, appConfig)
        self.neglected_users = self.appConfig['Static']['EC2']['Whitelisted-User-Ip']
        self.severity_map = self.appConfig['Severity']['EC2']
        print("[*]EC2 Event Classifier loaded with required configuration")
    
    def handle_event(self, event_data, aws_account):
        eventResponse = self.classify_event(event_data, aws_account)
        print(f"[*]EC2 Classifier response : {eventResponse.get_response_dict()}")
        return eventResponse

    @staticmethod
    def timestamp():
        return str(datetime.datetime.now(datetime.timezone.utc)).split('.')[0] + "GMT"
    
    def classify_event(self, event, aws_account):
        eventName = event["eventName"]
        userIdentity = event["userIdentity"]
        arn = self.utils.username_fetch(event['userIdentity'])
        ip = event["sourceIPAddress"]
        awsRegion = event["awsRegion"]
        instance_id = ""
        event_id = event["eventID"]
        username = re.search("/(.*)", arn).group(1)
        # Whitelisted Usernames
        title = ""
        eventResponse = EventResponse('EC2 Event')
        eventResponse.eventName = eventName
        eventResponse.arn = arn
        eventResponse.userName = arn
        eventResponse.aws_account = aws_account
        eventResponse.userIp = ip
        eventResponse.aws_region = awsRegion
        eventResponse.eventId = event_id
        eventResponse.location = self.utils.get_location(eventResponse.userIp)
        # If username is one of whitelisted ones, then this script will not be invoked.
        if username in self.neglected_users or ip in self.neglected_users:
            print(f'[!]Username[{username}] or IP[{ip}] in whitelist. Skipping')
            eventResponse.skipped = True
            pass
        
        else:
            print(f"[+]At EC2 asset tracker handler with event: {eventName}")
            # Run Instance alerts
            if eventName == "RunInstances":
                print(f"[+]Processing event for message parsing: {eventName}")
                bottom_text = "*EC2 Creation Alerts* | *"
                if "errorCode" in event:
                    print(f"[+]Got error in the event: {eventName}")
                    severity = self.severity_map['RunInstances']['Error']
                    error = True
                    error_message = event['errorMessage']
                    author_name = f"EC2 Error [{aws_account}]"
                    title = f"[{eventResponse.eventName}] - {error_message}"
                    text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                else:
                    error = False
                    print(f"[+]Got success data in the event: {eventName}")
                    if event["responseElements"] is not None:
                        for i in event["responseElements"]["instancesSet"]["items"]:
                            instance_id += i["instanceId"] + ", "
                        if (instance_id.count(",") == 1):
                            title = f"Instance [{instance_id[:-2]}] created [{aws_account}]"
                            instance_id = instance_id[:-2]
                            severity = self.severity_map['RunInstances']['SingleInstance']
                            author_name = f"EC2 - {title}"
                            text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                        else:
                            title = str(instance_id.count(",")) + f" new instances created [{aws_account}]"
                            instance_id = instance_id[:-2]
                            severity = self.severity_map['RunInstances']['MultipleInstances']
                            author_name = f"EC2 - {title}"
                            text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                
                    else:
                        instance_id = "n/a"
                        title = f"New Instance created [{aws_account}]"
                        severity = self.severity_map['RunInstances']['Default']
                        author_name = f"EC2 - {title}"
                        text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                
                
            # Stop Instance Alerts
            elif eventName == "StopInstances":
                bottom_text = "*EC2 Stoppage Alerts* | *"
                print(f"[+]Processing event for message parsing: {eventName}")
                if "errorCode" in event:
                    print(f"[+]Got error in the event: {eventName}")
                    title = f"[ERROR] Instance stoppage failed [{aws_account}]"
                    instance_id = "n/a\nError: " + event["errorCode"]
                    severity = self.severity_map['StopInstances']['Error']
                    error = True
                    author_name = f"EC2 - {title}"
                    text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                else:
                    error = False
                    print(f"[+]Got success data in the event: {eventName}")
                    if event["responseElements"] is not None:
                        instance_id = event["responseElements"]["instancesSet"]["items"][0]["instanceId"]
                        title = f"Instance [{instance_id}] stopped [{aws_account}]"
                        severity = self.severity_map['StopInstances']['Stopped']
                        author_name = f"EC2 - {title}"
                        text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    else:
                        instance_id = "n/a"
                        title = f"Instance stopped [{aws_account}]"
                        severity = self.severity_map['StopInstances']['Default']
                        author_name = f"EC2 - {title}"
                        text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                
                
            # Terminate Instance Alerts
            elif eventName == "TerminateInstances":
                print(f"[+]Processing event for message parsing: {eventName}")
                bottom_text = "*EC2 Termination Alerts* | *"
                if "errorCode" in event:
                    print(f"[+]Got error in the event: {eventName}")
                    title = f"[ERROR] Instance termination failed [{aws_account}]"
                    instance_id = "n/a\nError: " + event["errorCode"]
                    severity = self.severity_map['TerminateInstances']['Default']
                    error = True
                    author_name = f"EC2 - {title}"
                    text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                
                else:
                    error = False
                    print(f"[+]Got success data in the event: {eventName}")
                    if event["responseElements"] is not None:
                        for i in event["responseElements"]["instancesSet"]["items"]:
                            instance_id += i["instanceId"] + ", "
                        if (instance_id.count(",") == 1):
                            title = f"Instance [{instance_id[:-2]}] terminated [{aws_account}]"
                            instance_id = instance_id[:-2]
                            severity = self.severity_map['TerminateInstances']['SingleInstance']
                            author_name = f"EC2 - {title}"
                            text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                
                        else:
                            title = str(instance_id.count(",")) + f" instances terminated [{aws_account}]"
                            instance_id = instance_id[:-2]
                            severity = self.severity_map['TerminateInstances']['MultipleInstances']
                            author_name = f"EC2 - {title}"
                            text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                
                    else:
                        instance_id = "n/a"
                        title = f"Instance termination [{aws_account}]"
                        severity = self.severity_map['TerminateInstances']['Default']
                        author_name = f"EC2 - {title}"
                        text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                
            else:
                title = 'Unclassified event'
                severity = 'UNKNOWN'
                instance_id = 'Unknown'
                text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                author_name = f"EC2 - {title}"
            
            eventResponse.title = title
            eventResponse.author_name = author_name
            eventResponse.text = text
            eventResponse.severity = severity
            eventResponse.aws_resources = instance_id
            eventResponse.error = error
            eventResponse.bottom_text = bottom_text
        return eventResponse


class EC2EventHandlerTest(unittest.TestCase):
    def test_load_default_application_config(self):
        conf = Configruation()
        EC2EventHandler(conf.get_service_config('EC2'))
    
    def test_run_instance_event(self):
        event = json.loads(open('test-events/runInstance.json','r').read())
        conf = Configruation()
        ec2 = EC2EventHandler(conf.get_service_config('EC2'))
        resp = ec2.classify_event(event).get_response_dict()
        print("RunInstances Response : ", resp)
        self.assertEqual(resp['skipped'], False)
        self.assertEqual(resp['eventName'], 'RunInstances')
        self.assertEqual(resp['aws_account'], 'STAGE')
        self.assertEqual(resp['aws_resources'], 'i-06489151c0aedc8a6')
        self.assertEqual(resp['severity'], conf.appConfig['EC2']['Severity']['RunInstances']['SingleInstance'])                    
    
    def test_stop_instance_event(self):
        event = json.loads(open('test-events/stopInstance.json','r').read())
        conf = Configruation()
        ec2 = EC2EventHandler(conf.get_service_config('EC2'))
        resp = ec2.classify_event(event).get_response_dict()
        print("StopInstances Response : ", resp)
        self.assertEqual(resp['skipped'], False)
        self.assertEqual(resp['eventName'], 'StopInstances')
        self.assertEqual(resp['aws_account'], 'STAGE')
        self.assertEqual(resp['severity'], conf.appConfig['EC2']['Severity']['StopInstances']['Stopped'])                    
        
    def test_terminate_instance_event_autoscaled(self):
        event = json.loads(open('test-events/terminateInstance.json','r').read())
        conf = Configruation()
        ec2 = EC2EventHandler(conf.get_service_config('EC2'))
        resp = ec2.classify_event(event).get_response_dict()
        print("TerminateInstance AutoScaling Response : ", resp)
        self.assertEqual(resp['skipped'], True)
        self.assertEqual(resp['eventName'], 'TerminateInstances')
        self.assertEqual(resp['aws_account'], 'STAGE')

if __name__ == '__main__':
    unittest.main()
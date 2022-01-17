#! /usr/bin/python3

from utils import EventHandler, EventResponse, Configruation
import unittest
import json

class SSMEventHandler(EventHandler):
    def __init__(self, appConfig):
        name = 'SSM'
        super().__init__(name, appConfig)
        self.severity_map = appConfig['Severity']['SSM']
    
    def handle_event(self, event_data, aws_account):
        response = self.get_event_response(event_data, aws_account)
        print(f"[*]SSM Classifier Response : {response.get_response_dict()}")
        return response
    
    def get_event_response(self, event, aws_account):
        eventResponse = EventResponse('SSM Event')
        eventResponse.eventId = event["eventID"]
        eventResponse.userName = self.utils.username_fetch(event['userIdentity'])
        eventResponse.eventName = event["eventName"]
        eventResponse.userIp = event['sourceIPAddress']
        eventResponse.other_data['eventTime'] = event['eventTime']
        eventResponse.aws_account = aws_account
        eventResponse.aws_region = event['awsRegion']
        param_name = event['requestParameters']['name']
        eventResponse.other_data['param_name'] = param_name
        eventResponse.location = self.utils.get_location(eventResponse.userIp)
        eventResponse.text = f"*Initiator:* {eventResponse.userName}\n*Parameter name:* {param_name}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
        error = "errorMessage" in event
        eventResponse.error = error
        eventResponse.title, eventResponse.author_name = self.get_title_and_author_name(eventResponse, param_name)
        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
        
        return eventResponse

    def get_title_and_author_name(self, eventResponse, param_name, error=False):
        eventName = eventResponse.eventName 
        env = eventResponse.aws_account
        if eventName == "GetParameter":
            author_name = f"SSM Parameter Read - [{env}]"
            title = f"Parameter Value Read : {param_name}"
        elif eventName == "DeleteParameter":
            author_name = f"SSM Parameter deleted - [{env}]"
            title = f"Parameter Value Changed : {param_name}"
        elif eventName == "PutParameter":
            author_name = f"SSM Parameter Value Changed - [{env}]"
            title = f"Parameter Value Changed : {param_name}"
        elif error:  
            author_name = f"SSM error [{env}]"
            title = "Unauthrozied Access Detected"
        return title,author_name

    def get_event_severity(self, eventName, error=False):
        if error:
            return self.severity_map[eventName]['Error']
        return self.severity_map[eventName]['Default']

class SSMEventHandlerTest(unittest.TestCase):
    def test_load_default_application_config(self):
        conf = Configruation()
        SSMEventHandler(conf.appConfig)
    
if __name__ == '__main__':
    unittest.main()
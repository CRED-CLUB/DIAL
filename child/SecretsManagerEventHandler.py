#! /usr/bin/python3

from utils import EventResponse, EventHandler, Configruation
import unittest
import json

class SecretsManagerEventHandler(EventHandler):
    def __init__(self, appConfig):
        name = 'Secrets Manager Event Handler'
        super().__init__(name, appConfig)
        self.severity_map = self.appConfig['Severity']['SecretsManager']
        print("[*] Secrets Manager Event Handler loaded.")
    
    def handle_event(self, event_data, aws_account):
        eventResponse = self.classify_event(event_data, aws_account)
        print(f"[*] Secrets Manager Classifier response : {eventResponse.get_response_dict()}")
        return eventResponse
    
    def classify_event(self, event, aws_account):
        eventResponse = EventResponse("Secrets Manager Event")
        eventResponse.eventId = event["eventID"]
        userName = self.utils.username_fetch(event['userIdentity'])
        eventName = event["eventName"]
        userIP = event['sourceIPAddress']
        eventResponse.other_data['eventTime'] = event['eventTime']
        # process data
        secret_name = event['requestParameters']['secretId']
        eventResponse.aws_region = event['awsRegion']
        location = self.utils.get_location(userIP)
        eventResponse.text = f"*Initiator:* {userName}\n*Secret name:* {secret_name}\n*Source IP:* {userIP}\n*Location:* {location}"
        error = "errorMessage" in event
        eventResponse.error = error
        # get title, author_name and event severity
        eventResponse.title, eventResponse.author_name = self.get_title_and_authors_name(eventName, secret_name, aws_account, error)
        eventResponse.severity = self.get_event_severity(eventName, error)
        eventResponse.userName = userName
        eventResponse.eventName = eventName
        eventResponse.userIp = userIP
        eventResponse.aws_account = aws_account
        eventResponse.aws_resources = secret_name
        eventResponse.location = location
        return eventResponse
        
    def get_title_and_authors_name(self, eventName, secret_name, env, error):
        if eventName == "GetSecretValue":
            author_name = f"Secret Value Read - [{env}]"
            title = f"Secret Value Read: {secret_name}"
        elif eventName == "UpdateSecret":
            author_name = f"Secret Encryption Updated - [{env}]"
            title = f"Secret Encrpytion changed: {secret_name}"
        elif eventName == "DeleteSecret":
            author_name = f"Secret Deleted - [{env}]"
            title = f"Secret Value Deleted: {secret_name}"
        elif eventName == "PutSecretValue":
            author_name = f"Secret Key changed - [{env}]"
            title = f"Secret Value Changed: {secret_name}"
        elif error:
            author_name = f"Secrets Manager error [{env}]"
            title = "Unauthrozied Access Detected"
        return title,author_name

    def get_event_severity(self, eventName, error=False):
        print(f"Event [{eventName}]; error = {error}")
        if error:
            return self.severity_map[eventName]['Error']
        return self.severity_map[eventName]['Default']

class SecretsManagerEventHandlerTest(unittest.TestCase):
    def test_load_default_application_config(self):
        conf = Configruation()
        SecretsManagerEventHandler(conf.get_service_config('Secrets-Manager'))
    
if __name__ == '__main__':
    unittest.main()
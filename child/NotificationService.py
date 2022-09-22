from abc import abstractmethod
from datetime import datetime
import boto3
import os
import json
import requests

def send_notifications(appConfig, notification):
    services = appConfig['Notifications']
    
    try:
        if "Console" in services and services["Console"]["Enabled"]:
            ConsoleNotificationService().notify(notification)
    except:
        pass
    
    try:
        if "Slack" in services and services["Slack"]["Enabled"]:
            SlackNotificationService(appConfig).notify(notification)
        elif "GoogleGroups" in services and services["GoogleGroups"]["Enabled"]:
            SlackNotificationService(appConfig).notify(notification)
    
    except Exception as e:
        print(f'[-]Error sending slack notification. error = {e}')
        #raise e
    
    try:
        if "DIAL" in services and services["DIAL"]["Enabled"]:
            DialNotficationService(appConfig).notify(notification)
    
    except Exception as e:
        print(f"[-]ERROR notifying DIAL Master")
        # backup error handling ? save event to s3 / send to queue
    
    

class NotificationService:
    def __init__(self, name):
        self.name = name
    
    @abstractmethod
    def notify(self, event_data):
        pass

    @abstractmethod
    def get_severity(self, event_data):
        pass

class ConsoleNotificationService(NotificationService):
    def __init__(self):
        SERVICE_NAME = 'Console Test Notification Service'
        super().__init__(SERVICE_NAME)
        
    def notify(self, event_data): 
        print("[Notification]")
        print(json.dumps(event_data.get_response_dict()))

class SlackNotificationService(NotificationService):
    def __init__(self, appConfig):
        SERVICE_NAME = 'Slack Notification Service'
        self.slack_hook_url = appConfig['Notifications']['Slack']['Hook']
        super().__init__(SERVICE_NAME)
        self.appConfig = appConfig
    
    def notify(self, eventResponse): 
        color = '#03a9f4'
        event_url = f'https://{eventResponse.aws_region}.console.aws.amazon.com/cloudtrail/home?region={eventResponse.aws_region}#/events/{eventResponse.eventId}'
        print("At Slack Notification Service...", eventResponse.event_type, eventResponse.severity)
        if eventResponse.event_type == "GuardDuty Event":
            colour = eventResponse.severity_level
        elif eventResponse.severity.lower() == "high":
            color = '#9d1111'
        elif eventResponse.severity.lower() == "medium":
            color = '#ffae42'

        if (eventResponse.skipped == True) or (eventResponse.title == "" or eventResponse.author_name == "" or eventResponse.text == ""):
            print(f"Event: {eventResponse.eventName} SKIPPED.")
            print(f"Event Details:{eventResponse.eventId}")
            return

        body = {
            "attachments":[{
                "title": eventResponse.title,
                "author_name": eventResponse.author_name,
                "fallback": eventResponse.author_name,
                "title_link": event_url,
                "text": eventResponse.text,
                "footer": "\nDIAL Security Alerts | "+str(datetime.now()),
                "color":color,
                "footer_icon": "https://raw.githubusercontent.com/g33kyrash/icons/master/aws_icon_1.png"
            }]}
        if eventResponse.event_type == "GuardDuty Event":
            body["attachments"][0]['footer'] = eventResponse.bottom_text + str(datetime.now()) 
        try:
            headers = {"Content-Type": "application/json"}
            response = requests.post(self.slack_hook_url, headers=headers, json=body)
            print(f"[*]Slack Message sent. Response Code : {response.status_code}")
        except Exception as em:
            print("[-] Error sending slack notification: " + str(em))

# Class for Google Groups Notification Service
class GoogleGroupsNotificationService(NotificationService):
    def __init__(self, appConfig):
        SERVICE_NAME = "Google Groups Notification Service"
        self.google_groups_hook_url = appConfig["Notifications"]["GoogleGroups"]["Hook"]
        super().__init__(SERVICE_NAME)
        self.appConfig = appConfig

    def notify(self, eventResponse):
        color = "#03a9f4"
        event_url = f"https://{eventResponse.aws_region}.console.aws.amazon.com/cloudtrail/home?region={eventResponse.aws_region}#/events/{eventResponse.eventId}"
        print(
            "At Google Groups Notification Service...",
            eventResponse.event_type,
            eventResponse.severity,
        )
        if eventResponse.event_type == "GuardDuty Event":
            color = eventResponse.severity_level
        elif eventResponse.severity.lower() == "high":
            color = "#9d1111"
        elif eventResponse.severity.lower() == "medium":
            color = "#ffae42"

        if (eventResponse.skipped == True) or (
            eventResponse.title == ""
            or eventResponse.author_name == ""
            or eventResponse.text == ""
        ):
            print(f"Event: {eventResponse.eventName} SKIPPED.")
            print(f"Event Details:{eventResponse.eventId}")
            return

        body = {
            "cards": [
                {
                    "header": {
                        "imageUrl": "https://raw.githubusercontent.com/g33kyrash/icons/master/aws_icon_1.png",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "textParagraph": {
                                        "text": "<b>{0}</b>\n<i>{1}</i>".format(
                                            eventResponse.title,
                                            eventResponse.author_name,
                                        ),
                                    }
                                }
                            ]
                        },
                        {
                            "widgets": [
                                {
                                    "textParagraph": {
                                        "text": '{0}\n\n<b>Severity</b>\n<font color="{1}">{2}</font>'.format(
                                            eventResponse.text,
                                            color,
                                            eventResponse.severity,
                                        ),
                                    }
                                },
                                {
                                    "textParagraph": {
                                        "text": "\nDIAL Security Alert | "
                                        + str(datetime.now())
                                    }
                                },
                                {
                                    "buttons": [
                                        {
                                            "textButton": {
                                                "text": "Check Event",
                                                "onClick": {
                                                    "openLink": {
                                                        "url": "{0}".format(event_url),
                                                    }
                                                },
                                            }
                                        }
                                    ]
                                },
                            ]
                        },
                    ],
                }
            ],
        }
        if eventResponse.event_type == "GuardDuty Event":
            body["attachments"][0]["footer"] = eventResponse.bottom_text + str(
                datetime.now()
            )
        try:
            headers = {"Content-Type": "application/json; charset=UTF-8"}
            response = requests.post(
                self.google_groups_hook_url, headers=headers, json=body
            )
            print(
                f"[*]GoogleGroups Message sent. Response Code : {response.status_code}"
            )
        except Exception as em:
            print("[-] Error sending GoogleGroups notification: " + str(em))

class DialNotficationService(NotificationService):
    def __init__(self, appConfig):
        SERVICE_NAME = 'DIAL Notification Service'
        self.dial_master_url = appConfig['Notifications']['DIAL']['Master-URL']
        self.dial_master_auth_token = appConfig['Notifications']['DIAL']['X-DIALv2-Master-auth']
        super().__init__(SERVICE_NAME)
    
    def notify(self, eventResponse):
        body = {
            "Group": eventResponse.event_type,
            "Title": eventResponse.author_name,
            "Text": eventResponse.title,
            "Desc": eventResponse.text,
            "User": eventResponse.userName,
            "SourceIp": eventResponse.userIp,
            "EventTime": eventResponse.eventTime,
            "EventName": eventResponse.eventName,
            "Location": eventResponse.location,
            "Severity": eventResponse.severity,
            "Environment": eventResponse.aws_account
        }
        headers = {'X-DIALv2-Master-auth': self.dial_master_auth_token}
        print(f"[+]Sending event to DIAL Master")
        response = requests.post(self.dial_master_url, headers=headers, json=body)
        print(f"[*]DIAL Response [{response.status_code}]: {response.text}")


# Example extension 
# Upto the user/org
class BackupNotificationService(NotificationService):
    def __init__(self, appConfig):
        SERVICE_NAME = '[Backup] Cross Account Backup Event Store'
        self.s3_bucket_name = appConfig['Notifications']['Backup']['S3BucketName']
        self.cross_account_role_arn = appConfig['Notifications']['Backup']['CrossAccountRoleArn']
        super().__init__(SERVICE_NAME)
    
    def notify(self, eventResponse):
        print(f"[+]Saving event to backup event store")

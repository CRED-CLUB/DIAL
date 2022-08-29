#! /usr/bin/python3

import os
from dbAlertsclass import dbAlerts
from RootEC2EventHandler import handle_parent_ec2_event
from SecretsManagerEventHandler import SecretsManagerEventHandler
from SSMEventHandler import SSMEventHandler
from GDEventHandler import GDEventHandler
from IAMEventHandler import IAMEventHandler
from s3EventHandler import S3AccessAlerts
from utils import Utils,Configruation
from queue import Queue
from NotificationService import send_notifications

q = Queue()

def lambda_handler(event, context):

    profile = os.getenv('DIAL_PROFILE', 'default') 
    config = Configruation(profile)
    appConfig = config.appConfig
    utils = Utils(appConfig)
    event = event['detail']

    try:
        print('[+]Checking type of event: guard_duty or cloudtrail')
        if bool(event['eventVersion']):
            print('[+]Got cloudtrail event')
            eventSource = event['eventSource']
            aws_account = utils.user_type(event['userIdentity'])
            print(f"[+]Event Source: {eventSource}")
    
            if eventSource == 'ec2.amazonaws.com':
                response = handle_parent_ec2_event(event, aws_account, appConfig)
    
            elif eventSource == 'iam.amazonaws.com' or eventSource == "signin.amazonaws.com":
                event_handler = IAMEventHandler(appConfig)
                response = event_handler.handle_event(event, aws_account)
    
            elif eventSource == 'rds.amazonaws.com' or eventSource == "dynamodb.amazonaws.com":
                event_handler = dbAlerts(appConfig)
                response = event_handler.handle_event(event, aws_account)
    
            elif eventSource ==  's3.amazonaws.com':
                event_handler = S3AccessAlerts(appConfig)
                response = event_handler.handle_event(event, aws_account)
    
            elif eventSource == 'ssm.amazonaws.com':
                event_handler = SSMEventHandler(appConfig)
                response = event_handler.handle_event(event, aws_account)
    
            elif eventSource == 'secretsmanager.amazonaws.com':
                event_handler = SecretsManagerEventHandler(appConfig)
                response = event_handler.handle_event(event, aws_account)
    
            else:
                print(f'[+]Got eventsource: {eventSource}')
            
            response.eventTime = event['eventTime']
            send_notifications(appConfig, response)

    except KeyError as parent_exception:

        try:
            if bool(event['SchemaVersion']):
                print('[+]Got guard_duty event')
                event_handler = GDEventHandler(appConfig)
                response = event_handler.handle_event(event)
                send_notifications(appConfig, response)
        except Exception as child_exception:
            q.put(parent_exception)
            q.put(child_exception)

    except Exception as parent_exception:
        q.put(parent_exception)

    if q.qsize() > 0:
        print(f'[-]Unhandled exception occoured while processing request. error = {q}')
        for exception in q.queue:
            print(exception)
        #write_to_s3_bucket(event, q, "dial-security")

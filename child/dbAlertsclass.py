#! /usr/bin/python3

import json
import sys
from datetime import datetime
from utils import EventHandler, EventResponse


class dbAlerts(EventHandler):
    def __init__(self, appConfig):
        name = "DB"
        super().__init__(name, appConfig)
        self.severity_map = appConfig['Severity']['DB']
        
    def handle_event(self, event_data, aws_account):
        response = self.get_event_response(event_data, aws_account)
        print(f"[+]VPC Classifier Response: {response.get_response_dict()}")
        return response
    
    def get_event_response(self, event, aws_account):
        eventResponse = EventResponse('DB Event')
        eventResponse.userName = self.utils.username_fetch(event['userIdentity'])
        eventResponse.eventName = event["eventName"]
        eventResponse.eventId = event['eventID']
        eventResponse.userIp = event['sourceIPAddress']
        eventResponse.other_data['eventTime'] = event['eventTime']
        eventResponse.aws_region = event['awsRegion']
        eventResponse.location = self.utils.get_location(eventResponse.userIp)
        eventResponse.aws_account = aws_account
        request = event['requestParameters']
        if "dBClusterIdentifier" in request:
            dbName = request['dBClusterIdentifier']
        elif "dBInstanceIdentifier" in request:
            dbName = request['dBInstanceIdentifier']
        elif "tableName" in request:
            dbName = request['tableName']
        error = "errorMessage" in event
        eventResponse.error = error
        eventResponse.title, eventResponse.author_name = self.get_title_and_author_name(eventResponse, dbName, request, error)
        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
        print(eventResponse.severity)
        eventResponse.text = f"*Initiator:* {eventResponse.userName}\n*Database name:* {dbName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
        if "public" in eventResponse.title:
            eventResponse.text = f"*WARNING:* This instance was created with public access, please cross confirm this config.\n*Initiator:* {eventResponse.userName}\n*Database name:* {dbName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
            evenResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
        if "error" in eventResponse.title:
            eventResponse.text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
        return eventResponse
    
    def get_title_and_author_name(self, eventResponse, dbName, request, error=False):
        
        eventName = eventResponse.eventName 
        aws_account = eventResponse.aws_account
        
        if eventName == "DeleteDBInstance":
            author_name = f"RDS Instance deleted [{aws_account}]"
            title = f"RDS Instance deleted: [{dbName}]"
        
        elif eventName == "DeleteDBCluster":
            author_name = f"RDS Cluster deleted [{aws_account}]"
            title = f"RDS Cluster deleted: [{dbName}]"
        
        elif eventName == "DeleteTable":
            author_name = f"DynamoDB Table deleted [{aws_account}]"
            title = f"DynamoDB Table deleted: [{dbName}]"
        
        elif eventName == "CreateDBInstance":
            try:
                if request['publiclyAccessible'] == True:
                    author_name = f"RDS Instance created [{aws_account}]"
                    title = f"RDS Instance created with public access: [{dbName}]"
                    print(title, author_name)
                elif request['publiclyAccessible'] == False:
                    author_name = f"RDS Instance created [{aws_account}]"
                    title = f"RDS Instance created: [{dbName}]"
            except KeyError as em:
                print('[+]Did not find public access as true: {}'.format(em))
                author_name = f"RDS Instance created [{aws_account}]"
                title = f"RDS Instance created: [{dbName}]"
        
        elif eventName == "CreateDBCluster":
            print(f"[+]Processing event for message parsing: {eventName}")
            try:
                if request['publiclyAccessible'] == True:
                    author_name = f"RDS Cluster created [{aws_account}]"
                    title = f"RDS Cluster created with public access: [{dbName}]"
                elif request['publiclyAccessible'] == False:
                    author_name = f"RDS Cluster created [{aws_account}]"
                    title = f"RDS Cluster create: [{dbName}]"
            except KeyError as em:
                print('[+]Got keyerror while checking cluster: {}'.format(em))
                author_name = f"RDS Cluster created [{aws_account}]"
                title = f"RDS Cluster created: [{dbName}]"
        
        elif eventName == "CreateTable":
            print(f"[+]Processing event for message parsing: {eventName}")
            author_name = f"DynamoDB Table created [{aws_account}]"
            title = f"DynamoDB Table created: [{dbName}]"
        
        #Modify DB Instance
        elif eventName == "ModifyDBInstance":
            print(f"[+]Processing event for message parsing: {eventName}")
            try:
                if request['publiclyAccessible'] == True:
                    author_name = f"RDS Instance modified [{aws_account}]"
                    title = f"RDS Instance made public: [{dbName}]"
            except KeyError as em:
                print('[!]Something else was changed, hence skipping the invocation: {}'.format(em))
                eventResponse.skipped = True
        
        #Modify DB Cluster
        elif eventName == "ModifyDBCluster":
            print(f"[+]Processing event for message parsing: {eventName}")
            try:
                if request['publiclyAccessible'] == True:
                    author_name = f"RDS Cluster modified [{aws_account}]"
                    title = f"RDS Cluster made public: [{dbName}]"
            except KeyError as em:
                print('[!]Something else was changed in the cluster, hence skipping the invocation: {}'.format(em))
                eventResponse.skipped = True
                
        # Stop DB Instance 
        elif eventName == "StopDBInstance":
            print(f"[+]Processing event for message parsing: {eventName}")
            author_name = f"RDS Instance stopped [{aws_account}]"
            title = f"RDS Instance was stopped: [{dbName}]"
            
        # Stop DB Cluster
        elif eventName == "StopDBCluster":
            print(f"[+]Processing event for message parsing: {eventName}")
            author_name = f"RDS Cluster stopped [{aws_account}]"
            title = f"RDS Cluster was stopped: [{dbName}]"
            
        # Start DB Instance
        elif eventName == "StartDBInstance":
            print(f"[+]Processing event for message parsing: {eventName}")
            author_name = f"RDS Instance started [{aws_account}]"
            title = f"RDS Instance started: [{dbName}]"
        
        # Start DB Cluster
        elif eventName == "StartDBCluster":
            print(f"[+]Processing event for message parsing: {eventName}")
            author_name = f"RDS Cluster started [{aws_account}]"
            title = f"RDS Cluster started: [{dbName}]"
    
        # Reboot DB Instance
        elif eventName == "RebootDBInstance":
            print(f"[+]Processing event for message parsing: {eventName}")
            author_name = f"RDS Instance restarted [{aws_account}]"
            title = f"RDS Instance was restarted: [{dbName}]"

        elif error:  
            error_message = event['errorMessage']
            author_name = f"DB error [{aws_account}]"
            title = f"[{eventName}] - {error_message}"
        
        return title, author_name
    
    def get_event_severity(self, eventName, error=False, extras=False):
        if error:
            return self.severity_map[eventName]['Error']
        elif extras:
            print("checking extras now")
            print(self.severity_map[eventName]['Dangerous'])
            return self.severity_map[eventName]['Dangerous']
        return self.severity_map[eventName]['Default']

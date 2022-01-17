import json
import requests
import boto3
from datetime import datetime
import yaml
from yaml.scanner import ScannerError
import traceback
import os

DYNAMODB_OK_STATUS_CODE = 200 # successfully inserted event 
HIVE_OK_STATUS_CODE = 201 # successfully created new ticket for the event

def lambda_handler(event, context):
    try:
        auth_header_key = 'X-DIALv2-Master-auth'
        try:
            cfgText = open("config.yaml", 'r').read()
            appConfig = yaml.safe_load(cfgText)

        # return 500 if error occours while reading in config file
        except (FileNotFoundError, ScannerError) as er:
            responseText = {"Message": f"internal server error"}
            return generate_response_object(responseText, 500)
        
        # return 401 if auth header is missing
        if auth_header_key not in event['headers']:
            response_text = {"Message": f"missing authentication token"}
            return generate_response_object(response_text, 401)
        
        request_auth_header = event['headers'][auth_header_key]
        required_auth_header = appConfig['auth'][auth_header_key]
        
        if  request_auth_header != required_auth_header:
            response_text = {"Message": f"invalid authentication token"}
            return generate_response_object(response_text, 403)
        
        # for debugging ?
        print(f"[+]request body: {event['body']}")
        event_details = json.loads(event['body'])
        
        # always save event to dynamoDB table
        dynamo_status_code = save_event_to_dynamodb(event_details)
        send_to_hive= False

        # save to theHive only if configured to do so
        if 'hive' in appConfig and 'Enabled' in appConfig['hive'] and appConfig['hive']['Enabled'] == True:
            send_to_hive = True
            hive_status_code = send_event_to_hive(appConfig, event_details)
            print(f"[+] TheHive Response: {hive_status_code}")
        print(f"[+] DynamoDB Response: {dynamo_status_code}")

        if send_to_hive == True: # sending to hive is enabled
            if dynamo_status_code == DYNAMODB_OK_STATUS_CODE and hive_status_code == HIVE_OK_STATUS_CODE:
                print(f"[+]event sent to hive and stored in dynamodb")
                response_text = {"Message": "Ticket Raised"}
                return generate_response_object(response_text, 200)
            else:
                print(f"[+]one or more unexpected errors occoured while saving event")
                response_text = {"Message": "one or more errors occoured while processing request"}
                return generate_response_object(response_text, 202)

        else: # sending to hive is disabled
            if dynamo_status_code != DYNAMODB_OK_STATUS_CODE:
                print(f"[-]error storing event in dynamoDB table")
                print("[+]raw event:")
                print(event['body'])
                response_text = {"Message": "one or more errors occoured while processing request"}
                return generate_response_object(response_text, 500)
            
            if dynamo_status_code == DYNAMODB_OK_STATUS_CODE:
                print(f"[+]event stored in dynamodb")
                response_text = {"Message": "Event Data Stored"}
                return generate_response_object(response_text, 200)
        
    except Exception as e:
        print(f'[+]encountered an unhandled exception while processing request. error = {e}')
        traceback.print_tb(e.__traceback__)
        responseText = {"Message": f"internal server error"}
        return generate_response_object(responseText, 500)

def generate_response_object(responseText, status_code):
    print(f"Returning statusCode {status_code} with Message: {responseText['Message']}")
    responseObject = {}
    responseObject['statusCode'] = status_code
    responseObject['headers'] = {'Content-Type': 'application/json'}
    responseObject['body'] = json.dumps(responseText)
    return responseObject


def save_event_to_dynamodb(event_details):
    table_name = os.getenv('DYNAMODB_TABLE_NAME', 'dial-security-events')
    dynamodb_item = event_details.copy()
    dynamodb_item.update({'WriteTime': str(datetime.now().timestamp())})
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)
    print(f"[+]attempting to store event details in dynamodb table {table_name}")
    response = table.put_item(Item=dynamodb_item)
    print(f"[+]dynamoDb response http statusCode: {response['ResponseMetadata']['HTTPStatusCode']}")
    return response['ResponseMetadata']['HTTPStatusCode']
        

def send_event_to_hive(appConfig, event_details):
    severity = event_details['Severity']
    severity_num = 3
    # severity = tlp
    if severity.lower() == "low":
        severity_num = 1 
    elif severity.lower() == "medium":
        severity_num = 2
    elif severity.lower() == "high":
        severity_num = 3
    else:
        # unknown severity
        severity_num = 3
    
    hive_url = appConfig['hive']['Url']
    hive_api_key = appConfig['hive']['ApiKey']
    
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {hive_api_key}"}
    
    print(f"[+]attempting to send event details to hive at: {hive_url}")
    
    try:
        data = {
            "title": event_details['Title'],
            "description": f"""
            \nThe following are the details of the event. 
            \n* **Title:** **{event_details['Text']}** 
            \n* **Source IP:** **`{event_details['SourceIp']}`** 
            \n* **UserName:** **`{event_details['User']}`**
            \n* **Event Name:** **`{event_details['EventName']}`**
            \n* **Location:** **`{event_details['Location']}`** 
            \n* **{event_details['Desc']}** **`{event_details['User']}`** 
            """,
            "severity": severity_num,
            "tlp": severity_num, # same as severity
            "tags": [event_details['Group'], event_details['Environment']]
        }
        response = requests.post(hive_url, headers=headers, json=data, timeout=5)
        print(f'[*]hive response http statusCode: {response.status_code}')
        if response.status_code == 201:
            print(f'[+]ticket raised at hive')
        else:
            print(f'[+]error at hive: {response.text} ')
        return response.status_code

    except Exception as em:
        print(f'[+]exception at hive controller: {em}')
        return 500 # something went wrong
    
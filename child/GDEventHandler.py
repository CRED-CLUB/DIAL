from utils import EventHandler, Configruation, EventResponse
import unittest
import datetime
import re
import json

class GDEventHandler(EventHandler):
    def __init__(self, appConfig):
        self.name = 'GuardDuty Event Handler'
        super().__init__(self.name, appConfig)
        print("[*] GuardDuty Event Classifier loaded with required configuration")
    
    def handle_event(self, event_data):
        resp = EventResponse('GuardDuty Event')
        try:
            eventResponse = self.process_event(event_data, resp)
        except KeyError as e:
            print(f'[ERROR] KeyError while parsing guard duty event! \n{e}')
            raise e
        print(f"[*] GuardDuty Classifier response : {eventResponse.get_response_dict()}")
        return eventResponse

    def process_event(self, event, resp):
        severity_level, colour = self.get_severity_colour(event["severity"])
        resp.severity_level = severity_level
        resp.colour = colour
        resp.severity = severity_level
        resp.arn = event['arn']
        resp.eventName = "GuardDuty"
        resp.aws_account = self.utils.get_aws_account_name(self.aws_account_number(resp.arn))
        resp.other_data["last_seen"] = event["service"]["eventLastSeen"]
        resp.title = f"GuardDuty [{resp.aws_account}] - {event['title']} ({severity_level})"
        resp.other_data['description'] = event["description"]
        resp.eventId = event["id"]
        #resp.event_type = event["type"]
        resp.aws_resources = re.search(":(.*?)/", event['type']).group(1) # attacked resource
        resp.aws_region = event["region"]
        resp.other_data['action_graber'] = event['service']['action']
        resp.other_data['resource_graber'] = event['resource']
        
        print(f'[+]Event with {resp.severity} severity in aws account: {resp.aws_account}. AWS Resource attacked : {resp.aws_resources}')
        
        if resp.aws_resources == "S3":
            self.handle_s3_attack(event, resp)
        elif resp.aws_resources == "IAMUser":
            self.handle_iam_attack(event, resp)
        elif resp.aws_resources == "EC2":
            self.handle_ec2_attack(event, resp)
        
        return resp
    
    def handle_ec2_attack(self, event, resp):
        instance_type = ""
        instance_id = ""
        if "instanceDetails" in event["resource"]:
            instance_type = event["resource"]["instanceDetails"]["instanceType"]
            instance_id = event["resource"]["instanceDetails"]["instanceId"]
        else:
            instance_type = "N/A"
            instance_id = "N/A"

        final_text = instance_id + ", " + instance_type 
        
        resp.user_text = self.user_instance("EC2", final_text)
        resp.lastseen_text = "\n*Region:* " + resp.aws_region + "\n*EventLastSeen:* " + self.last_seen_func(resp.other_data["last_seen"])
        resp.bottom_text = "*GuardDuty EC2* Alerts| *"
        resp.actiontype = event["service"]["action"]
        resp.callaction, resp.outin, resp.otherip = self.callaction_func(resp.actiontype)
        
        remotedetails = ""
        if resp.callaction!="dnsRequestAction":
            if resp.callaction == "portProbeAction":
                remotedetails = event["service"]["action"][resp.callaction]['portProbeDetails'][0]['remoteIpDetails']
            else:
                remotedetails = event["service"]["action"][resp.callaction]["remoteIpDetails"]
            resp.userIp, resp.location = self.grab_ip(remotedetails)
        else:
            remotedetails = event["service"]["action"][resp.callaction]["domain"]
            resp.userIp = remotedetails
            resp.location = 'Unknown'
        resp.text = f"\n{resp.user_text}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location} {resp.lastseen_text}"

    def handle_iam_attack(self, event, resp):
        resp.other_data['access_key_details'] = event["resource"]["accessKeyDetails"]
        resp.other_data['principal_id'] = resp.other_data['access_key_details']["principalId"]
        resp.userName = resp.other_data['access_key_details']["userName"]

        if "@" in resp.other_data['principal_id']:
            resp.userName = re.search(":(.*)", resp.other_data['principal_id']).group(1)
        
        resp.user_text = self.user_instance("IAM", resp.userName)
        print(f'[+] User : {resp.userName} IAM Event ')
        resp.lastseen_text = "\n*Region:* " + resp.aws_region + "\n*EventLastSeen:* " + self.last_seen_func(resp.other_data["last_seen"])
        resp.bottom_text = "*GuardDuty IAM* Alerts| *"
        
        actiontype = event["service"]["action"]
        resp.callaction, resp.outin, resp.otherip = self.callaction_func(actiontype)

        remotedetails = ""
        if resp.callaction != "dnsRequestAction":
            remotedetails = event["service"]["action"][resp.callaction]["remoteIpDetails"]
            resp.userIp, resp.location = self.grab_ip(remotedetails)

        else:
            remotedetails = event["service"]["action"][resp.callaction]["domain"]
            resp.userIp = remotedetails
            resp.location = 'Unknown'
        resp.text = f"\n{resp.user_text}\n\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}\n {resp.lastseen_text}"
    
    def handle_s3_attack(self, event, resp):
        bucket_name = ""
        if "s3BucketDetails" in event["resource"]:
            bucket_name = event["resource"]["s3BucketDetails"][0]["name"]
        else:
            bucket_name = "Unavailable"
        
        resp.other_data['access_key_details'] = event["resource"]["accessKeyDetails"]
        resp.other_data['principal_id'] = event["resource"]["accessKeyDetails"]["principalId"]
        resp.userName = event["resource"]["accessKeyDetails"]["userName"]
        
        if "@" in resp.other_data['principal_id']:
            resp.userName = re.search(":(.*)", resp.other_data['principal_id']).group(1)

        print(f'[+] User: {resp.userName} , Bucket: {bucket_name}')
        resp.user_text = self.user_instance("s3", resp.userName)
        resp.lastseen_text = "S3 Bucket: " +  bucket_name + "\nRegion: " + resp.aws_region + "\nEventLastSeen: " + self.last_seen_func(resp.other_data["last_seen"])
        resp.bottom_text = "*GuardDuty S3* Alerts| *"

        resp.actiontype = event["service"]["action"]
        resp.callaction, resp.outin, resp.otherip = self.callaction_func(resp.actiontype)

        remotedetails = ""
        if resp.callaction != "dnsRequestAction":
            remotedetails = event["service"]["action"][resp.callaction]["remoteIpDetails"]
            resp.userIp, resp.location = self.grab_ip(remotedetails)

        else:
            remotedetails = event["service"]["action"][resp.callaction]["domain"]
            resp.userIp = remotedetails
            resp.location = 'Unknown'
        resp.text = f"\n{resp.user_text}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}\n{resp.lastseen_text}"
        
    @staticmethod
    def user_instance(event, variable):
        if event == "s3" or event == "IAM":
            return "\n*User: " + variable + "*"
        if variable == "N/A, N/A":
            variable = "Not Found"
        return "\n*Instance: " + variable + "*"
    
    @staticmethod
    def timestamp_func():
        return str(datetime.datetime.now(datetime.timezone.utc)).split('.')[0] + "GMT"

    @staticmethod
    def last_seen_func(lastseen):
        return str(lastseen.replace("T"," ").replace("Z","GMT"))

    @staticmethod
    def callaction_func(action):
        if action["actionType"] == "AWS_API_CALL":
            return "awsApiCallAction", "", ""
        elif action["actionType"] == "NETWORK_CONNECTION":
            if action["networkConnectionAction"]["connectionDirection"] == "OUTBOUND":
                if "localIpDetails" in action["networkConnectionAction"]:
                    if "ipAddressV4" in action["networkConnectionAction"]["localIpDetails"]:
                        if action["networkConnectionAction"]["localIpDetails"]["ipAddressV4"] is not None or action["networkConnectionAction"]["localIpDetails"]["ipAddressV4"] != "":
                            return "networkConnectionAction", "", "Source IP: *" + str(action["networkConnectionAction"]["localIpDetails"]["ipAddressV4"]) + "*" + " (Instance IP)"
            return "networkConnectionAction", "", ""
        elif action["actionType"] == "DNS_REQUEST":
            return "dnsRequestAction", "", ""
        else:
            return "portProbeAction", "", ""
    
    @staticmethod
    def grab_ip(remotedetails):
        ip = remotedetails["ipAddressV4"]
        city_temp = ""
        country_temp = ""
        if remotedetails["city"] is not None:
            if remotedetails["city"]["cityName"] is None or remotedetails["city"]["cityName"] == "":
                city_temp = "n/a, "
            else:
                city_temp = remotedetails["city"]["cityName"] + ", "
        else:
            city_temp = "n/a, "
        if remotedetails["country"] is not None:
            if remotedetails["country"]["countryName"] is None or remotedetails["country"]["countryName"] == "":
                country_temp = "n/a"
            else:
                country_temp = remotedetails["country"]["countryName"]
        else:
            country_temp = "n/a"
        if city_temp == "n/a, " and country_temp == "n/a":
            city_temp = "n/a"
            country_temp = ""
        elif city_temp == "n/a, " and country_temp != "n/a":
            city_temp = country_temp
            country_temp = "" 
        elif city_temp != "n/a, " and country_temp == "n/a":
            city_temp = city_temp[:-2]
            country_temp = ""
        return ip, str(city_temp + country_temp)
    
    def get_severity_colour(self, severity_number):
        s_level = ""
        color = ""
        if (float(severity_number) <= 3.9):
            s_level = "LOW"
            color = "#03a9f4"
        elif (4.0 <= float(severity_number) <= 6.9):
            s_level = "MEDIUM"
            color = "#ffae42"
        elif (7.0 <= float(severity_number) <= 8.9):
            s_level = "HIGH"
            color = "#9d1111"
        return s_level, color

    def aws_account_number(self, arn):
        aws_account_number = arn
        aws_account_number = aws_account_number.split("/")
        aws_account_number = aws_account_number[0]
        aws_account_number = aws_account_number.split(":")
        a = len(aws_account_number)
        print(aws_account_number[a-2])
        return aws_account_number[a-2]
        
class GDEventHandlerTest(unittest.TestCase):
    def test_load_default_application_config(self):
        conf = Configruation()
        GDEventHandler(conf.appConfig)

        
if __name__ == '__main__':
    unittest.main()
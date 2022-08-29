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
            print(eventResponse)
        except KeyError as e:
            print(f'[ERROR] KeyError while parsing guard duty event! \n{e}')
            raise e
        print(f"[*] GuardDuty Classifier response : {eventResponse.get_response_dict()}")
        return eventResponse

    def process_event(self, event, resp):
        severity_level, colour = self.get_severity_colour(event["Severity"])
        resp.severity_level = severity_level
        resp.colour = colour
        resp.severity = severity_level
        resp.arn = event['Arn']
        resp.eventName = "GuardDuty"
        resp.aws_account = self.utils.get_aws_account_name(self.aws_account_number(resp.arn))
        resp.other_data["last_seen"] = event["Service"]["EventLastSeen"]
        resp.author_name = f"GuardDuty Alert [{resp.aws_account}]"
        resp.title = f"GuardDuty [{resp.aws_account}] - {event['Title']} ({severity_level})"
        resp.other_data['description'] = event["Description"]
        resp.eventId = event["Id"]
        #resp.event_type = event["type"]
        resp.aws_resources = re.search(":(.*?)/", event['Type']).group(1) # attacked resource
        resp.aws_region = event["Region"]
        resp.other_data['action_graber'] = event['Service']['Action']
        resp.other_data['resource_graber'] = event['Resource']
        
        print(f'[+]Event with {resp.severity} severity in aws account: {resp.aws_account}. AWS Resource attacked : {resp.aws_resources}')
        
        if resp.aws_resources == "S3":
            print("s3, resource")
            self.handle_s3_attack(event, resp)
        elif resp.aws_resources == "IAMUser":
            self.handle_iam_attack(event, resp)
        elif resp.aws_resources == "EC2":
            self.handle_ec2_attack(event, resp)
        elif resp.aws_resources == "Kubernetes":
            print("K8s")
            print(resp.title)
            self.handle_k8_attack(event, resp)
        else:
            print(f"[+]Event Type on GD Rxd: {resp.aws_resources}")
            
        return resp
    
    def handle_ec2_attack(self, event, resp):
        instance_type = ""
        instance_id = ""
        if "instanceDetails" in event["Resource"]:
            instance_type = event["Resource"]["InstanceDetails"]["InstanceType"]
            instance_id = event["Resource"]["InstanceDetails"]["InstanceId"]
        else:
            instance_type = "N/A"
            instance_id = "N/A"

        final_text = instance_id + ", " + instance_type 
        
        resp.user_text = self.user_instance("EC2", final_text)
        resp.lastseen_text = "\n*Region:* " + resp.aws_region + "\n*EventLastSeen:* " + self.last_seen_func(resp.other_data["last_seen"])
        resp.bottom_text = "*GuardDuty EC2* Alerts| *"
        resp.actiontype = event["Service"]["Action"]
        resp.callaction, resp.outin, resp.otherip = self.callaction_func(resp.actiontype)
        
        remotedetails = ""
        if resp.callaction!="dnsRequestAction":
            if resp.callaction == "portProbeAction":
                remotedetails = event["Service"]["Action"][resp.callaction]['PortProbeDetails'][0]['RemoteIpDetails']
            else:
                remotedetails = event["Service"]["Action"][resp.callaction]["RemoteIpDetails"]
            resp.userIp, resp.location = self.grab_ip(remotedetails)
        else:
            remotedetails = event["Service"]["Action"][resp.callaction]["Domain"]
            resp.userIp = remotedetails
            resp.location = 'Unknown'
        resp.text = f"\n{resp.user_text}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location} {resp.lastseen_text}"

    def handle_iam_attack(self, event, resp):
        resp.other_data['access_key_details'] = event["Resource"]["AccessKeyDetails"]
        resp.other_data['principal_id'] = resp.other_data['access_key_details']["principalId"]
        resp.userName = resp.other_data['access_key_details']["userName"]

        if "@" in resp.other_data['principal_id']:
            resp.userName = re.search(":(.*)", resp.other_data['principal_id']).group(1)
        
        resp.user_text = self.user_instance("IAM", resp.userName)
        print(f'[+] User : {resp.userName} IAM Event ')
        resp.lastseen_text = "\n*Region:* " + resp.aws_region + "\n*EventLastSeen:* " + self.last_seen_func(resp.other_data["last_seen"])
        resp.bottom_text = "*GuardDuty IAM* Alerts| *"
        
        actiontype = event["Service"]["Action"]
        resp.callaction, resp.outin, resp.otherip = self.callaction_func(actiontype)

        remotedetails = ""
        if resp.callaction != "dnsRequestAction":
            remotedetails = event["Service"]["Action"][resp.callaction]["RemoteIpDetails"]
            resp.userIp, resp.location = self.grab_ip(remotedetails)

        else:
            remotedetails = event["Service"]["Action"][resp.callaction]["Domain"]
            resp.userIp = remotedetails
            resp.location = 'Unknown'
        resp.text = f"\n{resp.user_text}\n\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}\n {resp.lastseen_text}"
    
    def handle_s3_attack(self, event, resp):
        bucket_name = ""
        if "s3BucketDetails" in event["Resource"]:
            bucket_name = event["Resource"]["S3BucketDetails"][0]["Name"]
        else:
            bucket_name = "Unavailable"
        
        resp.other_data['access_key_details'] = event["Resource"]["AccessKeyDetails"]
        resp.other_data['principal_id'] = event["Resource"]["AccessKeyDetails"]["PrincipalId"]
        resp.userName = event["Resource"]["AccessKeyDetails"]["UserName"]
        
        if "@" in resp.other_data['principal_id']:
            resp.userName = re.search(":(.*)", resp.other_data['principal_id']).group(1)

        print(f'[+] User: {resp.userName} , Bucket: {bucket_name}')
        resp.user_text = self.user_instance("s3", resp.userName)
        resp.lastseen_text = "S3 Bucket: " +  bucket_name + "\nRegion: " + resp.aws_region + "\nEventLastSeen: " + self.last_seen_func(resp.other_data["last_seen"])
        resp.bottom_text = "*GuardDuty S3* Alerts| *"

        resp.actiontype = event["Service"]["Action"]
        resp.callaction, resp.outin, resp.otherip = self.callaction_func(resp.actiontype)

        remotedetails = ""
        if resp.callaction != "dnsRequestAction":
            remotedetails = event["Service"]["Action"][resp.callaction]["RemoteIpDetails"]
            resp.userIp, resp.location = self.grab_ip(remotedetails)

        else:
            remotedetails = event["Service"]["Action"][resp.callaction]["Domain"]
            resp.userIp = remotedetails
            resp.location = 'Unknown'
        resp.text = f"\n{resp.user_text}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}\n{resp.lastseen_text}"
        
    #K8 handler
    def handle_k8_attack(self, event, resp):
        cluster_details = resp.other_data['resource_graber']['EksClusterDetails']
        cluster_actions = resp.other_data['action_graber']
        cluster_name = cluster_details['Name']
        cluster_arn = cluster_details['Arn']
        cluster_vpc = cluster_details['VpcId']
        k8_details_fetch = self.k8_details(resp.other_data['resource_graber']['KubernetesDetails'], cluster_actions)
        resp.userIp = k8_details_fetch['ip']
        resp.location = k8_details_fetch['city']
        resp.user_text = f"*User:* {k8_details_fetch['username']}"
        resp.lastseen_text = f"*EKS Cluster:* {cluster_name}\n*Cluster ARN:* {cluster_arn}\n*EventLastSeen:* {self.last_seen_func(resp.other_data['last_seen'])}"
        resp.text = f"\n{resp.user_text}\n*Source IP:* {resp.userIp}\n*Location:* {resp.location}\n{resp.lastseen_text}"
        return resp
        
    def k8_details(self, k8_data, action_details):
        response = {}
        # K8 Details
        response['username'] = k8_data['KubernetesUserDetails']['Username']
        response['uid'] = k8_data['KubernetesUserDetails']['Uid']
        response['groups'] = k8_data['KubernetesUserDetails']['Groups']
        # K8 Actions
        action_type = action_details['ActionType']
        k8_call_action = action_details['KubernetesApiCallAction']
        response['request_uri'] = k8_call_action['RequestUri']
        response['http_method'] = k8_call_action['Verb']
        response['user_agent'] = k8_call_action['UserAgent']
        response['ip'], response['city'] = self.grab_ip(k8_call_action['RemoteIpDetails'])
        return response

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
        if action["ActionType"] == "AWS_API_CALL":
            return "awsApiCallAction", "", ""
        elif action["ActionType"] == "NETWORK_CONNECTION":
            if action["NetworkConnectionAction"]["ConnectionDirection"] == "OUTBOUND":
                if "localIpDetails" in action["NetworkConnectionAction"]:
                    if "ipAddressV4" in action["NetworkConnectionAction"]["LocalIpDetails"]:
                        if action["NetworkConnectionAction"]["LocalIpDetails"]["IpAddressV4"] is not None or action["NetworkConnectionAction"]["LocalIpDetails"]["IpAddressV4"] != "":
                            return "networkConnectionAction", "", "Source IP: *" + str(action["NetworkConnectionAction"]["LocalIpDetails"]["IpAddressV4"]) + "*" + " (Instance IP)"
            return "networkConnectionAction", "", ""
        elif action["ActionType"] == "DNS_REQUEST":
            return "dnsRequestAction", "", ""
        else:
            return "portProbeAction", "", ""
    
    @staticmethod
    def grab_ip(remotedetails):
        ip = remotedetails["IpAddressV4"]
        city_temp = ""
        country_temp = ""
        if remotedetails["City"] is not None:
            if remotedetails["City"]["CityName"] is None or remotedetails["City"]["CityName"] == "":
                city_temp = "n/a, "
            else:
                city_temp = remotedetails["City"]["CityName"] + ", "
        else:
            city_temp = "n/a, "
        if remotedetails["Country"] is not None:
            if remotedetails["Country"]["CountryName"] is None or remotedetails["Country"]["CountryName"] == "":
                country_temp = "n/a"
            else:
                country_temp = remotedetails["Country"]["CountryName"]
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

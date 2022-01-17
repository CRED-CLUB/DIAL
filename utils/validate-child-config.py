import yaml
import argparse
import logging

from yaml.error import YAMLError

logging.basicConfig(format='[+]%(levelname)8s - %(message)s')
logger = logging.getLogger('validator')

doc_links = {
    'Notifications': '',
    'Static-Config': '',
    'Severity-Config': '',
    'Selective-Severity-Config': ''
}

def verify_required_variables(vars, obj):
    all_okay = True
    not_found = []
    for var in vars:
        if var not in obj:
            not_found.append(var)
            all_okay = False
        elif obj[var] == None:
            not_found.append(var)
            all_okay = False
    return not_found, all_okay

class ProfileValidator:
    def __init__(self, profile_name, config):
        self.profile_name = profile_name
        self.config = config
        self.status = {
            'Notifications': False,
            'Static-Config': False,
            'Severity-Config': False,
            'Selective-Severity-Config': False
        }
        # keys for all services other than S3, IAM
        self.typical_required_severity_keys = {
            "EC2": [
                "RunInstances",
                "StopInstances",
                "TerminateInstances"
            ],
            "SecretsManager": [
                "GetSecretValue",
                "UpdateSecret",
                "DeleteSecret",
                "PutSecretValue"
            ],
            "SSM": [
                "GetParameter",
                "DeleteParameter",
                "PutParameter"
            ],
            "DB": [
                "DeleteDBInstance",
                "DeleteDBCluster",
                "DeleteTable",
                "CreateDBInstance",
                "CreateDBCluster",
                "CreateTable",
                "ModifyDBInstance",
                "ModifyDBCluster",
                "StopDBInstance",
                "StopDBCluster",
                "StartDBInstance",
                "StartDBCluster",
                "RebootDBInstance"
            ],
            "S3": [
                "PutObjectAcl",
                "PutObject",
                "DeleteBucket",
                "CreateBucket",
                "PutBucketPolicy",
                "PutBucketAcl"
            ],
            "VPC": [
                "CreateVPCPeeringConnection",
                "AcceptVPCPeeringConnection",
                "ModifyVpcPeeringConnectionOptions",
                "DeleteVpcPeeringConnection",
                "DeleteRouteTable",
                "CreateRouteTable",
                "AssociateRouteTable",
                "CreateRoute",
                "DeleteRoute",
                "DetachInternetGateway",
                "DeleteInternetGateway",
                "AttachInternetGateway",
                "CreateInternetGateway",
                "CreateVpc",
                "AssociateVpcCidrBlock",
                "DeleteVpc",
                "ModifyVpcAttribute"
            ],
            "SG": [
                "CreateSecurityGroup",
                "AuthorizeSecurityGroupIngress",
                "RevokeSecurityGroupIngress",
                "AuthorizeSecurityGroupEgress",
                "RevokeSecurityGroupEgress",
                "DeleteSecurityGroup"
            ],
            "IAM": [
                "High",
                "Medium"
            ]
        }
        self.typical_required_severity_values = ['Error', 'Default']
        self.apis_with_dangerous_mappings = [
            "CreateDBInstance",
            "CreateDBCluster",
            "ModifyDBInstance",
            "ModifyDBCluster",
            "StartDBCluster",
            "PutObjectAcl",
            "PutObject",
            "DeleteBucket",
            "CreateBucket",
            "PutBucketPolicy",
            "PutBucketAcl",
            "AuthorizeSecurityGroupIngress"
        ]
        self.vpc_external_apis = [
            "CreateVPCPeeringConnection",
            "AcceptVPCPeeringConnection",
            "ModifyVpcPeeringConnectionOptions",
            "AssociateRouteTable"
        ]
    def verify_notification_services(self, notification_services_definition):
        if notification_services_definition == None:
            logger.error(f"No Notification Services defined. DIAL needs one or more services to be notified after event is processed")
            return False
        enabled = []

        if 'Console' in notification_services_definition and notification_services_definition['Console']['Enabled'] == True:
            logger.debug('Console logging is enabled')
            enabled.append('Console')

        if 'Slack' in notification_services_definition and notification_services_definition['Slack']['Enabled'] == True:
            needed_and_not_null = ['Hook']
            not_found, ok = verify_required_variables(needed_and_not_null, notification_services_definition['Slack'])
            if ok:
                logger.debug('Slack is configured with required parameters')
                enabled.append('Slack')
            else:
                logger.warning(f'[{self.profile_name}] Slack is enabled but missing required parameters: {not_found}')
        
        if 'DIAL' in notification_services_definition and notification_services_definition['DIAL']['Enabled'] == True:
            needed_and_not_null = ['Master-URL']
            not_found, ok = verify_required_variables(needed_and_not_null, notification_services_definition['DIAL'])
            if ok:
                logger.debug('DIAL is configured with required parameters')
                enabled.append('DIAL')
            else:
                logger.warning(f"[{self.profile_name}] DIAL Master Notification Service is enabled but missing required parameters: {not_found}")
        
        if len(enabled) > 0:
            logger.info(f"[{self.profile_name}] - Notification Services found {len(enabled)} services enabled and configured: {', '.join(enabled)}")
            self.status['Notifications'] = True
            return True
        else:
            logger.error(f"[{self.profile_name}]Notification Servies are defined but not enabled.")
            return False
    
    def verify_static_config(self, static_config):
        required_vars = ['Enrichment-URL', 'Account-Id-Map', 'EC2', 'S3']
        not_found, ok = verify_required_variables(required_vars, static_config)
        if ok:
            logger.info(f'[{self.profile_name}] - Static config Level-1 has required parameters')
            self.status['Static-Config'] = True
            return True
        else:
            logger.error(f"[{self.profile_name}] Static config is missing reqiuired parameters: {not_found}")
            return False

    def verify_severity_config(self, severity_config):
        self.status['Severity-Config'] = True
        for service in self.typical_required_severity_keys:
            if service not in severity_config or severity_config[service] == None:
                # warning as EventBridge might be configured not be send the api events for required service
                logger.warning(f'[{self.profile_name}] - Severity - [{service}] events are not defined / are empty.')
                self.status['Selective-Severity-Config'] = True
                continue
            required_apis = self.typical_required_severity_keys[service]
            service_ok = True
            for api in required_apis:
                if api not in severity_config[service]:
                    # warning as EventBridge might be configured not be send the sepcific api events
                    logger.warning(f'[{self.profile_name}] - Severity - [{service}] - [{api}] event not found')
                    self.status['Selective-Severity-Config'] = True
                else:
                    # custom keys used by sources and apis
                    required_values = self.typical_required_severity_values.copy()

                    if api == 'RunInstances' or api == 'TerminateInstances':
                        required_values += ['SingleInstance', 'MultipleInstances']

                    elif api == 'StopInstances':
                        required_values += ['Stopped']

                    elif service == "VPC":
                        required_values = ['Internal', 'Default', 'Error']
                        if api in self.vpc_external_apis:
                            required_values += ['External']

                    elif service == "IAM":
                        required_values = ['Author-Name', 'Event-Name']
                    
                    if api in self.apis_with_dangerous_mappings:
                        required_values += ['Dangerous']

                    not_found, ok = verify_required_variables(required_values, severity_config[service][api])
                    
                    if not ok:
                        # error because if API Event reaches DIAL but 'Default' or 'Error' or required value is not defined then DIAL might crash
                        logger.error(f'[{self.profile_name}] - Severity - [{service}] - [{api}] Missing Parameter: {not_found}')
                        self.status['Severity-Config'] = False
                        service_ok = False
                    
                    else:
                        logger.debug(f'[{self.profile_name}] - Severity - [{service}] - [{api}] configuration appears valid')
            
            # all okay for the given service
            if service_ok:
                logger.debug(f'[{self.profile_name}] - Severity - [{service}] appears valid')
            else:
                logger.warning(f'[{self.profile_name}] - Severity - [{service}] missing required parameters')
                    
        if self.status['Severity-Config']:
            logger.info(f'[{self.profile_name}] - Severity configuration appears valid')
        else:
            logger.critical(f'[{self.profile_name}] - Severity configuration missing required configuration parameters')

        return self.status['Severity-Config']
        

    def verify_profile(self):
        all_ok = True
        logger.debug(f"Verifying Notification Configuration")
        ok = self.verify_notification_services(self.config['Notifications'])
        if not ok:
            logger.error(f"Notification Services Documentation: {doc_links['Notifications']}")
            all_ok = False
        
        logger.debug(f"Verifying Static Config")
        ok = self.verify_static_config(self.config['Static'])
        if not ok:
            logger.error(f"Static Configuration Documentation: {doc_links['Static-Config']}")
            all_ok = False

        logger.debug(f"Verifying Severity Config")
        ok = self.verify_severity_config(self.config['Severity'])
        if not ok:
            logger.error(f"Severity Configuration Documentation: {doc_links['Severity-Config']}")
            all_ok = False
        
        if all_ok:
            logger.info(f"[{self.profile_name}] appears valid")

        else:
            if not self.status['Notifications']:
                logger.error(f"[{self.profile_name}] [ Notification Service ] appears to be missing configuration")

            if not self.status['Static-Config']:
                logger.error(f"[{self.profile_name}] [ Static Config ] appears to be missing configuration")
            
            if not self.status['Severity-Config']:
                logger.error(f"[{self.profile_name}] [ Severity Config ] appears to be missing configuration")

        if self.status['Selective-Severity-Config']:
            logger.info(f'[{self.profile_name}] appears to be having custom event sources / APIs configured. [ Event Bridge would need tweaking ]')
            logger.info(f'[{self.profile_name}] severity configuration is "selective" (Event Sources / APIs are missing from configuration)')
            logger.info(f'Selective EventSource/API Configuration Documentation: {doc_links["Selective-Severity-Config"]}')
        
        return all_ok
        

def verify_config(config, profile_to_scan = "ALL"):
    profiles = config.keys()
    logger.info(f"Config has the following profiles defined: { ', '.join(profiles) }")
    profiles_to_scan = []
    if profile_to_scan == "ALL":
        logger.debug(f"Scanning ALL profiles")
        profiles_to_scan = profiles
    else:
        logger.debug(f"Scanning profile '{profile_to_scan}' ")
        if profile_to_scan not in profiles:
            logger.error(f"Profile '{profile_to_scan}' not found in config.")
        else:
            logger.debug(f"Profile definition for '{profile_to_scan}' found, scanning..")
            profiles_to_scan = [profile_to_scan]

    for profile in profiles_to_scan:
        logger.info(f"Verifying Profile '{profile}' ")
        validator = ProfileValidator(profile, config[profile])
        validator.verify_profile()

def main():
    parser = argparse.ArgumentParser(description="Configuration Verification script for DIALv2")
    parser.add_argument("config", default="config.yml", help="config file to be verified")
    parser.add_argument("--profile", default="ALL", help="specific profile to be verified (default: ALL Profiles)")
    parser.add_argument("--debug", default=False, action="store_true", help="print debug logs")
    args = parser.parse_args()
    config_file = args.config
    profile = args.profile

    logger.setLevel(logging.INFO)
    if args.debug:
        logger.setLevel(logging.DEBUG)

    logger.info(f"Attempting to load config file '{config_file}' ")
    try:
        with open(config_file, "r") as input_file:
            logger.debug("Opened config file")
            config = yaml.safe_load(input_file)
            logger.debug("YAML load finished. config is NOT MALFORMED")
            verify_config(config, profile)

    except FileNotFoundError as e:
        logger.error(f"Config file not found. error = {e}")
    except YAMLError as e:
        logger.error(f"Config file has malformed YAML. error = {e}")
    except Exception as e:
        logger.error(f"Unknown exception occoured while verifying config file. error = {e}")

if __name__ == "__main__":
    main()
    
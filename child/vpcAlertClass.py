#! /usr/bin/python3

from utils import EventHandler, EventResponse

class vpcEventHandler(EventHandler):
    def __init__(self, appConfig):
        name = "VPC"
        super().__init__(name, appConfig)
        self.severity_map = appConfig['Severity']['VPC']
        self.accountID = list(appConfig['Static']['Account-Id-Map'].values())
        
    def handle_event(self, event_data, aws_account):
        response = self.get_event_response(event_data, aws_account)
        print(f"[+]VPC Classifier Response: {response.get_response_dict()}")
        return response
    
    def get_event_response(self, event, aws_account):
        eventResponse = EventResponse('VPC Event')
        eventResponse.eventId = event['eventID']
        eventResponse.userName = self.utils.username_fetch(event['userIdentity'])
        eventResponse.eventName = event["eventName"]
        eventResponse.userIp = event['sourceIPAddress']
        eventResponse.other_data['eventTime'] = event['eventTime']
        eventResponse.aws_region = event['awsRegion']
        eventResponse.location = self.utils.get_location(eventResponse.userIp)
        eventResponse.aws_account = aws_account
        error = "errorMessage" in event
        eventResponse.error = error
        if error:
            error_message = event['errorMessage']
            eventResponse.author_name = f"VPC Error [{eventResponse.aws_account}]"
            eventResponse.title = f"[{eventResponse.eventName}] - {error_message}"
            eventResponse.text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
            eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            return eventResponse
            
        ##########################################
        ########## VPC Peering Alerts ############
        ##########################################
        
        if ("VpcPeeringConnection" in eventResponse.eventName) and (eventResponse.eventName != "DeleteVpcPeeringConnection"):
            peerConnectionID = event['responseElements']['vpcPeeringConnection']['vpcPeeringConnectionId']
            requester_vpc_account = event['responseElements']['vpcPeeringConnection']['requesterVpcInfo']['ownerId']
            acceptor_vpc_account = event['responseElements']['vpcPeeringConnection']['accepterVpcInfo']['ownerId']
            aws_account_acceptor = self.utils.get_aws_account_name(acceptor_vpc_account)
            aws_account_requester = self.utils.get_aws_account_name(requester_vpc_account)
            try:
                requester_peering_options = event['responseElements']['vpcPeeringConnection']['requesterVpcInfo']['peeringOptions']
            except KeyError:
                requester_peering_options = None
            
            #CreateVPCPeeringConnection
            if "Create" in eventResponse.eventName:
                requester_vpc = event['requestParameters']['vpcId']
                acceptor_vpc = event['requestParameters']['peerVpcId']
                if acceptor_vpc_account in self.accountID:
                    eventResponse.author_name = f'VPC Peering initiated [{aws_account_requester}]'
                    eventResponse.text = f"*Requester VPC:* `{requester_vpc}`\n*Acceptor VPC:* `{acceptor_vpc}`\n*Peering Options:* ```\n{requester_peering_options}\n```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    eventResponse.title = f"VPC Peer Connection [{peerConnectionID}] initiated between: {aws_account_requester} -> {aws_account_acceptor}"
                    eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
                else:
                    eventResponse.author_name = f'VPC Peering initiated outside Company\'s infrastructure [{aws_account_requester}]'
                    eventResponse.title = f"VPC Peer Connection [{peerConnectionID}] initiated between: {aws_account_requester} -> {acceptor_vpc_account}"
                    eventResponse.text = f"*Requester VPC:* `{requester_vpc}`\n*Acceptor VPC:* `{acceptor_vpc} (Outside Company's Infrastructure)`\n*Peering Options:* ```\n{requester_peering_options}\n```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
            
            #AcceptVPCPeeringConnection
            elif "Accept" in eventResponse.eventName:
                requester_vpc = event['responseElements']['vpcPeeringConnection']['requesterVpcInfo']['vpcId']
                acceptor_vpc = event['responseElements']['vpcPeeringConnection']['accepterVpcInfo']['vpcId']
                if requester_vpc_account in self.accountID:
                    eventResponse.author_name = f"VPC Peering created [{aws_account_acceptor}]"
                    eventResponse.text = f"*Requester VPC:* `{requester_vpc}`\n*Acceptor VPC:* `{acceptor_vpc}`\n*Peering Options:* ```\n{requester_peering_options}\n```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    eventResponse.title = f"VPC Peer Connection [{peerConnectionID}] created between: {aws_account_requester} -> {aws_account_acceptor}"
                    eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
                else:
                    eventResponse.author_name = f'VPC Peering created outside Company\'s infrastructure [{aws_account_acceptor}]'
                    eventResponse.title = f"VPC Peer Connection [{peerConnectionID}] created between: {requester_vpc_account} -> {aws_account_acceptor}"
                    eventResponse.text = f"*Requester VPC:* `{requester_vpc} (Outside Company's Infrastructure)`\n*Acceptor VPC:* `{acceptor_vpc}`\n*Peering Options:* ```{requester_peering_options}```\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
            else:
                pass

        elif eventResponse.eventName == "ModifyVpcPeeringConnectionOptions":
            peerConnectionID = event['responseElements']['vpcPeeringConnection']['vpcPeeringConnectionId']
            requestParameters = event['requestParameters']['ModifyVpcPeeringConnectionOptionsRequest']
            answer = self.utils.get_modifyvpc_details(requestParameters)

            if answer is not None:
                eventResponse.author_name = f"VPC Peering Connection Modified [{eventResponse.aws_account}]"
                eventResponse.title = f"VPC Peering Connection modified"
                eventResponse.text = f"*Peer Connection ID:* {peerConnectionID}\n*Modified Options:* ```\n{answer}\n```\n*Inititator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            else:
                eventResponse.author_name = f"VPC Peering Connection Modified [{eventResponse.aws_account}]"
                eventResponse.title = f"VPC Peering Connection modified"
                eventResponse.text = f"*Peer Connection ID:* {peerConnectionID}\n*Modified Options:* ```\n{requestParameters}\n```\n*Inititator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
                
        elif eventResponse.eventName == "DeleteVpcPeeringConnection":
            peerConnectionID = event['responseElements']['vpcPeeringConnection']['vpcPeeringConnectionId']
            eventResponse.author_name = f"VPC Peering Connection deleted [{eventResponse.aws_account}]"
            eventResponse.title = f'VPC Peering connection was deleted: {peerConnectionID}'
            eventResponse.text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
            eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
        
        ##########################################
        ########## Route Table Alerts ############
        ##########################################

        elif "RouteTable" in eventResponse.eventName:
            if "Delete" in eventResponse.eventName:
                routeTableID = event['requestParameters']['routeTableId']
                eventResponse.author_name = f"Route Table deleted [{eventResponse.aws_account}]"
                eventResponse.title = f"Route Table deleted: {routeTableID}"
                eventResponse.text = f"*Route TableID:* {routeTableID}\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            
            elif "Create" in eventResponse.eventName:
                requester_vpc = event['requestParameters']['vpcId']
                vpcName = self.utils.vpc_name(requester_vpc)
                eventResponse.author_name = f"Route Table created [{eventResponse.aws_account}]"
                eventResponse.title = f"Route table created on vpc [{requester_vpc}]: {vpcName}"
                eventResponse.text = f"*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            
            elif "Associate" in eventResponse.eventName:
                routeTableID = event['requestParameters']['routeTableId']
                subnetId = event['requestParameters']['subnetId']
                print(routeTableID, subnetId)
                access = self.utils.check_route_access(routeTableID)
                print(access + " access value")
                if access is not None:
                    eventResponse.author_name = f"Subnet associated with route table [{eventResponse.aws_account}]"
                    eventResponse.title = f"Subnet Associated with public route table"
                    eventResponse.text = f"*Subnet-ID:* {subnetId}\*Public Resource:* `{access}`\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    eventResponse.severity = self.get_event_severity(eventResponse.eventName, error, True)
                else:
                    eventResponse.author_name = f'Route Table associated [{eventResponse.aws_account}]'
                    eventResponse.title = f"Subnet associated with route table: {routeTableID}"
                    eventResponse.text = f"*SubnetID:* `{subnetId}`\n*RouteTableId:* `{routeTableID}`\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
        
        elif ("Route" in eventResponse.eventName) and ("RouteTable" not in eventResponse.eventName):
            routeTableID = event['requestParameters']['routeTableId']
            destinationCIDR = event['requestParameters']['destinationCidrBlock']
            eventRequest = event['requestParameters']
            answer = self.utils.create_route_runner(eventRequest)
            
            # CreateRoute
            if "Create" in eventResponse.eventName:
                if answer is not None:
                    for key in answer:
                        if key == "gatewayId":
                            gatewayId = answer[key]
                            eventResponse.author_name = f"Route created [{eventResponse.aws_account}]"
                            eventResponse.title = f"Route created on route table: {routeTableID}"
                            eventResponse.text = f"*GatewayID:* `{gatewayId}`\n*CIDR Block:* `{destinationCIDR}` \n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                            eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
                        elif key == "vpcPeeringConnectionId":
                            vpcPeeringConnectionId= answer[key]
                            eventResponse.author_name = f'Route created [{eventResponse.aws_account}]'
                            eventResponse.title = f"Route created for peer connection: {routeTableID}"
                            eventResponse.text = f"*VPC Peer Connection ID:* `{vpcPeeringConnectionId}`\n*CIDR Block:* `{destinationCIDR}` \n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                            eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
                else:
                    eventResponse.author_name = f'Route created [{eventResponse.aws_account}]'
                    eventResponse.title = f"Route created on route table: {routeTableID}"
                    eventResponse.text = f"*GatewayID:* ```\n{eventRequest}\n``` \n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            
            # DeleteRoute
            elif "Delete" in eventResponse.eventName:
                eventResponse.author_name = f"Route deleted [{eventResponse.aws_account}]"
                eventResponse.title = f"Route deleted from {routeTableID}"
                eventResponse.text = f"*Route TableID:* `{routeTableID}`\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)

        ###############################################
        ########## Internet Gateway Alerts ############
        ###############################################

        elif "InternetGateway" in eventResponse.eventName:
            if eventResponse.eventName == "DetachInternetGateway":
                igwID = event['requestParameters']['internetGatewayId']
                vpcID = event['requestParameters']['vpcId']
                eventResponse.author_name = f"Internet Gateway Detached [{eventResponse.aws_account}]"
                eventResponse.title = f"Internet Gateway was detached from {vpcID}"
                eventResponse.text = f"*IGW VPC:* `{vpcID}`\n*IGW ID:* `{igwID}`\n*Inititator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            elif eventResponse.eventName == "DeleteInternetGateway":
                igwID = event['requestParameters']['internetGatewayId']
                eventResponse.author_name = f"Internet Gateway deleted [{eventResponse.aws_account}]"
                eventResponse.title = f"Internet Gateway was deleted {igwID}"
                eventResponse.text = f"*Inititator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            elif eventResponse.eventName == "AttachInternetGateway":
                igwID = event['requestParameters']['internetGatewayId']
                vpcID = event['requestParameters']['vpcId']
                eventResponse.author_name = f"Internet Gateway Attached [{eventResponse.aws_account}]"
                eventResponse.title = f"Internet Gateway was attached to {vpcID}"
                eventResponse.text = f"*IGW VPC:* `{vpcID}`\n*IGW ID:* `{igwID}`\n*Inititator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            elif eventResponse.eventName == "CreateInternetGateway":
                igwID = event['responseElements']['internetGateway']['internetGatewayId']
                eventResponse.author_name = f"Internet Gateway Created [{eventResponse.aws_account}]"
                eventResponse.title = f"Internet Gateway was created: {igwID}"
                eventResponse.text = f"*IGW ID:* `{igwID}`\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
        
        ###############################################
        ################ VPC Alerts ###################
        ###############################################

        elif ("CreateVpc" in eventResponse.eventName) or ("AssociateVpcCidrBlock" in eventResponse.eventName):
            #CreateVPC
            if eventResponse.eventName == "CreateVpc":
                vpcID = event['responseElements']['vpc']['vpcId']
                cidr = event['responseElements']['vpc']['cidrBlock']
                try:
                    tagSet = bool(event['responseElements']['vpc']['tagSet'])
                    if tagSet:
                        tagset_items = event['responseElements']['vpc']['tagSet']['items']
                        vpcName = self.utils.get_tagSet_name(tagset_items)
                        eventResponse.author_name = f"VPC created [{eventResponse.aws_account}]"
                        eventResponse.title = f"VPC was created: {vpcName}"
                        eventResponse.text = f"*VPC-Name:* `{vpcName}`\n*VPC-ID:* `{vpcID}`\n*VPC-CIDR:* `{cidr}`\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
                    else:
                        eventResponse.author_name =  f"VPC created [{eventResponse.aws_account}]"
                        eventResponse.title = f"VPC was created: {vpcID}"
                        eventResponse.text = f"*VPC-ID:* `{vpcID}`\n*VPC-CIDR:* `{cidr}`\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                        eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
                except KeyError:
                    eventResponse.author_name =  f"VPC created [{eventResponse.aws_account}]"
                    eventResponse.title = f"VPC was created: {vpcID}"
                    eventResponse.text = f"*VPC-ID:* `{vpcID}`\n*VPC-CIDR:* `{cidr}`\n*Initiator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            
            #AssociateVpcCidrBlock
            elif eventResponse.eventName == "AssociateVpcCidrBlock":
                cidr = event['responseElements']['AssociateVpcCidrBlockResponse']['cidrBlockAssociation']['cidrBlock']
                vpcID = event['responseElements']['AssociateVpcCidrBlockResponse']['vpcId']
                vpcName = self.utils.vpc_name(vpcID)
                eventResponse.author_name = f"CIDR Block assoicated with VPC [{eventResponse.aws_account}]"
                eventResponse.title = f"CIDR Block associated with {vpcName}"
                eventResponse.text = f"*VPC-Name:* `{vpcName}`\n*VPC-ID:* `{vpcID}`\n*Inititator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
        
        #DeleteVPC
        elif eventResponse.eventName == "DeleteVpc":
            vpcID = event['requestParameters']['vpcId']
            eventResponse.author_name = f"VPC deleted [{eventResponse.aws_account}]"
            eventResponse.title = f"VPC was deleted {vpcID}"
            eventResponse.text = f"*VPC ID:* `{vpcID}`\n*Inititator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
            eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
        
        #ModifyVpcAttribute
        elif eventResponse.eventName == "ModifyVpcAttribute":
            vpcID = event['requestParameters']['vpcId']
            vpcName = self.utils.vpc_name(vpcID)
            try:
                dns = event['requestParameters']['enableDnsSupport']['value']
                if dns:
                    eventResponse.author_name = f"VPC Attribute modified [{eventResponse.aws_account}]"
                    eventResponse.title = f"DNS Support added to {vpcName}"
                    eventResponse.text = f"*VPC-Name:* `{vpcName}`\n*VPC-ID:* `{vpcID}`\n*Inititator:* {eventResponse.usernName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
                else:
                    eventResponse.author_name = f"VPC Attribute modified [{eventResponse.aws_account}]"
                    eventResponse.title = f"DNS Support removed from {vpcName}"
                    eventResponse.text = f"*VPC-Name:* `{vpcName}`\n*VPC-ID:* `{vpcID}`\n*Inititator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            except KeyError:
                hostname = event['requestParameters']['enableDnsHostnames']['value']
                if hostname:
                    eventResponse.author_name = f"VPC Attribute modified [{eventResponse.aws_account}]"
                    eventResponse.title = f"DNS Hostname resolution added to {vpcName}"
                    eventResponse.text = f"*VPC-Name:* `{vpcName}`\n*VPC-ID:* `{vpcID}`\n*Inititator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
                else:
                    eventResponse.author_name = f"VPC Attribute modified [{eventResponse.aws_account}]"
                    eventResponse.title = f"DNS Hostname resolution removed from {vpcName}"
                    eventResponse.text = f"*VPC-Name:* `{vpcName}`\n*VPC-ID:* `{vpcID}`\n*Inititator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                    eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
            except:
                requestParams = event['requestParameters']
                eventResponse.author_name = f"VPC Attribute modified [{eventResponse.aws_account}]"
                eventResponse.title = f"Something was modified on {vpcName}"
                eventResponse.text = f"*VPC-Name:* `{vpcName}`\n*VPC-ID:* `{vpcID}`\n*Request Dump:* ```\n{requestParams}\n```\n*Inititator:* {eventResponse.userName}\n*Source IP:* {eventResponse.userIp}\n*Location:* {eventResponse.location}"
                eventResponse.severity = self.get_event_severity(eventResponse.eventName, error)
        return eventResponse
    
    def get_event_severity(self, eventName, error=False, external=False):
        if external:
            return self.severity_map[eventName]['External']
        elif error:
            return self.severity_map[eventName]['Error']
        elif error == True and external == True:
            return self.severity_map[eventName]['Error']
        return self.severity_map[eventName]['Internal']
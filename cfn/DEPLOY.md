
# Deployment



## Step-1: Packaging Parent Controller
- Create a private S3 bucket.
- If you have a theHive instance running just update the [master/config.yaml](../master/config.yaml) with `hive.Enabled: True` along with `hive.Url` and `hive.apiKey`, if you choose not to go with theHive deployment just keep the `hive.Enabled: False`.
	```yaml
	hive:
  		Enabled: true
  		Url: <theHiveInstance>/api/case
  		ApiKey: <apiKey>
	```
	
- Generate a random authentication token (ex. `openssl rand 16 | sha256sum`) and update value of `auth.X-DIALv2-Master-auth` Key in the `master/config.yaml` file.
	```yaml
	auth:
  		X-DIALv2-Master-auth: <authenticationToken> 
	```
	
- Use the Makefile to create a package for the lambda layer and the parent lambda


	```bash
	make layer
	make master_package
	```


- This would create `layer.zip` and `master.zip` packages in deployment folder. 
- These packages need to be copied to an s3 bucket in the same account as parent lambda (find example cloudformation for that in [S3 Bucket Cloudformation Example](s3-buckets.yaml)).

	```bash
	aws s3 cp deployment/master.zip s3://<s3-bucket-name>/master.zip
	aws s3 cp deployment/layer.zip s3://<s3-bucket-name>/layer.zip
	```
<br>

## Step-2: Deploying Parent Controller 

- AWS Console
	- Go to AWS Cloudformation, Create Stack, Upload the `cfn/master-deployment-stack.yaml` file as the template.
	- Update the required paramters `s3 bucket: The one you uploaded master.zip on`
	- Create the stack
	- After stack is deployed, get the api gateway URL from the output section. (this will be used in configuring child lambda)
	- Please make sure to save **api gateway URL** as this will be used by child controller to send request to and **X-DIALv2-Master-auth** as this will be the token through which your api gateway will authenticate the incoming requests from all the child controllers.  

- AWS CLI [optional]
	- Refer awscli documentation for passing in parameter-overrides [awscli cloudformation deploy](https://docs.aws.amazon.com/cli/latest/reference/cloudformation/deploy/)
	
		```bash
		aws cloudformation deploy --template-file master-deployment-stack.yaml --stack-name 'DIALv2-Master' --capabilities 'CAPABILITY_NAMED_IAM' 
		```
	
	- Get API Gateway URL from the above stack output
	
		```bash
		aws cloudformation describe-stacks --stack-name 'DIALv2-Master' --query "Stacks[0].Outputs[?OutputKey=='DIALv2MasterApiGatewayURL'].OutputValue" --output text
		```

## Step-3: Attaching Parent controller to VPC [optional]

Skip this step if you have set `hive.Enabled: False` in master/config.yaml

- If you have deployed theHive project and want the lambda to send data to theHive webdashboard, please follow the following steps to attach the lambda to a VPC and Subnet where theHive instance is present.
	- By default the parent controller's execution role has `AWSLambdaVPCAccessExecutionRole` policy attached, which will give parent controller's lambda access to be attached to a VPC.
	- Open AWS lambda console, navigate to Parent controller lambda and open `Configurations` tab.
	- Go to `VPC` tab, and select **Edit** by default we do not attach this lambda to VPC.
	- Select the VPC and subnet of theHive instance, what this will do is that it will attach Parent controller lambda to the same subnet as where theHive instance is running.
	- Edit `inbound rules` on your theHive instance's security-group to accept traffic from the subnet and port where the lambda is attached and theHive is running respectively, for e.g `172.21.0.0/24: 9000`.
	- Once done, your Parent controller lambda will be able to send data to your private theHive instance.
<br>

## Step-4: Packaging Child Controller
- Create a private S3 bucket.
- Update the child controller config file [child/config.yaml](../child/config.yaml) file, please make sure to update the values of `Notifications.DIAL.Master-URL: <apiGatewayURL>/Prod/DIALv2` & `Notifications.DIAL.X-DIALv2-Master-auth: <authenticationToken>` with the values saved earlier from Parent Controller deployment. 
	```yaml
	DIAL:
      Enabled: true 
      Master-URL: https://<apiGatewayURL>/Prod/DIALv2
      X-DIALv2-Master-auth: <authenticationToken>
	```
- Update the `Notifications.Slack.Hook` field with your desired Slack Webhook URL.
- Update the `Static.Account-Id-Map` with the names and account IDs of your AWS accounts that you own, for example
	
	```yaml
	Static: &defaultStaticMap
		Enrichment-URL: https://ipinfo.io/ 
		Account-Id-Map: &defaultStaticAccount-Id-Map
		  PROD: '123412341234'
		  STAGE: '098709870987'
		  PCI: '123412341234'
		  PROD-UAT: '123412341234'
	```
	
- Update any severity that you wish to change according to your needs under `Severity` section in the **config.yaml** file, for example, if you dont wish to change, the deployment will fallback to the default severity that we have configured.

	```yaml
	Severity:
		EC2: &defaultSeverityMapEC2
		  RunInstances:
			Error: LOW
			SingleInstance: LOW
			MultipleInstances: LOW
			Default: LOW
		  StopInstances: 
			Error: LOW
			Stopped: MEDIUM
			Default: MEDIUM
		  TerminateInstances:
			Error: LOW
			SingleInstance: LOW
			MultipleInstances: HIGH
			Default: LOW
	```
	
- Use makefile to package child controller code

	```bash
	make child_package
	```
	
- Copy the child controller package to s3 bucket in the accounts where child controller is to be deployed
	```bash
	aws s3 cp deployment/child.zip s3://<s3-bucket-name>/child.zip
	```
<br>

## Step-5: Deploy Child Controller
- AWS cloudformation console (for single account/region deployment):
	- Go to AWS Cloudformation, Create Stack, Upload the `cfn/child-deployment-stack.yaml` file as the template
	- Update the required paramters `s3 bucket: The one you uploaded child.zip on`
	- Create the stack

- StackSet (for multiple account / region deployments)[optional]
	- Package the child controller as a zip and upload it to an s3 bucket in the root AWS account / delegated admin for stack set account.
	- The stack set deployment would require the use of `cfn/child-stack-set-cfn-template.yaml` file as not all stack set deployments support the `AWS::Serverless` Transform.
	- Create a stack set using the above mentioned template with the appropriate parameters for the selected organizations AWS accounts.

<br>

## Notes
- DIAL is a event driven project, which means it will not detect any existsing misconfiguration rather misconfigurations on the incoming events.
- You will have to deploy child controllers in **us-east-1** for each account as **IAM** is a global service and all events can be captured on the mentioned region itself. If you choose not to deploy it on **us-east-1** region, you will not be getting any alerts related to **IAM**.
- The Parent deployment will create **DynamoDB Table and API Gateway Endpoing that will NOT be deleted** when the stack is marked for deletion. This is done to save the security events in the DynamoDB table and the API Gateway Endpoint configured in the child controllers. For changes to parent - updating the cloudformation stack is recommended.
- The DynamoDB Table created by the Parent cloudformation template does not have autoscaling enabled (Ref: https://medium.com/@CevoAustralia/dynamodb-autoscaling-with-cloudformation-702e16009573) but it is recommended to enable autoscaling for the dynamoDB if the number of events varies over time.
- The EventPattern JSON for the EventBridge for child controllers can be found at [eventBridge](eventBridge)
- You can choose **not** to configure **theHive** URL and apiKey if you are not using that, in that case all the events will be forwarded to DyanmoDB and Slack.
- If you wish to use **theHive** project as a full part of deployment you can simply follow the steps mentioned in their official [repository](https://docs.thehive-project.org/thehive/legacy/thehive3/installation/install-guide/)

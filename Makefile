build-docker:
	sudo docker build --no-cache --tag robos .

run-docker:
	sudo docker run --rm --name robos --publish 4300:4300 robos
	
build-enclave:
	PCR0=$$(sudo enclaver build --file enclaver.yaml | grep -o '"PCR0": "[^"]*"' | cut -d'"' -f4) && \
	sudo sed -i "s|__PCR0__|$$PCR0|g" pcr-policy-stub.json

update-pcr:
	TOKEN=$$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") && \
    INSTANCE_PROFILE_ARN=$$(curl -s -H "X-aws-ec2-metadata-token: $$TOKEN" http://169.254.169.254/latest/meta-data/iam/info | jq -r '.InstanceProfileArn') && \
    INSTANCE_PROFILE_NAME=$$(echo $$INSTANCE_PROFILE_ARN | sed 's/.*instance-profile\///' | sed 's/\/.*//') && \
    ROLE_NAME=$$(aws iam get-instance-profile --instance-profile-name $$INSTANCE_PROFILE_NAME --query "InstanceProfile.Roles[0].RoleName" --output text) && \
    aws iam put-role-policy --role-name $$ROLE_NAME --policy-name KMSEnclavePermissions --policy-document file://pcr-policy-stub.json
	
run-enclave:
	sudo enclaver run --publish 4300:4300 robos:enclave-latest
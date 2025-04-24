build-docker:
	sudo docker build --no-cache --tag robos .

build-enclave:
	PCR0=$(sudo enclaver build --file enclaver.yaml | grep -o '"PCR0": "[^"]*"' | cut -d'"' -f4)
	sudo sed -i "s|\${PCR0}|$PCR0|g" pcr-policy-stub.json

run-enclave:
	sudo enclaver run --publish 4300:4300 robos:enclave-latest
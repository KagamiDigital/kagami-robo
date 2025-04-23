build-docker:
	sudo docker build --no-cache --tag robos .

build-enclave:
	sudo enclaver build --file enclaver.yaml

run-enclave:
	sudo enclaver run --publish 4300:4300 robos:enclave-latest
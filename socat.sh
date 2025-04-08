#!/bin/sh

# The Enclaver sets `http_proxy` env variable that looks like "http://127.0.0.1:9000"
# Extract proxy settings from environment or use defaults
if [[ -n "$http_proxy" ]]; then
  proxy_url=${http_proxy#http://}
  proxy_host=${proxy_url%:*}
  proxy_port=${proxy_url#*:}
else
  proxy_host=127.0.0.1
  proxy_port=9000
fi

# Print the proxy host and port for debugging
echo "Proxy host: ${proxy_host}"
echo "Proxy port: ${proxy_port}"

# The host and port that you want to egress to. Be sure to add the host or IP to the
# egress.allow list in enclaver.yaml
remote_host="www.google.com"
remote_port=443

# Start the TCP tunnel
socat TCP4-LISTEN:${remote_port},reuseaddr,fork PROXY:${proxy_host}:${remote_host}:${remote_port},proxyport=${proxy_port} &
#!/bin/bash

# Create the runner script
cat > /usr/local/bin/run-robo-enclave.sh << EOF
#!/bin/bash

# Log the start time
echo "Starting kagami-robo enclave at \$(date)" >> /var/log/startup-robo-enclave.log

# Change to the repository directory
cd /home/ec2-user/kagami-robo || {
    echo "Failed to find kagami-robo repository at /home/ec2-user/kagami-robo" >> /var/log/startup-robo-enclave.log
    exit 1
}

# Run the make command and log the result
echo "Running make run-enclave in \$(pwd)" >> /var/log/startup-robo-enclave.log
make run-enclave >> /var/log/startup-robo-enclave.log 2>&1

# Log completion
echo "Completed kagami-robo enclave startup at \$(date)" >> /var/log/startup-robo-enclave.log
EOF

# Make the script executable
chmod +x /usr/local/bin/run-robo-enclave.sh

# Create a systemd service file
cat > /etc/systemd/system/run-robo-enclave.service << EOF
[Unit]
Description=Run robo enclave on boot
After=network.target

[Service]
Type=oneshot
User=$CURRENT_USER
ExecStart=/usr/local/bin/run-robo-enclave.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable the service so it runs on every boot
systemctl enable run-robo-enclave.service

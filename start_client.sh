#!/bin/bash
if [ -z "$1" ]; then
  echo "Error: You must provide the Server's IP address."
  echo "Usage: ./start_client.sh <SERVER_IP>"
  echo "Example: ./start_client.sh 100.80.90.100"
  exit 1
fi

# Connects to the provided IP address on port 9877
./client "$1" 9877

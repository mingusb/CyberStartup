#!/bin/bash
for i in {1..30}; do
  status=$(curl -s -o /dev/null -w "%{http_code}" https://mingusb.github.io/CyberStartup/)
  
  if [ "$status" -eq 200 ]; then
    echo "SUCCESS: Page is live at CyberStartup"
    exit 0
  fi
  
  echo "Still waiting... (CyberStartup=$status)"
  sleep 15
done
echo "FAILURE: Timeout waiting for page"
exit 1

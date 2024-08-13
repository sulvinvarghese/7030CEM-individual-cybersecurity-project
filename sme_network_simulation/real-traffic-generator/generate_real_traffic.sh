#!/bin/bash

while true; do
  curl http://node-app:3000
  ping -c 4 node-app
  sleep 5
done

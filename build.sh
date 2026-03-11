#!/bin/bash
set -e
apt-get update -y
apt-get install -y nmap
pip install --upgrade pip
pip install -r requirements.txt

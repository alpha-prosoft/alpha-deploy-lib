#!/bin/bash

python3 -m venv .venv

source .venv/bin/activate

pip install boto3 

python3 deploy.py

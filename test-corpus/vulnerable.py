import pickle
import yaml
import os

# sg-insecure-deserialization-py
def load_session(data):
    return pickle.loads(data)

# sg-yaml-unsafe-load
def load_config(raw):
    return yaml.load(raw)

# sg-command-injection
def ping(host):
    os.system("ping -c 1 " + host)

# sg-debug-mode-enabled
DEBUG = True

# sg-hardcoded-secret-generic
password = "SuperSecretPassw0rd!23"

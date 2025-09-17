import configparser
import os

CONFIG_FILE = 'config.ini'

def get_config():
    """Reads the configuration file and returns a config object."""
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
    
    if 'VirusTotal' not in config:
        config['VirusTotal'] = {'api_key': ''}
        
    return config

def save_config(config):
    """Saves the config object to the configuration file."""
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def get_api_key():
    """Retrieves the VirusTotal API key from the config file."""
    config = get_config()
    return config.get('VirusTotal', 'api_key', fallback='')

def save_api_key(api_key):
    """Saves the VirusTotal API key to the config file."""
    config = get_config()
    if 'VirusTotal' not in config:
        config['VirusTotal'] = {}
    config['VirusTotal']['api_key'] = api_key
    save_config(config)
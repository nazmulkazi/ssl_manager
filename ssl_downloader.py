'''
Author: Nazmul Kazi
Version: 2.1.1
Updated: September 20, 2024

Description:
    This script automates the process of retrieving SSL data from a remote server for a specified domain, validates the certificate's metadata, and exports it along with its private key and CA bundle to the local machine based on the user's preferences. The script also provides functionality to trigger a shell command after successfully exporting a new certificate.

Requirements:
    - A configuration file in JSON format that includes the necessary information to fetch the SSL certificate from the remote server and export it to the local machine.
'''

import argparse
import json
import os
import requests
import subprocess as sp
import sys
import traceback
from datetime import datetime

def print_block(message: str, title: str = None, hline_width: int = 80, indent_level: int = 0) -> None:
    '''
    Prints a message within a block, created by printing a horizontal line of dashes at the beginning and end of the message. If a title is provided, it is centered on the top horizontal line.

    Args:
        message (str): The message to print.
        title (str, optional): Title of the block. Defaults to None.
        hline_width (int, optional): Width of the horizontal line. Defaults to 80.
        indent_level (int, optional): Indentation level. The text is indented by two spaces at each level. Defaults to 0.
    '''
    
    hline = '-' * hline_width
    indent = ' ' * (indent_level * 2)
    
    # Print the top line and the title, if provided
    print(indent, f' {title} '.center(hline_width, '-') if title else hline, sep='', end=f'\n{indent}')
    
    # Convert message to string, if not already
    if not isinstance(message, str):
        message = str(message)
    
    # Print the message and the bottom line with the same indentation
    print(str(message).replace('\n', f'\n{indent}').rstrip(), hline, sep=f'\n{indent}')

def timestamp2datetime(timestamp: int) -> str:
    '''
    Converts a Unix timestamp to a human-readable datetime string.

    Args:
        timestamp (int): Unix timestamp.

    Returns:
        str: The datetime string in the format 'YYYY-MM-DD HH:MM:SS'.
    '''
    
    return datetime.fromtimestamp(timestamp).isoformat().replace('T', ' ')

def load_config(path: str) -> dict:
    '''
    Loads the configuration file and checks for required parameters.

    Args:
        path_config (str): Path to the configuration JSON file.

    Returns:
        dict: Returns the configuration as a dictionary if valid, otherwise exits with an error message.
    '''
    
    # Check if the config file exists
    if not os.path.exists(path):
        raise SystemExit(f'Error: The configuration file does not exist.\nPath: {path}')

    # Read the configuration file as JSON
    with open(path, 'r') as file:
        try:
            config = json.load(file)
        except Exception as e:
            print('ParseError: Failed to parse the configuration file as JSON! Please ensure the configuration file is properly formatted.')
            print('Path:', path)
            return print_block(traceback.format_exc(), title='Traceback')
    
    # Check if the configuration file contains all required parameters
    params = ['remote_url', 'token', 'domain', 'crt', 'key', 'cab', 'metadata']
    missing_params = [param for param in params if param not in config]
    
    # Raise an error if any of the required fields are missing
    if missing_params:
        raise SystemExit(f'Error: The configuration file is missing the following required fields: {", ".join(missing_params)}')
    
    # Return the loaded configuration
    return config

def download_ssl_data(config: dict) -> dict:
    '''
    Downloads SSL data from remote server.

    Args:
        config (dict): Dictionary containing configuration parameters.

    Returns:
        dict: Returns SSL certificate data if successful, otherwise None.
    '''
    
    # Set headers for the SSL request
    headers = {
        'Accept': 'application/json',
        'Authorization': config['token'],
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    }
    
    # Send a request to the remote server
    res = requests.get(url=f"{config['remote_url']}?req=ssl_certificate&domain={config['domain']}", headers=headers)
    
    # Check if the request was successful
    if res.status_code != 200:
        print(f'Error: Request to the remote server failed and returned HTTP Status Code {res.status_code} ({res.reason}).')
        if res.content:
            print_block(res.content.decode(), title='Response Body')
        return None
    
    # Parse the response as JSON. The response should contain 'domain', 'crt', 'cab', 'key', 'valid_from', 'valid_to', and 'fingerprint'.
    try:
        data = res.json()
    except Exception as e:
        print('ParseError: Failed to parse the response from the remote server as JSON.')
        print_block(traceback.format_exc(), title='Traceback')
        return print_block(res.content.decode(), title='Response Body')
    
    # Check if the response contains SSL certificate data
    if 'crt' not in data:
        print('Error: The response from the remote server does not contain any SSL certificate.')
        return print_block(data, title='Parsed Response')
    
    # Return SSL certificate data
    return data

def export_ssl_certificate(config: dict, cert: dict) -> bool:
    '''
    Exports SSL certificate, private key, CA bundle, and certificate metadata to local machine.
    
    Args:
        config (dict): Configuration dictionary with file paths for certificate, key, CA bundle, and metadata.
        cert (dict): SSL certificate data including 'domain', 'crt', 'cab', 'key', 'valid_from', 'valid_to', and 'fingerprint'.

    Returns:
        bool: Returns True if the certificate data is successfully exported, otherwise None.
    '''
    
    # Check if the certificate's validation period has begun
    if cert['valid_from'] > int(datetime.now().timestamp()):
        valid_from = timestamp2datetime(cert['valid_from'])
        return print(f'Error: The received certificate is not valid before {valid_from}.\nFingerprint: {cert["fingerprint"]}')
    
    # Load current certificate metadata for comparison, if exists
    try:
        with open(config['metadata'], 'r') as file:
            metadata = json.load(file)
    # If failed to load or parse the existing metadata file, override the existing certificate with the received one
    except FileNotFoundError:
        print('Metadata file does not exist.')
    except Exception as e:
        if e.__class__.__name__ == 'JSONDecodeError':
            print('JSONDecodeError: Failed to parse the current certificate metadata file as JSON.')
            print_block(traceback.format_exc(), title='Traceback')
            with open(config['metadata'], 'r') as file:
                print_block(file.read(), title='Certificate Metadata File Content')
        else:
            print(e.__class__.__name__ + ':', e)
        print('*** Exporting the received certificate to override the existing certificate and its corrupted metadata file. ***')
    # Compare the received certificate against the existing one
    else:
        # Check if the existing and the received certificates are identical
        if metadata['fingerprint'] == cert['fingerprint']:
            return print('Certificate is up to date.')

        # Check if the received certificate expires before the existing one
        if cert['valid_to'] <= metadata['valid_to']:
            print(f'Error: The received certificate expires before the existing one.')
            print_block(f"Fingerprint: {cert['fingerprint']}\nValid Until: {timestamp2datetime(cert['valid_to'])}", title='Received Certificate')
            print_block(f"Fingerprint: {metadata['fingerprint']}\nValid Until: {timestamp2datetime(metadata['valid_to'])}", title='Existing Certificate')
            return None
    
    # Log a new and valid certificate is received
    print('Received new certificate with fingerprint:', cert['fingerprint'])
    
    # Export the received certificate, private key, and CA bundle
    print('Exporting new certificate:')
    for name in ['crt', 'key', 'cab']:
        if config.get(name):
            try:
                with open(config[name], 'w') as file:
                    file.write(cert[name])
                    print(' ', name, '=>', config[name])
                    exported = True
            except:
                print_block(f'Path: {config[name]}\n\n{traceback.format_exc()}', title=f'Error: Failed To Export {name.upper()}')
                # Exit as failed to export a required file
                return False
    
    # Export metadata of the received certificate
    metadata = {k:cert[k] for k in ['domain', 'valid_from', 'valid_to', 'fingerprint']}
    try:
        with open(config['metadata'], 'w') as file:
            json.dump(metadata, file, indent=4)
    except:
        print_block(f'Path: {config["metadata"]}\n\n{traceback.format_exc()}', title='Error: Failed To Export Metadata')
    
    return True

if __name__ == '__main__':
    # Get the directory path of the script
    script_dir = os.path.dirname(os.path.realpath(__file__))

    # Argument parser for command-line options
    parser = argparse.ArgumentParser(description='Automatically downloads new SSL certificate from remote server and exports it to the local machine.')
    parser.add_argument('--config', metavar='PATH', default=os.path.join(script_dir, 'config.json'), help='Path to the configuration file.')
    # parser.add_argument('--metadata',  metavar='PATH', default=os.path.join(script_dir, 'metadata.json'), help='Path to the certificate metadata file.')
    parser.add_argument('--on-export', metavar='COMMAND', help='A shell command to execute after exporting a new certificate.')
    
    # Parse the command-line arguments
    args = parser.parse_args()
    
    # Print current date and time for logging
    print('\n', f' Timestamp: {datetime.now()} '.center(100, '#') , sep='')
    
    # Load configuration
    if config := load_config(args.config):
        # Fetch the latest certificate from remote server
        if cert := download_ssl_data(config):
            # Export the received certificate and execute the shell command if provided
            if export_ssl_certificate(config, cert) and args.on_export:
                # Flush STDOUT to avoid mixed output
                sys.stdout.flush()
                # Print a horizontal line to separate outputs
                print(' Shell Command Executed '.center(100, '='), flush=True)
                # Execute the provided shell command
                sp.run(args.on_export, shell=True, check=True)

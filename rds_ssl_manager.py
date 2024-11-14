'''
Author: Nazmul Kazi
Version: 1.0.0
Updated: September 30, 2024

Description:
    This script manages SSL certificates for Remote Desktop Services (RDS) on a Windows machine. It performs the following tasks:
        1. Converts an SSL certificate from PEM to PKCS #12 format using OpenSSL.
        2. Imports the certificate into the specified certificate store on the local machine.
        3. Sets the newly imported certificate for use by RDS.
        4. Cleans the certificate store by deleting expired certificates.

Dependencies:
    - Must be executed with administrative privilege.
    - OpenSSL must be installed and accessible via the specified path.
'''

import argparse
import ctypes
import json
import os
import re
import subprocess as sp
import traceback
from datetime import datetime

def has_admin_privileges() -> bool:
    '''
    Checks if the current script is running with administrative privileges.

    Returns:
        bool: True if running with administrative privileges, False otherwise.
    '''
    
    try:
        # Try to call the Windows API to check if the current user is an administrator
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        # Return False when cannot be determined or encounters an exception
        return print('Error: Unable to determine if the script is running with administrative privileges.')

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

def convert_certificate(path_openssl: str, path_crt: str, path_key: str, path_pfx: str) -> bool:
    '''
    Converts an SSL certificate from PEM to PKCS #12 format using OpenSSL.

    Args:
        path_openssl (str): Path to the OpenSSL executable.
        path_crt (str): Path to the certificate file in PEM format.
        path_key (str): Path to the private key file in PEM format.
        path_pfx (str): Path to save the converted certificate in PKCS #12 format.

    Returns:
        bool: True if the conversion was successful, False otherwise.
    '''
    
    command = f'{path_openssl} pkcs12 -export -passout pass: -in {path_crt} -inkey {path_key} -out {path_pfx}'
    try:
        # Execute the OpenSSL command to convert the certificate format
        sp.run(command, shell=True, check=True)
        
        # Verify the existence of the PKCS #12 certificate file
        if not os.path.isfile(path_pfx):
            return print(f'\nError: Certificate conversion command executed without errors, but the PKCS #12 certificate was not found at `{path_pfx}`.\nCommand: {command}')
        print(f'Converted certificate to PKCS #12 format.')
        return True
    except sp.CalledProcessError as e:
        print(f'\nError: Certificate conversion command failed with return code {e.returncode}\nCommand: {command}')
        return print_block(e.stdout, title='STDOUT')

def import_certificate(path_pfx: str, store_name: str) -> bool:
    '''
    Imports PKCS #12 certificate into the specified certificate store in local machine.

    Args:
        path_pfx (str): Path to the PKCS #12 certificate file.
        store_name (str): Name of the certificate store (e.g., 'My').

    Returns:
        bool: True if the import was successful, False otherwise.
    '''
    
    command = f'certutil -p "" -importpfx {store_name} {path_pfx}'
    try:
        process = sp.run(command, shell=True, check=True, stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
        
        # Check the process output for success indicators
        if ' added to store.' in process.stdout:
            print(f'Added certificate to store {store_name} in local machine (certlm).')
        elif ' already in store' in process.stdout:
            print(f'Certificate already exists in store {store_name} in local machine (certlm).')
        else:
            print(f'\nError: Failed to add certificate to store {store_name} in local machine (certlm).\nCommand: {command}')
            return print_block(process.stdout, title='STDOUT')
        return True
    except sp.CalledProcessError as e:
        print(f'\nError: Certificate import command failed with return code {e.returncode}.\nCommand: {command}')
        return print_block(e.stdout, title='STDOUT')

def load_metadata(path: str) -> dict:
    '''
    Loads and parses JSON metadata of the certificate.

    Args:
        path (str): Path to the metadata file.

    Returns:
        dict: Parsed metadata, or None if parsing failed.
    '''
    
    with open(path, 'r') as file:
        try:
            return json.load(file)
        except Exception as e:
            print('ParseError: Failed to parse the metadata file as JSON! Please ensure the metadata file is properly formatted.')
            print('Path:', path)
            return traceback.print_exc()

def set_rds_certificate(fingerprint: str) -> bool:
    '''
    Sets certificate for Remote Desktop Services (RDS) using its SHA1 fingerprint.

    Args:
        fingerprint (str): SHA1 fingerprint of the certificate.

    Returns:
        bool: True if the certificate was successfully set, False otherwise.
    '''
    
    command = rf'wmic /namespace:\\root\cimv2\TerminalServices PATH Win32_TSGeneralSetting Set SSLCertificateSHA1Hash="{fingerprint}"'
    try:
        process = sp.run(command, shell=True, check=True, stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
        
        # Check if the process output indicates success
        if ' update successful' not in process.stdout:
            print(f'\nError: Failed to set certificate for Remote Desktop Services (RDS).\nCommand: {command}')
            return print_block(process.stdout, title='STDOUT')
        
        print('Certificate for RDS is set to', fingerprint)
        return True
    except sp.CalledProcessError as e:
        print(f'Error: Setting certificate for Remote Desktop Services (RDS) failed with return code {e.returncode}.\nCommand: {command}')
        return print_block(e.stdout, title='STDOUT')

def delete_certificate(store_name: str, fingerprint: str) -> bool:
    '''
    Deletes a certificate from store in the local machine using its fingerprint.

    Args:
        store_name (str): Name of the certificate store.
        fingerprint (str): SHA1 fingerprint of the certificate to delete.

    Returns:
        bool: True if the certificate was successful deleted, False otherwise.
    '''
    
    command = f'certutil -delstore {store_name} {fingerprint}'
    try:
        process = sp.run(command, shell=True, check=True, stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
        
        # Check if the process output indicates successful deletion
        if fingerprint not in process.stdout or ' completed successfully' not in process.stdout:
            print(' '*3, 'Error: Failed to delete certificate.')
            print_block(process.stdout, title='STDOUT', indent=2)
        return print(' '*3, '[DELETED]')
    except sp.CalledProcessError as e:
        indent = ' '*4
        print(f'{indent}Error: Certificate deletion command failed with return code {e.returncode}.\n{indent}Command: {command}')
        return print_block(e.stdout, title='STDOUT', indent=2)

def clean_store(store_name: str, fingerprint: str) -> None:
    '''
    Cleans the specified certificate store by deleting expired certificates.

    Args:
        store_name (str): Name of the certificate store.
        fingerprint (str): Fingerprint of the current active certificate to be retained.
    '''
    
    print(f'Deleting expired certificate(s) from store {store_name}:')
    
    # Get a list of current certificates
    command = f'certutil -store {store_name}'
    try:
        process = sp.run(command, shell=True, check=True, stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
        
        # Ensure the store command was successful
        if 'CertUtil: -store command completed successfully.' not in process.stdout:
            print(f'  Error: Failed to get a list of current certificate(s) in store {store_name}.\n  Command: {command}')
            return print_block(process.stdout, title='STDOUT', indent=1)
    except sp.CalledProcessError as e:
        print(f'  Error: Listing current certificates failed with return code {e.returncode}.\n  Command: {command}')
        return print_block(e.stdout, title='STDOUT', indent=1)
    
    # Split the output into separate certificates
    certs = re.split(r'={3,} Certificate \d+ ={3,}\n', process.stdout)[1:]
    if not certs:
        return print(f'  Error: No certificates were found in store {store_name}, even though a certificate was added or reported to already exist in the store in a previous step!')
    
    # Iterate over the certificates and delete if expired
    for cert in certs:
        # Ignore the latest certificate and certificates with no expiration date.
        if fingerprint in cert or 'NotAfter:' not in cert: continue
        
        # Extract expiration date
        not_after = re.search(r'NotAfter:\s([^\n]+)', cert).groups()[0]
        not_after = datetime.strptime(not_after, '%m/%d/%Y %I:%M %p')
        
        # Delete certificate if expired
        if not_after < datetime.now():
            # Extract fingerprint and common name for logging
            cn = re.search(r'Subject: CN=([^\n]+)', cert).groups()[0]
            fp = re.search(r'Cert Hash\(sha1\): ([^\s]+)', cert).groups()[0]
            print(f'  Found expired certificate:\nCommon Name: {cn}\nFingerprint: {fp}\nNot After: {not_after}'.replace('\n', '\n    '))
            
            # Delete the expired certificate
            delete_certificate(store_name, fp)

if __name__ == '__main__':
    # Get the directory path of the script
    script_dir = os.path.dirname(os.path.realpath(__file__))
    
    # Argument parser for command-line options
    parser = argparse.ArgumentParser(description='Installs SSL certificate for Remote Desktop Services (RDS) and keeps the certificate up-to-date.')
    parser.add_argument('path_crt', metavar='crt PATH', help='Path to the SSL certificate in PEM format.')
    parser.add_argument('path_key', metavar='key PATH', help='Path to the SSL private key in PEM format.')
    parser.add_argument('--openssl', metavar='PATH', dest='path_openssl', default=os.path.join(script_dir, 'openssl', 'openssl.exe'), help='Path to the OpenSSL executable. (Default: `openssl/openssl.exe`)')
    parser.add_argument('--pfx', metavar='PATH', dest='path_pfx', default=None, help='Path to save the certificate in PKCS #12 format. (Default: Same directory as certificate.)')
    parser.add_argument('--metadata', metavar='PATH', dest='path_metadata', default=os.path.join(script_dir, 'metadata.json'), help='Path to the JSON metadata file. Must contain the certificate fingerprint. (Default: `metadata.json`)')
    parser.add_argument('--store-name', default='My', help='Certificate store name in the local machine. (Default: `My`)')
    
    # Parse the command-line arguments
    args = parser.parse_args()
    
    # Ensure the script is running with administrative privileges 
    if not has_admin_privileges():
        raise SystemExit('Error: Please run the script with administrative privileges. Otherwise, CertUtil cannot add or set the certificate for Remote Desktop Services (RDS).')
    
    # Validate the existence of specified paths
    for path in [args.path_crt, args.path_key, args.path_metadata]:
        if not os.path.isfile(path):
            raise SystemExit(f'Error: File not found! Path: `{path}`')
    
    # Validate or formulate the path to save the certificate in PKCS #12 format
    if args.path_pfx:
        # The path must end with .pfx extension
        if not args.path_pfx.endswith('.pfx'):
            raise SystemExit(f'Error: The path for PKCS #12 certificate file must end with ".pfx" file extension.')
    
        # The path directory must exist
        if not os.path.isdir((dirname := os.path.dirname(args.path_pfx))):
            raise SystemExit(f'Error: The path directory for PKCS #12 certificate file not found! Path: `{dirname}`')
    else:
        args.path_pfx = re.sub(r'\.(?:crt|pem)$', '', args.path_crt, flags=re.IGNORECASE) + '.pfx'
    
    # Format the store name to properly handle spaces
    if ' ' in args.store_name and not args.store_name.startswith('"'):
        args.store_name = f'"{args.store_name}"'
    
    # Convert SSL certificate from PEM to PKCS #12 format
    if convert_certificate(args.path_openssl, args.path_crt, args.path_key, args.path_pfx):
        # Import SSL certificate to the personal store and load certificate metadata
        if import_certificate(args.path_pfx, args.store_name) and (metadata := load_metadata(args.path_metadata)):
            # Set new certificate to be used for RDS
            if set_rds_certificate(metadata['fingerprint']):
                # Delete expired certificates
                clean_store(args.store_name, fingerprint=metadata['fingerprint'])
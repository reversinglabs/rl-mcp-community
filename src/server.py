import logging
import os

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP(name="Spectra Assure Community MCP Server")

RL_PROTECT_BIN = os.environ.get("RL_PROTECT_BIN", "rl-protect")
SCAN_TIMEOUT = int(os.environ.get("RL_SCAN_TIMEOUT", "600"))
REPORTS_DIR = os.environ.get("RL_REPORTS_DIR", "/app/reports")
SCRIPTS_DIR = os.environ.get("RL_SCRIPTS_DIR", "/app/scripts")


def get_auth_args() -> list[str]:
    token = os.environ.get("RL_TOKEN")
    if not token:
        raise ValueError("RL_TOKEN environment variable not set")

    args = ["--rl-token", token]

    if token.startswith("rls3c"):
        server = os.environ.get("RL_PORTAL_SERVER")
        org = os.environ.get("RL_PORTAL_ORG")
        if not server or not org:
            raise ValueError("RL_PORTAL_SERVER and RL_PORTAL_ORG must be set for enterprise accounts")
        args += ["--rl-portal-server", server, "--rl-portal-org", org]
        group = os.environ.get("RL_PORTAL_GROUP")
        if group:
            args += ["--rl-portal-group", group]

    return args


def get_optional_args(*, profile_override: str | None = None) -> list[str]:
    args = ["--no-tracking", "--no-color"]

    env_flags = [
        ("--concurrency", "RL_CONCURRENCY"),
        ("--ca-path", "RL_CA_PATH"),
        ("--proxy-server", "RL_PROXY_SERVER"),
        ("--proxy-port", "RL_PROXY_PORT"),
        ("--proxy-user", "RL_PROXY_USER"),
        ("--proxy-password", "RL_PROXY_PASSWORD"),
    ]

    if profile_override:
        args += ["--profile", profile_override]
    else:
        profile = os.environ.get("RL_PROFILE")
        if profile:
            args += ["--profile", profile]

    for flag, env in env_flags:
        val = os.environ.get(env)
        if val:
            args += [flag, val]

    return args


# Import tool modules to register their tools with the mcp instance.
from src import interpret as _interpret_module  # noqa: E402, F401
from src import scanning as _scanning_module  # noqa: E402, F401


def main():
    mcp.run()


if __name__ == "__main__":
    main()

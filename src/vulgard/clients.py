from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .config import Config
from .github import GitHub
from .kev import fetch_kev
from .linear import Linear, LinearClient
from .slack import Slack, SlackClient


@dataclass
class Clients:
    github: Any
    linear: LinearClient | None
    slack: SlackClient | None
    slack_webhook: str | None
    kev: Callable[[], frozenset[str]]


def live_clients(config: Config) -> Clients:
    linear_key = os.environ.get(config.linear.api_key_env)
    slack_token = os.environ.get(config.slack.token_env)
    return Clients(
        github=GitHub(),
        linear=Linear(linear_key) if linear_key else None,
        slack=Slack(slack_token) if slack_token else None,
        slack_webhook=os.environ.get(config.slack.webhook_env),
        kev=fetch_kev,
    )

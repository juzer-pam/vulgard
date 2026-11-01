from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import boto3

from .aws import AwsScanner
from .config import Config
from .estate import Scanner
from .github import GitHub
from .kev import fetch_kev
from .linear import Linear, LinearClient
from .slack import Slack, SlackClient
from .vercel import Vercel


@dataclass
class Clients:
    github: Any
    linear: LinearClient | None
    slack: SlackClient | None
    slack_webhook: str | None
    kev: Callable[[], frozenset[str]]
    scanners: Callable[[], list[Scanner]] = list  # built on first use: they need cloud creds


def live_scanners(config: Config) -> list[Scanner]:
    """AWS from the ambient credentials (OIDC in CI), Vercel when its token is set."""
    cfg = config.deployments
    scanners: list[Scanner] = [AwsScanner(boto3.Session(), cfg.aws.regions)]
    token = os.environ.get(cfg.vercel.token_env)
    if token and cfg.vercel.team_id:
        scanners.append(Vercel(token, cfg.vercel.team_id))
    return scanners


def live_clients(config: Config) -> Clients:
    linear_key = os.environ.get(config.linear.api_key_env)
    slack_token = os.environ.get(config.slack.token_env)
    return Clients(
        github=GitHub(),
        linear=Linear(linear_key) if linear_key else None,
        slack=Slack(slack_token) if slack_token else None,
        slack_webhook=os.environ.get(config.slack.webhook_env),
        kev=fetch_kev,
        scanners=lambda: live_scanners(config),
    )

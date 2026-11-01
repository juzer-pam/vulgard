from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import boto3

from .aws import AwsOps, AwsScanner
from .config import Config
from .estate import Scanner
from .executor import LiveExecutor
from .github import GitHub
from .kev import fetch_kev
from .lifecycle import Executor
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
    executor: Callable[[], Executor] | None = None


def _vercel(config: Config) -> Vercel | None:
    cfg = config.deployments.vercel
    token = os.environ.get(cfg.token_env)
    return Vercel(token, cfg.team_id) if token and cfg.team_id else None


def live_scanners(config: Config) -> list[Scanner]:
    """AWS from the ambient credentials (OIDC in CI), Vercel when its token is set."""
    scanners: list[Scanner] = [AwsScanner(boto3.Session(), config.deployments.aws.regions)]
    vercel = _vercel(config)
    if vercel:
        scanners.append(vercel)
    return scanners


def live_executor(gh: Any, config: Config) -> Executor:
    aws = AwsOps(boto3.Session(), config.deployments.aws.delete_role_arn)
    return LiveExecutor(gh, config, aws, _vercel(config))


def live_clients(config: Config) -> Clients:
    linear_key = os.environ.get(config.linear.api_key_env)
    slack_token = os.environ.get(config.slack.token_env)
    gh = GitHub()
    return Clients(
        github=gh,
        linear=Linear(linear_key) if linear_key else None,
        slack=Slack(slack_token) if slack_token else None,
        slack_webhook=os.environ.get(config.slack.webhook_env),
        kev=fetch_kev,
        scanners=lambda: live_scanners(config),
        executor=lambda: live_executor(gh, config),
    )

"""Static estimate of the AWS actions Python code calls through literal boto3 clients.

Source is parsed with `ast`, never imported. This is an estimate, labelled as such: dynamic
service names, `boto3.resource` objects and wrappers are reported as unresolved, not guessed.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

# boto3 method names that do not map mechanically to an IAM action name.
OVERRIDES = {
    ("s3", "list_objects"): "s3:ListBucket",
    ("s3", "list_objects_v2"): "s3:ListBucket",
    ("s3", "head_bucket"): "s3:ListBucket",
    ("s3", "head_object"): "s3:GetObject",
    ("s3", "download_file"): "s3:GetObject",
    ("s3", "download_fileobj"): "s3:GetObject",
    ("s3", "upload_file"): "s3:PutObject",
    ("s3", "upload_fileobj"): "s3:PutObject",
    ("lambda", "invoke"): "lambda:InvokeFunction",
}
CLIENT_HELPERS = {"close", "get_paginator", "get_waiter", "can_paginate", "exceptions", "meta"}


@dataclass(frozen=True, slots=True)
class CodeActions:
    actions: tuple[str, ...]
    unresolved: tuple[str, ...]  # Files with boto3 usage this estimate cannot resolve.
    method: str = "static_boto3_client_call_estimate"

    def missing_from(self, granted: Iterable[str]) -> tuple[str, ...]:
        granted = [action.lower() for action in granted]
        return tuple(
            action
            for action in self.actions
            if not any(fnmatchcase(action.lower(), allowed) for allowed in granted)
        )


def _action(service: str, method: str) -> str:
    return OVERRIDES.get(
        (service, method), f"{service}:{''.join(part.capitalize() for part in method.split('_'))}"
    )


def _boto3_factory(call: ast.Call) -> str | None:
    """Return "client"/"resource" for boto3.client(...) or session.client(...) calls."""
    function = call.func
    if not isinstance(function, ast.Attribute) or function.attr not in {"client", "resource"}:
        return None
    owner = function.value
    name = owner.id if isinstance(owner, ast.Name) else ""
    if name == "boto3" or "session" in name.lower():
        return function.attr
    return None


def required_actions(root: Path, files: Iterable[Path]) -> CodeActions:
    actions: set[str] = set()
    unresolved: set[str] = set()
    for path in files:
        if path.suffix != ".py":
            continue
        relative = path.relative_to(root).as_posix()
        tree = ast.parse(path.read_bytes(), filename=relative)
        clients: dict[str, str] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not (factory := _boto3_factory(node)):
                continue
            first = node.args[0] if node.args else None
            literal = isinstance(first, ast.Constant) and isinstance(first.value, str)
            if factory == "resource" or not literal:
                unresolved.add(relative)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and _boto3_factory(node.value) == "client"
                and node.value.args
                and isinstance(node.value.args[0], ast.Constant)
                and isinstance(node.value.args[0].value, str)
            ):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        clients[target.id] = node.value.args[0].value
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in clients
                and node.func.attr not in CLIENT_HELPERS
            ):
                actions.add(_action(clients[node.func.value.id], node.func.attr))
    return CodeActions(tuple(sorted(actions)), tuple(sorted(unresolved)))

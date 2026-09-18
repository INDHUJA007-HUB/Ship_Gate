"""Local executor for the subset of Amazon States Language the scan pipeline uses.

Local mode runs the exact definition deployed to AWS Step Functions, so retries, catches, map
iterations and partial-result routing are exercised without an account. SAM has no local state
machine emulator, and a hand-written Python copy of the flow would drift from the deployed one.

Fidelity rules this runner follows (JSONPath query language):
- Task:   InputPath -> Parameters -> invoke -> ResultSelector -> ResultPath -> OutputPath.
- Retry:  first retrier whose ErrorEquals matches is used; each keeps its own attempt count;
          delay = IntervalSeconds * BackoffRate ** n, capped by MaxDelaySeconds, FULL jitter.
- Catch:  {"Error", "Cause"} is placed at the catcher's ResultPath in the state's raw input.
- States.ALL matches everything except States.Runtime and States.DataLimitExceeded, which
  always fail the execution; States.TaskFailed also excludes States.Timeout.
- Invocation payloads round-trip through JSON and are capped at 256 KiB, like Lambda tasks.
Anything outside the subset is rejected when the definition loads, never silently ignored.
"""

from __future__ import annotations

import copy
import json
import random as random_module
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from datetime import UTC, datetime

PAYLOAD_LIMIT = 256 * 1024
PATH = re.compile(r"\$\$?(\.[A-Za-z_][A-Za-z0-9_]*)*")
PLACEHOLDER = re.compile(r"\$\{([A-Za-z][A-Za-z0-9]*)\}")
UNCATCHABLE = {"States.Runtime", "States.DataLimitExceeded"}
COMMON = {"Type", "Comment"}
FIELDS = {
    "Task": COMMON
    | {"Resource", "Parameters", "InputPath", "OutputPath", "ResultPath", "ResultSelector"}
    | {"TimeoutSeconds", "Retry", "Catch", "Next", "End"},
    "Map": COMMON
    | {"ItemsPath", "ItemSelector", "ItemProcessor", "MaxConcurrency", "InputPath"}
    | {"OutputPath", "ResultPath", "ResultSelector", "Retry", "Catch", "Next", "End"},
    "Choice": COMMON | {"Choices", "Default", "InputPath", "OutputPath"},
    "Pass": COMMON
    | {"Parameters", "Result", "InputPath", "OutputPath", "ResultPath"}
    | {"Next", "End"},
    "Succeed": COMMON | {"InputPath", "OutputPath"},
    "Fail": COMMON | {"Error", "Cause", "CausePath"},
}
RETRY_FIELDS = {"ErrorEquals", "IntervalSeconds", "MaxAttempts", "BackoffRate"}
RETRY_FIELDS |= {"MaxDelaySeconds", "JitterStrategy", "Comment"}
CATCH_FIELDS = {"ErrorEquals", "Next", "ResultPath", "Comment"}
COMPARISONS = {
    "StringEquals": lambda value, expected: isinstance(value, str) and value == expected,
    "BooleanEquals": lambda value, expected: isinstance(value, bool) and value == expected,
    "NumericEquals": lambda value, expected: _number(value) and value == expected,
    "NumericGreaterThan": lambda value, expected: _number(value) and value > expected,
    "NumericLessThan": lambda value, expected: _number(value) and value < expected,
}


def _number(value) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


class UnsupportedDefinition(ValueError):
    pass


class StatesError(Exception):
    def __init__(self, name: str, cause: str = ""):
        super().__init__(name)
        self.name = name
        self.cause = cause


@dataclass
class Execution:
    name: str
    status: str  # SUCCEEDED | FAILED
    output: object = None
    error: str | None = None
    cause: str | None = None
    history: list[dict] = field(default_factory=list)

    def events(self, kind: str, state: str | None = None) -> list[dict]:
        return [e for e in self.history if e["event"] == kind and state in (None, e["state"])]


# ------------------------------------------------------------------------------ validation
def validate(definition: dict, resources: set[str] | None = None) -> None:
    _validate_machine(definition, resources, top=True)


def _validate_machine(machine: dict, resources, top=False) -> None:
    allowed = {"StartAt", "States", "Comment"} | (
        {"TimeoutSeconds"} if top else {"ProcessorConfig"}
    )
    if not isinstance(machine, dict) or set(machine) - allowed:
        raise UnsupportedDefinition("unsupported state machine fields")
    states = machine.get("States")
    if not isinstance(states, dict) or machine.get("StartAt") not in states:
        raise UnsupportedDefinition("StartAt must name a state")
    for name, state in states.items():
        kind = state.get("Type") if isinstance(state, dict) else None
        if kind not in FIELDS or set(state) - FIELDS[kind]:
            raise UnsupportedDefinition(f"{name}: unsupported type or field")
        transitions = [state.get("Next"), state.get("Default")]
        if kind in {"Task", "Map", "Pass"} and ("Next" in state) == bool(state.get("End")):
            raise UnsupportedDefinition(f"{name}: exactly one of Next or End")
        for key in ("InputPath", "OutputPath", "ItemsPath", "CausePath"):
            if state.get(key) is not None:
                _path(state[key], name)
        if "ResultPath" in state and state["ResultPath"] is not None:
            _reference_path(state["ResultPath"], name)
        for key in ("Parameters", "ResultSelector", "ItemSelector"):
            if key in state:
                _template(state[key], name)
        if kind == "Task":
            match = PLACEHOLDER.fullmatch(str(state.get("Resource", "")))
            if not match or (resources is not None and match[1] not in resources):
                raise UnsupportedDefinition(f"{name}: Resource must be a known ${{Placeholder}}")
            if not isinstance(state.get("TimeoutSeconds", 1), int):
                raise UnsupportedDefinition(f"{name}: TimeoutSeconds must be an integer")
        if kind in {"Task", "Map"}:
            _validate_handlers(state, name, states)
            transitions += [c.get("Next") for c in state.get("Catch", [])]
        if kind == "Map":
            processor = state.get("ItemProcessor", {})
            if processor.get("ProcessorConfig", {}).get("Mode", "INLINE") != "INLINE":
                raise UnsupportedDefinition(f"{name}: only INLINE maps are supported")
            _validate_machine(processor, resources)
        if kind == "Choice":
            if not state.get("Choices"):
                raise UnsupportedDefinition(f"{name}: Choices required")
            for rule in state["Choices"]:
                _rule(rule, name, top=True)
                transitions.append(rule["Next"])
        for target in transitions:
            if target is not None and target not in states:
                raise UnsupportedDefinition(f"{name}: unknown transition {target}")


def _validate_handlers(state: dict, name: str, states: dict) -> None:
    for key, fields in (("Retry", RETRY_FIELDS), ("Catch", CATCH_FIELDS)):
        handlers = state.get(key, [])
        for index, handler in enumerate(handlers):
            errors = handler.get("ErrorEquals")
            if set(handler) - fields or not errors or not all(isinstance(e, str) for e in errors):
                raise UnsupportedDefinition(f"{name}: invalid {key}")
            if "States.ALL" in errors and (len(errors) > 1 or index != len(handlers) - 1):
                raise UnsupportedDefinition(f"{name}: States.ALL must be alone and last")
            if handler.get("JitterStrategy", "NONE") not in {"FULL", "NONE"}:
                raise UnsupportedDefinition(f"{name}: invalid JitterStrategy")
            if key == "Catch":
                if handler.get("Next") not in states:
                    raise UnsupportedDefinition(f"{name}: Catch Next must name a state")
                if handler.get("ResultPath") is not None:
                    _reference_path(handler["ResultPath"], name)


def _path(value, name: str) -> None:
    if not isinstance(value, str) or not PATH.fullmatch(value):
        raise UnsupportedDefinition(f"{name}: unsupported path {value!r}")


def _reference_path(value, name: str) -> None:
    _path(value, name)
    if value.startswith("$$"):
        raise UnsupportedDefinition(f"{name}: ResultPath cannot use the context object")


def _template(value, name: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.endswith(".$"):
                _path(item, name)
            else:
                _template(item, name)
    elif isinstance(value, list):
        if any(isinstance(item, dict | list) for item in value):
            raise UnsupportedDefinition(f"{name}: nested structures inside arrays")


def _rule(rule: dict, name: str, top: bool) -> None:
    keys = set(rule) - {"Next"} if top else set(rule)
    if top and "Next" not in rule:
        raise UnsupportedDefinition(f"{name}: choice rule needs Next")
    if not top and "Next" in rule:
        raise UnsupportedDefinition(f"{name}: nested rule cannot have Next")
    if keys <= {"And", "Or"} and len(keys) == 1:
        for nested in rule[next(iter(keys))]:
            _rule(nested, name, top=False)
        return
    if keys == {"Not"}:
        _rule(rule["Not"], name, top=False)
        return
    operators = keys - {"Variable"}
    if "Variable" not in keys or len(operators) != 1:
        raise UnsupportedDefinition(f"{name}: choice rule needs Variable and one operator")
    operator = next(iter(operators))
    if operator not in COMPARISONS and operator not in {"IsPresent", "IsNull"}:
        raise UnsupportedDefinition(f"{name}: unsupported operator {operator}")
    _path(rule["Variable"], name)


# ------------------------------------------------------------------------------- execution
_MISSING = object()


def read_path(path: str, data, context: dict):
    if path == "$":
        return data
    root, rest = (context, path[3:]) if path.startswith("$$.") else (data, path[2:])
    value = root
    for part in rest.split("."):
        if not isinstance(value, dict) or part not in value:
            return _MISSING
        value = value[part]
    return value


def resolve(template, data, context: dict):
    if isinstance(template, dict):
        resolved = {}
        for key, value in template.items():
            if key.endswith(".$"):
                found = read_path(value, data, context)
                if found is _MISSING:
                    raise StatesError(
                        "States.Runtime", f"The JSONPath {value} could not be found in the input"
                    )
                resolved[key[:-2]] = copy.deepcopy(found)
            else:
                resolved[key] = resolve(value, data, context)
        return resolved
    return copy.deepcopy(template)


def apply_result_path(raw_input, result, result_path):
    if result_path is None:
        return copy.deepcopy(raw_input)
    if result_path == "$":
        return result
    target = copy.deepcopy(raw_input)
    if not isinstance(target, dict):
        raise StatesError("States.ResultPathMatchFailure", "state input is not an object")
    cursor = target
    parts = result_path[2:].split(".")
    for part in parts[:-1]:
        child = cursor.setdefault(part, {})
        if not isinstance(child, dict):
            raise StatesError("States.ResultPathMatchFailure", f"{part} is not an object")
        cursor = child
    cursor[parts[-1]] = result
    return target


def _select(data, path, context):
    if path is None:
        return {}
    found = read_path(path, data, context)
    if found is _MISSING:
        raise StatesError("States.Runtime", f"The JSONPath {path} could not be found")
    return found


def _matches(errors: list[str], name: str) -> bool:
    if name in UNCATCHABLE:
        return False
    for error in errors:
        if error == "States.ALL" or error == name:
            return True
        if error == "States.TaskFailed" and name != "States.Timeout":
            return True
    return False


class StateMachine:
    def __init__(
        self,
        definition: dict,
        resources: Mapping[str, Callable[[object], object]],
        *,
        sleep: Callable[[float], None] = time.sleep,
        random: Callable[[], float] = random_module.random,
        clock: Callable[[], float] = time.monotonic,
    ):
        validate(definition, set(resources))
        self.definition = definition
        self.resources = dict(resources)
        self.sleep, self.random, self.clock = sleep, random, clock

    def execute(self, payload, name: str | None = None) -> Execution:
        name = name or uuid.uuid4().hex
        execution = Execution(name, "RUNNING")
        lock = threading.Lock()
        context = {
            "Execution": {
                "Id": f"local:{name}",
                "Name": name,
                "Input": copy.deepcopy(payload),
                "StartTime": datetime.now(UTC).isoformat(),
            },
            "StateMachine": {"Name": "local-scan-pipeline"},
        }
        timeout = self.definition.get("TimeoutSeconds")
        deadline = self.clock() + timeout if timeout else None

        def record(**event):
            with lock:
                execution.history.append(event)

        try:
            execution.output = self._run(self.definition, payload, context, record, deadline)
            execution.status = "SUCCEEDED"
        except StatesError as error:
            execution.status, execution.error, execution.cause = "FAILED", error.name, error.cause
        return execution

    # A sub-machine run returns its output or raises StatesError (a Fail state or uncaught error).
    def _run(self, machine, data, context, record, deadline):
        name = machine["StartAt"]
        while True:
            if deadline is not None and self.clock() > deadline:
                raise StatesError("States.Timeout", "execution timed out")
            state = machine["States"][name]
            record(state=name, event="entered", map_index=_index(context))
            kind = state["Type"]
            if kind == "Succeed":
                effective = _select(data, state.get("InputPath", "$"), context)
                output = _select(effective, state.get("OutputPath", "$"), context)
                record(state=name, event="succeeded", map_index=_index(context))
                return output
            if kind == "Fail":
                cause = state.get("Cause", "")
                if "CausePath" in state:
                    found = read_path(state["CausePath"], data, context)
                    cause = found if isinstance(found, str) else ""
                record(state=name, event="failed", error=state.get("Error"))
                raise StatesError(state.get("Error", "States.Fail"), cause)
            if kind == "Choice":
                effective = _select(data, state.get("InputPath", "$"), context)
                target = next(
                    (r["Next"] for r in state["Choices"] if self._choice(r, effective, context)),
                    state.get("Default"),
                )
                if target is None:
                    raise StatesError("States.NoChoiceMatched", f"{name} matched no rule")
                data = _select(effective, state.get("OutputPath", "$"), context)
                name = target
                continue
            if kind == "Pass":
                effective = _select(data, state.get("InputPath", "$"), context)
                if "Parameters" in state:
                    result = resolve(state["Parameters"], effective, context)
                else:
                    result = copy.deepcopy(state.get("Result", effective))
                data = apply_result_path(data, result, state.get("ResultPath", "$"))
                data = _select(data, state.get("OutputPath", "$"), context)
            else:
                outcome = self._with_handlers(name, state, data, context, record, deadline)
                if outcome[0] == "caught":
                    data, name = outcome[1], outcome[2]
                    continue
                data = outcome[1]
            record(state=name, event="succeeded", map_index=_index(context))
            if state.get("End"):
                return data
            name = state["Next"]

    def _with_handlers(self, name, state, data, context, record, deadline):
        counters = [0] * len(state.get("Retry", []))
        retries = 0
        while True:
            state_context = {**context, "State": {"Name": name, "RetryCount": retries}}
            try:
                return ("ok", self._attempt(state, data, state_context, record, deadline))
            except StatesError as error:
                retrier = next(
                    (
                        (i, r)
                        for i, r in enumerate(state.get("Retry", []))
                        if _matches(r["ErrorEquals"], error.name)
                    ),
                    None,
                )
                if retrier and counters[retrier[0]] < retrier[1].get("MaxAttempts", 3):
                    index, policy = retrier
                    delay = (
                        policy.get("IntervalSeconds", 1)
                        * policy.get("BackoffRate", 2.0) ** (counters[index])
                    )
                    if "MaxDelaySeconds" in policy:
                        delay = min(delay, policy["MaxDelaySeconds"])
                    if policy.get("JitterStrategy") == "FULL":
                        delay *= self.random()
                    counters[index] += 1
                    retries += 1
                    record(
                        state=name,
                        event="retry",
                        error=error.name,
                        attempt=retries,
                        delay=round(delay, 3),
                        map_index=_index(context),
                    )
                    self.sleep(delay)
                    continue
                catcher = next(
                    (c for c in state.get("Catch", []) if _matches(c["ErrorEquals"], error.name)),
                    None,
                )
                if catcher is None:
                    record(state=name, event="failed", error=error.name, map_index=_index(context))
                    raise
                record(state=name, event="caught", error=error.name, map_index=_index(context))
                output = {"Error": error.name, "Cause": error.cause}
                return (
                    "caught",
                    apply_result_path(data, output, catcher.get("ResultPath", "$")),
                    catcher["Next"],
                )

    def _attempt(self, state, data, context, record, deadline):
        effective = _select(data, state.get("InputPath", "$"), context)
        if state["Type"] == "Map":
            result = self._map(state, effective, context, record, deadline)
        else:
            payload = (
                resolve(state["Parameters"], effective, context)
                if "Parameters" in state
                else effective
            )
            result = self._invoke(state, payload)
        if "ResultSelector" in state:
            result = resolve(state["ResultSelector"], result, context)
        output = apply_result_path(data, result, state.get("ResultPath", "$"))
        return _select(output, state.get("OutputPath", "$"), context)

    def _invoke(self, state, payload):
        function = self.resources[PLACEHOLDER.fullmatch(state["Resource"])[1]]
        encoded = json.dumps(payload)
        if len(encoded.encode()) > PAYLOAD_LIMIT:
            raise StatesError("States.DataLimitExceeded", "task input exceeds 256 KiB")
        pool = ThreadPoolExecutor(max_workers=1)
        future = pool.submit(function, json.loads(encoded))
        try:
            result = future.result(timeout=state.get("TimeoutSeconds"))
        except FutureTimeout:
            raise StatesError("States.Timeout", "task timed out") from None
        except Exception as error:
            # Lambda reports the exception class as the error name and the message as the cause.
            error_name = type(error).__name__
            raise StatesError(
                error_name, json.dumps({"errorMessage": str(error), "errorType": error_name})
            ) from None
        finally:
            pool.shutdown(wait=False)
        encoded = json.dumps(result)
        if len(encoded.encode()) > PAYLOAD_LIMIT:
            raise StatesError("States.DataLimitExceeded", "task output exceeds 256 KiB")
        return json.loads(encoded)

    def _map(self, state, data, context, record, deadline):
        items = _select(data, state.get("ItemsPath", "$"), context)
        if not isinstance(items, list):
            raise StatesError("States.Runtime", "ItemsPath must select an array")
        processor = state["ItemProcessor"]

        def iteration(index, item):
            item_context = {**context, "Map": {"Item": {"Index": index, "Value": item}}}
            item_context.pop("State", None)
            payload = (
                resolve(state["ItemSelector"], data, item_context)
                if "ItemSelector" in state
                else copy.deepcopy(item)
            )
            return self._run(processor, payload, item_context, record, deadline)

        workers = max(1, min(state.get("MaxConcurrency", 0) or len(items) or 1, len(items) or 1))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(iteration, i, item) for i, item in enumerate(items)]
        results, failure = [], None
        for future in futures:
            try:
                results.append(future.result())
            except StatesError as error:
                failure = failure or error
        if failure:
            raise failure
        return results

    def _choice(self, rule, data, context) -> bool:
        if "And" in rule:
            return all(self._choice(r, data, context) for r in rule["And"])
        if "Or" in rule:
            return any(self._choice(r, data, context) for r in rule["Or"])
        if "Not" in rule:
            return not self._choice(rule["Not"], data, context)
        value = read_path(rule["Variable"], data, context)
        if "IsPresent" in rule:
            return (value is not _MISSING) == rule["IsPresent"]
        if value is _MISSING:
            raise StatesError("States.Runtime", f"Invalid path {rule['Variable']}")
        if "IsNull" in rule:
            return (value is None) == rule["IsNull"]
        operator = next(k for k in rule if k in COMPARISONS)
        return COMPARISONS[operator](value, rule[operator])


def _index(context: dict):
    return context.get("Map", {}).get("Item", {}).get("Index")

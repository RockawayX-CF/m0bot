#!/usr/bin/env python3
"""Repository-wide structured logging configuration."""

from __future__ import annotations

import json
import math
import os
import pwd
import re
import signal
import sys
import time
import traceback
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger

DEFAULT_LOG_ROOT = Path('/var/log/trading')
REPOSITORY_SLUG = 'underquant_agent'
IDENTIFIER_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}$')
SCREEN_STY_RE = re.compile(r'^[0-9]+\.([a-z0-9][a-z0-9._-]{0,63})$')
SUPPORTED_LOG_MODES = frozenset({'console', 'jsonl', 'journal'})
MAX_EVENT_BYTES = 64 * 1024
SEGMENT_SIZE_BYTES = 100 * 1024 * 1024
INSTANCE_SIZE_BYTES = 1024 * 1024 * 1024
RETENTION_SECONDS = 72 * 60 * 60
FILE_RATE_LIMIT_PER_SECOND = 200.0
FILE_RATE_LIMIT_BURST = 1000.0
ANSI_RESET = '\x1b[0m'
ANSI_GREEN = '\x1b[32m'
ANSI_CYAN = '\x1b[36m'
ANSI_LEVEL_COLORS = {
    'TRACE': '\x1b[36m',
    'DEBUG': '\x1b[34m',
    'INFO': '\x1b[1m',
    'SUCCESS': '\x1b[32m\x1b[1m',
    'WARNING': '\x1b[33m\x1b[1m',
    'ERROR': '\x1b[31m\x1b[1m',
    'CRITICAL': '\x1b[41m\x1b[37m\x1b[1m',
}
AUTHORIZATION_CREDENTIAL_RE = re.compile(
    r'(?i)(\bauthorization\b\s*[:=]\s*)(["\']?)'
    r'(?:bearer|basic)\s+([^,\s"\'}]+)\2'
)
SENSITIVE_VALUE_RE = re.compile(
    r'(?i)(\b(?:signature|api[_-]?key|apikey|secret(?:_key)?|password|token|'
    r'access_token|authorization|cookie)\b\s*[:=]\s*)(["\']?)([^,\s&"\'}]+)\2'
)
SENSITIVE_KEY_NAMES = frozenset(
    {
        'apikey',
        'authorization',
        'cookie',
        'credentials',
        'databaseurl',
        'dsn',
        'password',
        'passwd',
        'privatekey',
        'secret',
        'secretkey',
        'setcookie',
        'signature',
        'token',
        'accesstoken',
    }
)
RESERVED_EXTRA_FIELDS = frozenset(
    {
        'event',
        'script_owner',
        'repository',
        'service_name',
        'runtime',
        'instance',
        'run_id',
        'pid',
        'screen_name',
        'module',
        'function',
        'line',
        'message',
        'level',
        'ts',
    }
)


def _validate_identifier(name: str, value: str) -> str:
    normalized = value.strip().lower()
    if not IDENTIFIER_RE.fullmatch(normalized):
        raise ValueError(
            f'{name} must match {IDENTIFIER_RE.pattern!r}; got {value!r}'
        )
    return normalized


def _validate_script_owner(value: str) -> str:
    script_owner = value.strip()
    if not IDENTIFIER_RE.fullmatch(script_owner):
        raise ValueError(
            f'SCRIPT_OWNER must match {IDENTIFIER_RE.pattern!r}; got {value!r}'
        )
    return script_owner


def resolve_script_owner() -> str:
    raw_script_owner = os.getenv('SCRIPT_OWNER')
    if raw_script_owner is None or not raw_script_owner.strip():
        raise ValueError('SCRIPT_OWNER is required')
    return _validate_script_owner(raw_script_owner)


def _screen_name_from_environment() -> str | None:
    """Return the bounded GNU screen name inherited through ``STY``."""
    raw_sty = os.getenv('STY')
    if raw_sty is None:
        return None
    matched = SCREEN_STY_RE.fullmatch(raw_sty)
    return matched.group(1) if matched is not None else None


def _fallback_identifier(value: object, fallback: str) -> str:
    try:
        return _validate_identifier('fallback identity', str(value))
    except Exception:
        return fallback


def _redact_sensitive_text(value: str) -> str:
    value = AUTHORIZATION_CREDENTIAL_RE.sub(r'\1[REDACTED]', value)
    return SENSITIVE_VALUE_RE.sub(r'\1[REDACTED]', value)


def _is_sensitive_key(value: object) -> bool:
    try:
        normalized = re.sub(r'[^a-z0-9]', '', str(value).lower())
    except Exception:
        return False
    return (
        normalized in SENSITIVE_KEY_NAMES
        or normalized.endswith('password')
        or normalized.endswith('secret')
        or normalized.endswith('token')
        or normalized.endswith('apikey')
        or normalized.endswith('privatekey')
    )


def _json_safe(
    value: Any,
    *,
    field_name: object | None = None,
    seen: set[int] | None = None,
    depth: int = 0,
) -> Any:
    if field_name is not None and _is_sensitive_key(field_name):
        return '[REDACTED]'
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return _redact_sensitive_text(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if depth >= 8:
        return '<maximum serialization depth reached>'

    seen = seen or set()
    value_id = id(value)
    if value_id in seen:
        return '<recursive value>'

    if isinstance(value, dict):
        seen.add(value_id)
        try:
            return {
                str(key): _json_safe(
                    item,
                    field_name=key,
                    seen=seen,
                    depth=depth + 1,
                )
                for key, item in value.items()
            }
        finally:
            seen.remove(value_id)
    if isinstance(value, (list, tuple, set, frozenset)):
        seen.add(value_id)
        try:
            return [
                _json_safe(item, seen=seen, depth=depth + 1)
                for item in value
            ]
        finally:
            seen.remove(value_id)
    try:
        return _redact_sensitive_text(str(value))
    except Exception:
        return f'<unserializable {type(value).__name__}>'


def _event_from_record(record: dict[str, Any]) -> dict[str, Any]:
    extra = record['extra']
    timestamp = record['time'].astimezone(timezone.utc)
    event = {
        'ts': timestamp.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
        'level': record['level'].name,
        'script_owner': extra['script_owner'],
        'repository': extra['repository'],
        'service_name': extra['service_name'],
        'runtime': extra['runtime'],
        'instance': extra['instance'],
        'run_id': extra['run_id'],
        'event': extra.get('event', 'log_message'),
        'message': _redact_sensitive_text(record['message']),
        'pid': record['process'].id,
        'module': record['name'],
        'function': record['function'],
        'line': record['line'],
    }
    if 'screen_name' in extra:
        event['screen_name'] = extra['screen_name']

    for key, value in extra.items():
        if key not in RESERVED_EXTRA_FIELDS:
            event[key] = _json_safe(value, field_name=key)

    exception = record['exception']
    if exception is not None:
        event['error_type'] = exception.type.__name__
        event['error'] = _redact_sensitive_text(str(exception.value))
        event['exception'] = _redact_sensitive_text(
            ''.join(
                traceback.format_exception(
                    exception.type,
                    exception.value,
                    exception.traceback,
                )
            )
        )
    return event


def _escape_loguru_format(value: str) -> str:
    return (
        value
        .replace('<', r'\<')
        .replace('{', '{{')
        .replace('}', '}}')
    )


def _truncate_utf8(value: str, maximum_bytes: int) -> str:
    encoded = value.encode('utf-8')
    if len(encoded) <= maximum_bytes:
        return value
    suffix = '…[truncated]'
    available = max(0, maximum_bytes - len(suffix.encode('utf-8')))
    return encoded[:available].decode('utf-8', errors='ignore') + suffix


def _serialize_bounded_event(record: dict[str, Any]) -> str:
    event = _event_from_record(record)
    line = json.dumps(
        event,
        ensure_ascii=False,
        separators=(',', ':'),
        allow_nan=False,
    )
    original_size = len(line.encode('utf-8'))
    if original_size + 1 > MAX_EVENT_BYTES:
        required_fields = {
            key: event[key]
            for key in (
                'ts', 'level', 'script_owner', 'repository', 'service_name',
                'runtime', 'instance', 'run_id', 'event', 'message', 'pid',
                'screen_name', 'module', 'function', 'line', 'error_type',
                'error',
            )
            if key in event
        }
        required_fields['message'] = _truncate_utf8(
            str(required_fields['message']),
            24 * 1024,
        )
        if 'error' in required_fields:
            required_fields['error'] = _truncate_utf8(
                str(required_fields['error']),
                16 * 1024,
            )
        required_fields['log_truncated'] = True
        required_fields['original_size_bytes'] = original_size
        line = json.dumps(
            required_fields,
            ensure_ascii=False,
            separators=(',', ':'),
            allow_nan=False,
        )
        if len(line.encode('utf-8')) + 1 > MAX_EVENT_BYTES:
            required_fields['message'] = _truncate_utf8(
                str(required_fields['message']),
                8 * 1024,
            )
            required_fields.pop('error', None)
            line = json.dumps(
                required_fields,
                ensure_ascii=False,
                separators=(',', ':'),
                allow_nan=False,
            )
    return line


def _json_formatter(record: dict[str, Any]) -> str:
    line = _serialize_bounded_event(record)
    line = line.replace('<', r'\u003c')
    return _escape_loguru_format(line) + '\n'


def _render_console(record: dict[str, Any], *, colorize: bool) -> str:
    event = _event_from_record(record)
    timestamp = record['time'].astimezone(timezone.utc).strftime(
        '%Y-%m-%d %H:%M:%S.%f'
    )[:-3]
    if colorize:
        level_color = ANSI_LEVEL_COLORS.get(event['level'], '')
        line = (
            f"{ANSI_GREEN}{timestamp}{ANSI_RESET} | "
            f"{level_color}{event['level']:<8}{ANSI_RESET} | "
            f"{ANSI_CYAN}{event['module']}{ANSI_RESET}:"
            f"{ANSI_CYAN}{event['function']}{ANSI_RESET}:"
            f"{ANSI_CYAN}{event['line']}{ANSI_RESET} - "
            f"{level_color}{event['message']}{ANSI_RESET}"
        )
    else:
        line = (
            f"{timestamp} | {event['level']:<8} | "
            f"{event['module']}:{event['function']}:{event['line']} - "
            f"{event['message']}"
        )
    if 'exception' in event:
        exception = event['exception'].rstrip()
        if colorize:
            level_color = ANSI_LEVEL_COLORS.get(event['level'], '')
            line += f"\n{level_color}{exception}{ANSI_RESET}"
        else:
            line += f'\n{exception}'
    return line + '\n'


def emit_logging_initialization_failure(
    *,
    repository: str,
    service_name: str,
    runtime: str,
    log_level: str,
    error: Exception,
    script_owner: str | None = None,
    instance: str | None = None,
) -> None:
    """Emit a bounded synchronous fallback when identity bootstrap fails."""
    event = {
        'ts': datetime.now(timezone.utc).isoformat(
            timespec='microseconds'
        ).replace('+00:00', 'Z'),
        'level': 'ERROR',
        'script_owner': _fallback_identifier(
            script_owner or os.getenv('SCRIPT_OWNER', ''),
            'unknown',
        ),
        'repository': _fallback_identifier(repository, 'unknown'),
        'service_name': _fallback_identifier(service_name, 'unknown'),
        'runtime': _fallback_identifier(runtime, 'unknown'),
        'instance': _fallback_identifier(
            instance or os.getenv('LOG_INSTANCE', ''),
            'unknown',
        ),
        'run_id': str(uuid.uuid4()),
        'event': 'logging_initialization_failed',
        'message': 'Logging initialization failed; using stderr fallback',
        'pid': os.getpid(),
        'configured_log_level': log_level,
        'error_type': type(error).__name__,
        'error': _truncate_utf8(
            _redact_sensitive_text(str(error)),
            8 * 1024,
        ),
    }
    screen_name = _screen_name_from_environment()
    if screen_name is not None:
        event['screen_name'] = screen_name
    line = json.dumps(
        event,
        ensure_ascii=False,
        separators=(',', ':'),
        allow_nan=False,
    )
    if len(line.encode('utf-8')) + 1 > MAX_EVENT_BYTES:
        event['error'] = '<initialization error truncated>'
        line = json.dumps(
            event,
            ensure_ascii=False,
            separators=(',', ':'),
            allow_nan=False,
        )
    sys.stderr.write(line + '\n')
    sys.stderr.flush()


def _add_json_stderr_fallback(log_level: str, error: Exception) -> None:
    logger.remove()
    logger.add(
        sys.stderr,
        level=log_level,
        enqueue=True,
        format=_json_formatter,
        backtrace=False,
        diagnose=False,
    )
    logger.bind(
        event='logging_initialization_failed',
        error_type=type(error).__name__,
        error=str(error),
    ).error('JSONL logging could not be initialized; using JSON on stderr')


def _prepare_log_directory(
    linux_user: str,
    service_name: str,
    runtime: str,
    instance: str,
) -> Path:
    user_root = DEFAULT_LOG_ROOT / linux_user
    if not user_root.is_dir():
        raise FileNotFoundError(
            f'Deployment must provision logging directory {user_root}'
        )

    directory = user_root
    for component in (service_name, runtime, instance):
        directory = directory / component
        directory.mkdir(mode=0o750, exist_ok=True)
        directory.chmod(0o750)
    return directory


def _env_bool(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    normalized = raw_value.strip().lower()
    if normalized in {'1', 'true', 'yes', 'on'}:
        return True
    if normalized in {'0', 'false', 'no', 'off'}:
        return False
    raise ValueError(f'{name} must be a boolean value; got {raw_value!r}')


class SigtermReceived(KeyboardInterrupt):
    """Raised in the main thread when SIGTERM requests a graceful shutdown."""


def install_sigterm_handler() -> Any:
    previous_handler = signal.getsignal(signal.SIGTERM)

    def _handle_sigterm(signum: int, frame: Any) -> None:
        del signum, frame
        raise SigtermReceived()

    signal.signal(signal.SIGTERM, _handle_sigterm)
    return previous_handler


def restore_sigterm_handler(previous_handler: Any) -> None:
    signal.signal(signal.SIGTERM, previous_handler)


def shutdown_logger() -> None:
    """Flush queued records and close all configured sinks."""
    logger.complete()
    logger.remove()


class HumanConsoleSink:
    def __init__(self, stream: Any, *, colorize: bool) -> None:
        self.stream = stream
        self.colorize = colorize

    def write(self, message: Any) -> None:
        self.stream.write(
            _render_console(message.record, colorize=self.colorize)
        )
        self.stream.flush()


class SegmentedJsonlSink:
    """Bounded JSONL sink with immutable, monotonically numbered segments."""

    def __init__(self, directory: Path, run_id: str) -> None:
        self.directory = directory
        self.run_id = run_id
        self.segment = 0
        self.path: Path
        self.file: Any
        self.size_bytes = 0
        self.tokens = FILE_RATE_LIMIT_BURST
        self.last_token_time = time.monotonic()
        self.suppressed_count = 0
        self.last_suppressed_event: dict[str, Any] | None = None
        self.last_summary_time = self.last_token_time
        self._open_segment()
        self._enforce_retention()

    def _open_segment(self) -> None:
        self.path = self.directory / f'{self.run_id}.{self.segment:04d}.jsonl'
        file_descriptor = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o640,
        )
        self.file = os.fdopen(file_descriptor, 'wb', buffering=0)
        self.path.chmod(0o640)
        self.size_bytes = 0

    def _rotate(self) -> None:
        self.file.close()
        self.segment += 1
        self._open_segment()
        self._enforce_retention()

    def _write_bytes(self, encoded: bytes) -> None:
        if self.size_bytes and self.size_bytes + len(encoded) > SEGMENT_SIZE_BYTES:
            self._rotate()
        self.file.write(encoded)
        self.size_bytes += len(encoded)

    def _suppression_summary(self) -> bytes | None:
        if not self.suppressed_count or self.last_suppressed_event is None:
            return None
        source = self.last_suppressed_event
        summary = {
            'ts': datetime.now(timezone.utc).isoformat(
                timespec='microseconds'
            ).replace('+00:00', 'Z'),
            'level': 'WARNING',
            'script_owner': source['script_owner'],
            'repository': source['repository'],
            'service_name': source['service_name'],
            'runtime': source['runtime'],
            'instance': source['instance'],
            'run_id': source['run_id'],
            'event': 'log_events_suppressed',
            'message': f'Suppressed {self.suppressed_count} log events due to rate limit',
            'pid': source.get('pid'),
            'suppressed_count': self.suppressed_count,
            'suppressed_event': source.get('event'),
        }
        if 'screen_name' in source:
            summary['screen_name'] = source['screen_name']
        self.suppressed_count = 0
        self.last_suppressed_event = None
        return (
            json.dumps(summary, separators=(',', ':'), ensure_ascii=False)
            + '\n'
        ).encode('utf-8')

    def _emit_suppression_summary(self) -> None:
        encoded = self._suppression_summary()
        if encoded is not None:
            self._write_bytes(encoded)
            self.last_summary_time = time.monotonic()

    def _enforce_retention(self) -> None:
        now = time.time()
        files = [
            path
            for path in self.directory.glob('*.jsonl')
            if path != self.path and path.is_file()
        ]
        for path in files:
            try:
                if now - path.stat().st_mtime > RETENTION_SECONDS:
                    path.unlink()
            except FileNotFoundError:
                continue

        files = sorted(
            (
                path
                for path in self.directory.glob('*.jsonl')
                if path != self.path and path.is_file()
            ),
            key=lambda path: path.stat().st_mtime,
        )
        total_size = self.size_bytes + sum(path.stat().st_size for path in files)
        for path in files:
            if total_size <= INSTANCE_SIZE_BYTES:
                break
            try:
                size = path.stat().st_size
                path.unlink()
                total_size -= size
            except FileNotFoundError:
                continue

    def write(self, message: Any) -> None:
        line = str(message)
        now = time.monotonic()
        elapsed = max(0.0, now - self.last_token_time)
        self.tokens = min(
            FILE_RATE_LIMIT_BURST,
            self.tokens + elapsed * FILE_RATE_LIMIT_PER_SECOND,
        )
        self.last_token_time = now

        if self.tokens < 1.0:
            self.suppressed_count += 1
            try:
                self.last_suppressed_event = json.loads(line)
            except (TypeError, ValueError):
                self.last_suppressed_event = None
            if now - self.last_summary_time >= 10.0:
                self._emit_suppression_summary()
            return

        self.tokens -= 1.0
        self._write_bytes(line.encode('utf-8'))

    def stop(self) -> None:
        self._emit_suppression_summary()
        self.file.close()
        self._enforce_retention()


def setup_logger(
    runtime: str,
    log_level: str = 'INFO',
    *,
    repository: str,
    service_name: str | None = None,
    script_owner: str,
    console_stream: Any | None = None,
):
    """Configure console, screen JSONL, or journald logging from environment.

    ``console_stream`` defaults to stdout. Stdio protocol processes such as MCP
    servers pass stderr so human diagnostics cannot corrupt protocol frames.
    """
    console_stream = sys.stdout if console_stream is None else console_stream
    try:
        repository = _validate_identifier('repository', repository)
        mode = (os.getenv('LOG_MODE', 'console') or 'console').strip().lower()
        if mode not in SUPPORTED_LOG_MODES:
            raise ValueError(
                f'LOG_MODE must be one of {sorted(SUPPORTED_LOG_MODES)}; got {mode!r}'
            )
        raw_service_name = service_name or os.getenv('LOG_SERVICE_NAME')
        if not raw_service_name:
            raise ValueError('LOG_SERVICE_NAME or service_name is required')
        service_name = _validate_identifier('service_name', raw_service_name)
        runtime = _validate_identifier('runtime', runtime)
        script_owner = _validate_script_owner(script_owner)
        raw_instance = os.getenv('LOG_INSTANCE')
        if mode != 'console' and not raw_instance:
            raise ValueError(f'LOG_INSTANCE is required when LOG_MODE={mode}')
        instance = _validate_identifier('instance', raw_instance or 'local')
    except Exception as error:
        emit_logging_initialization_failure(
            repository=str(repository),
            service_name=str(service_name or os.getenv('LOG_SERVICE_NAME', 'unknown')),
            runtime=str(runtime),
            log_level=log_level,
            error=error,
            script_owner=script_owner,
            instance=os.getenv('LOG_INSTANCE'),
        )
        raise
    run_id = str(uuid.uuid4())
    identity = {
        'script_owner': script_owner,
        'repository': repository,
        'service_name': service_name,
        'runtime': runtime,
        'instance': instance,
        'run_id': run_id,
    }
    screen_name = _screen_name_from_environment()
    if screen_name is not None:
        identity['screen_name'] = screen_name

    logger.remove()
    logger.configure(
        extra=identity,
        patcher=lambda record: record['extra'].update(identity),
    )

    common_options = {
        'level': log_level,
        'enqueue': True,
        'backtrace': False,
        'diagnose': False,
    }
    console_color = _env_bool('LOG_CONSOLE_COLOR', True)
    if mode == 'console':
        logger.add(
            HumanConsoleSink(console_stream, colorize=console_color),
            colorize=False,
            format='{message}',
            **common_options,
        )
    elif mode == 'journal':
        logger.add(
            console_stream,
            colorize=False,
            format=_json_formatter,
            **common_options,
        )
    else:
        linux_user = pwd.getpwuid(os.getuid()).pw_name
        try:
            log_directory = _prepare_log_directory(
                linux_user,
                service_name,
                runtime,
                instance,
            )
            file_sink = SegmentedJsonlSink(log_directory, run_id)
            logger.add(
                file_sink,
                format=_json_formatter,
                **common_options,
            )
            if _env_bool('LOG_CONSOLE', True):
                logger.add(
                    HumanConsoleSink(console_stream, colorize=console_color),
                    colorize=False,
                    format='{message}',
                    **common_options,
                )
        except Exception as error:
            _add_json_stderr_fallback(log_level, error)

    logger.bind(event='logging_configured', log_mode=mode).info(
        f'Logging configured in {mode} mode'
    )
    return logger

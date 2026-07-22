"""Единый владелец рабочего контура контроллера версии 2."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass
class ControllerApplicationV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class ControllerApplicationV2:
    """Связывает health, рабочую службу и частный командный сокет.

    Объект создаётся только процессом, которому принадлежит health-сокет.
    Каждый частный вызов получает область конкретного корневого сеанса до
    обращения к четырём операциям рабочего сервера.
    """

    def __init__(
        self,
        *,
        health_runtime: Any,
        provider: Any,
        production: Any,
        command_server: Any,
    ) -> None:
        self.health_runtime = health_runtime
        self.provider = provider
        self.production = production
        self.command_server = command_server
        self._lifecycle_lock = threading.RLock()
        self._stopped = threading.Event()
        self._serve_started = threading.Event()
        self._serve_error: BaseException | None = None
        self._closed = False
        self._thread: threading.Thread | None = None

    @classmethod
    def start(
        cls,
        *,
        health_runtime: Any,
        provider: Any,
        production_factory: Callable[[Any], Any],
        command_server_factory: Callable[
            [Callable[[str, str, dict[str, Any]], Mapping[str, Any]]], Any
        ],
        lifecycle_handler: Callable[[Mapping[str, object]], Mapping[str, object]]
        | None = None,
        startup_timeout_seconds: float = 2.0,
    ) -> "ControllerApplicationV2":
        if getattr(health_runtime, "owns_runtime", None) is not True:
            raise ControllerApplicationV2Error(
                "CONTROLLER_OWNERSHIP_REQUIRED",
                "полный контроллер может запустить только владелец health-сокета",
            )
        if not callable(getattr(provider, "bind", None)):
            raise TypeError("provider must provide bind()")
        if not callable(production_factory):
            raise TypeError("production_factory must be callable")
        if not callable(command_server_factory):
            raise TypeError("command_server_factory must be callable")
        if lifecycle_handler is not None and not callable(lifecycle_handler):
            raise TypeError("lifecycle_handler must be callable")
        if (
            not isinstance(startup_timeout_seconds, (int, float))
            or isinstance(startup_timeout_seconds, bool)
            or not 0 < float(startup_timeout_seconds) <= 10
        ):
            raise ValueError("startup_timeout_seconds must be in (0, 10]")

        production: Any | None = None
        command_server: Any | None = None
        try:
            production = production_factory(provider)
            tool_server = getattr(production, "server", None)
            if not callable(getattr(tool_server, "call_tool", None)):
                raise TypeError("production server must provide call_tool()")

            def handle(
                shell_session_id: str,
                method: str,
                arguments: dict[str, Any],
            ) -> Mapping[str, Any]:
                with provider.bind(shell_session_id):
                    # Проверяем принадлежность и свежесть корневого хода до
                    # передачи команды рабочему серверу. Сам сервер повторно
                    # читает контекст в точке применения, что закрывает окно
                    # между проверкой области и изменением состояния.
                    load_context = getattr(provider, "request_context", None)
                    if callable(load_context):
                        load_context()
                    return tool_server.call_tool(method, arguments)

            command_server = command_server_factory(handle)
            for method in ("start", "wait_until_ready", "serve_forever", "close"):
                if not callable(getattr(command_server, method, None)):
                    raise TypeError(f"command server must provide {method}()")
            application = cls(
                health_runtime=health_runtime,
                provider=provider,
                production=production,
                command_server=command_server,
            )
            if lifecycle_handler is not None:
                bind_lifecycle = getattr(
                    health_runtime, "bind_lifecycle_handler", None
                )
                if not callable(bind_lifecycle):
                    raise ControllerApplicationV2Error(
                        "LIFECYCLE_CHANNEL_UNAVAILABLE",
                        "health runtime не предоставляет управляющий канал",
                    )

                def observe_lifecycle_response(
                    request: Mapping[str, object],
                    response: Mapping[str, object],
                ) -> None:
                    payload = response.get("payload")
                    if (
                        request.get("method") == "shutdown"
                        and response.get("responseKind") == "SUCCESS"
                        and isinstance(payload, Mapping)
                        and payload.get("status") == "SHUTDOWN_COMMITTED"
                    ):
                        application.request_stop()

                bind_lifecycle(
                    lifecycle_handler,
                    response_observer=observe_lifecycle_response,
                )
            command_server.start()
            if not command_server.wait_until_ready(float(startup_timeout_seconds)):
                raise ControllerApplicationV2Error(
                    "COMMAND_SERVER_NOT_READY",
                    "частный командный сокет не стал готов за отведённое время",
                )
            application._thread = threading.Thread(
                target=application._serve_command,
                name="codex-smart-command-v2-main",
                daemon=True,
            )
            application._thread.start()
            if not application._serve_started.wait(float(startup_timeout_seconds)):
                raise ControllerApplicationV2Error(
                    "COMMAND_SERVER_NOT_READY",
                    "цикл командного сервера не запустился",
                )
            return application
        except BaseException:
            if command_server is not None:
                try:
                    command_server.close()
                except BaseException:
                    pass
            if production is not None:
                try:
                    production.close()
                except BaseException:
                    pass
            try:
                health_runtime.close()
            except BaseException:
                pass
            raise

    @property
    def ready(self) -> bool:
        return (
            not self._closed
            and self._serve_started.is_set()
            and self._serve_error is None
            and bool(self.command_server.wait_until_ready(0))
        )

    def wait(self, *, timeout_seconds: float | None = None) -> bool:
        if timeout_seconds is not None and (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 <= float(timeout_seconds) <= 3600
        ):
            raise ValueError("timeout_seconds must be in [0, 3600]")
        completed = self._stopped.wait(
            None if timeout_seconds is None else float(timeout_seconds)
        )
        error = self._serve_error
        if error is not None:
            raise ControllerApplicationV2Error(
                "COMMAND_SERVER_FAILED",
                str(error)[:1024] or type(error).__name__,
            ) from error
        return completed

    def request_stop(self) -> None:
        self._stopped.set()
        self.command_server.close()

    def close(self) -> None:
        with self._lifecycle_lock:
            if self._closed:
                return
            self._closed = True
            self._stopped.set()
            try:
                self.command_server.close()
            finally:
                thread = self._thread
                if thread is not None and thread is not threading.current_thread():
                    thread.join(timeout=2.0)
                try:
                    self.production.close()
                finally:
                    self.health_runtime.close()

    def _serve_command(self) -> None:
        self._serve_started.set()
        try:
            self.command_server.serve_forever()
        except BaseException as exc:
            self._serve_error = exc
        finally:
            self._stopped.set()


__all__ = ["ControllerApplicationV2", "ControllerApplicationV2Error"]

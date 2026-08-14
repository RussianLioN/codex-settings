"""Bundled controller service entrypoint."""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = PLUGIN_ROOT / "src"
_START_ERROR_LIMIT_BYTES = 4096
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from codex_smart_subagents.daemon import ControllerProcessConfig  # noqa: E402
from codex_smart_subagents.production import (  # noqa: E402
    build_production_runtime,
    install_signal_handlers,
)
from codex_smart_subagents.controller_entrypoint_v2 import (  # noqa: E402
    load_controller_entrypoint_config_v2,
    load_controller_policy_bundle_v2,
    start_full_controller_v2,
)
from codex_smart_subagents.candidate_controller_v2 import (  # noqa: E402
    load_candidate_controller_config_v2,
    serve_candidate_controller_v2,
)
from codex_smart_subagents.candidate_ready_channel_v2 import (  # noqa: E402
    await_candidate_ownership_gate_v2,
    load_candidate_ready_bootstrap_v2,
)


def _build_dispatcher_factory_v2(
    *,
    config: Any,
    policy_bundle: Any,
    launch_decision: Any,
) -> Any:
    from codex_smart_subagents.production_composition_v2 import (
        build_default_production_dispatcher_dependencies_v2,
    )
    from codex_smart_subagents.production_dispatcher_v2 import (
        build_production_dispatcher_factory_v2,
    )

    dependencies = build_default_production_dispatcher_dependencies_v2(
        config=config,
        policy_bundle=policy_bundle,
        launch_decision=launch_decision,
    )
    return build_production_dispatcher_factory_v2(dependencies)


def install_v2_signal_handlers(application: Any) -> None:
    """Завершает все три службы одного контроллера по штатному сигналу."""

    def request_stop(_signum: int, _frame: object) -> None:
        application.request_stop()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)


def _render_start_error(exc: BaseException) -> str:
    code = str(getattr(exc, "code", "START_FAILED"))[:128]
    message = str(getattr(exc, "message", str(exc)))
    rendered = f"codex-smart-subagents-controller: {code}: {message}\n"
    encoded = rendered.encode("utf-8", errors="replace")
    if len(encoded) <= _START_ERROR_LIMIT_BYTES:
        return rendered
    suffix = b"...\n"
    prefix = encoded[: _START_ERROR_LIMIT_BYTES - len(suffix)]
    return prefix.decode("utf-8", errors="ignore") + suffix.decode("ascii")


def serve_v2(
    environment: Mapping[str, str],
    *,
    config_loader: Callable[..., Any] = load_controller_entrypoint_config_v2,
    policy_loader: Callable[..., Any] = load_controller_policy_bundle_v2,
    dispatcher_factory_builder: Callable[..., Any] = _build_dispatcher_factory_v2,
    starter: Callable[..., Any] = start_full_controller_v2,
    signal_installer: Callable[[Any], None] = install_v2_signal_handlers,
) -> None:
    """Поднимает полный v2 и удерживает процесс до штатной остановки."""

    config = config_loader(plugin_root=PLUGIN_ROOT, environment=environment)
    policy_bundle = policy_loader(
        source_root=config.source_root,
        plugin_root=config.plugin_root,
    )
    application = starter(
        config,
        policy_bundle=policy_bundle,
        dispatcher_factory=None,
        dispatcher_factory_builder=dispatcher_factory_builder,
    )
    try:
        signal_installer(application)
        application.wait()
    finally:
        application.close()


def serve_candidate_v2(
    environment: MutableMapping[str, str],
    *,
    config_loader: Callable[..., Any] = load_candidate_controller_config_v2,
    ready_bootstrap_loader: Callable[..., Any] = load_candidate_ready_bootstrap_v2,
    ownership_gate_waiter: Callable[
        [MutableMapping[str, str]], None
    ] = await_candidate_ownership_gate_v2,
    server: Callable[..., Any] = serve_candidate_controller_v2,
) -> None:
    """Запускает отдельный закрытый режим подготовленного кандидата."""

    config = config_loader(plugin_root=PLUGIN_ROOT, environment=environment)
    ready_bootstrap = ready_bootstrap_loader(
        codex_home=config.codex_home,
        environment=environment,
        operation_id=config.operation_id,
        controller_start_id=config.controller_start_id,
    )
    if not callable(ownership_gate_waiter):
        raise TypeError("ownership_gate_waiter must be callable")
    ownership_gate_waiter(environment)
    server(
        config,
        ready_bootstrap=ready_bootstrap,
        dispatcher_factory_builder=_build_dispatcher_factory_v2,
        signal_installer=install_v2_signal_handlers,
    )


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--serve-v2"]:
        try:
            serve_v2(os.environ)
        except Exception as exc:
            sys.stderr.write(_render_start_error(exc))
            return 1
        return 0
    if arguments == ["--serve-candidate-v2"]:
        try:
            serve_candidate_v2(os.environ)
        except Exception as exc:
            sys.stderr.write(_render_start_error(exc))
            return 1
        return 0
    if arguments != ["--serve"]:
        sys.stderr.write(
            "codex-smart-subagents-controller: "
            "поддерживаются только --serve, --serve-v2 и --serve-candidate-v2\n"
        )
        return 2
    try:
        config = ControllerProcessConfig.from_environ(
            os.environ,
            plugin_root=PLUGIN_ROOT,
        )
        runtime = build_production_runtime(config)
        install_signal_handlers(runtime)
        runtime.serve_forever()
    except Exception as exc:
        sys.stderr.write(_render_start_error(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

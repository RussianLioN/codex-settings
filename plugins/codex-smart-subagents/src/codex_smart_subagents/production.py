"""Production composition for the local adaptive-subagent controller."""

from __future__ import annotations

import json
import os
import platform
import signal
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .catalog import Catalog
from .child_runner import ChildRunner, PermissionProfileDefinition
from .controller import ControllerServer
from .daemon import ControllerProcessConfig, ControllerStartError
from .execution import ExecutionEngine
from .identity import sha256_text
from .launcher import probe_codex_version
from .live_canary import (
    CanaryProbeTargets,
    FileManagedConfigInspector,
    LivePermissionCanary,
)
from .permissions import PermissionGate
from .resource_gate import ResourceGate
from .runtime_executor import (
    READER_RESULT_SCHEMA,
    RuntimeExecutorConfig,
    RuntimeNodeExecutor,
)
from .service import SmartService
from .snapshot import SnapshotBuilder, SnapshotLimits, SnapshotResult
from .store import SmartStore
from .worker import ChildWorkRequest, ChildWorker


class ProductionRuntime:
    def __init__(
        self,
        *,
        server: ControllerServer,
        store: SmartStore,
        engine: ExecutionEngine,
        route_workers: int,
        stop_event: threading.Event | None = None,
    ) -> None:
        if route_workers <= 0:
            raise ValueError("route_workers must be positive")
        self.server = server
        self.store = store
        self.engine = engine
        self.route_workers = route_workers
        self.stop_event = stop_event or threading.Event()
        self._threads: list[threading.Thread] = []
        self._errors: list[BaseException] = []
        self._error_lock = threading.Lock()
        self._closed = False

    def serve_forever(self) -> None:
        recovered = self.store.recover_stale_leases(
            now=datetime.now(timezone.utc)
        )
        for route_id in recovered:
            self.store.requeue_recovering(route_id)
        self._threads = [
            threading.Thread(
                target=self._execution_loop,
                name=f"codex-smart-route-{index + 1}",
                daemon=True,
            )
            for index in range(self.route_workers)
        ]
        for thread in self._threads:
            thread.start()
        try:
            self.server.serve_forever()
        finally:
            self.close()
        if self._errors:
            raise ControllerStartError(
                "EXECUTION_LOOP_FAILED",
                str(self._errors[0]),
            ) from self._errors[0]

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.stop_event.set()
        self.server.close()
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(timeout=3)
        if not any(thread.is_alive() for thread in self._threads):
            self.store.close()

    def _execution_loop(self) -> None:
        try:
            while not self.stop_event.is_set():
                if not self.engine.run_once():
                    self.stop_event.wait(0.2)
        except BaseException as exc:
            with self._error_lock:
                self._errors.append(exc)
            self.stop_event.set()
            self.server.close()


class LiveChildRunnerFactory:
    """Bind permission evidence to the exact materialized snapshot."""

    def __init__(
        self,
        *,
        codex_executable: Path,
        codex_home: Path,
        canary_runtime_parent: Path,
        managed_config_inspector: FileManagedConfigInspector,
        store: SmartStore,
        controller_socket: Path,
    ) -> None:
        self.codex_executable = codex_executable
        self.codex_home = codex_home
        self.canary_runtime_parent = canary_runtime_parent
        self.managed_config_inspector = managed_config_inspector
        self.store = store
        self.controller_socket = controller_socket

    def __call__(
        self,
        profile: PermissionProfileDefinition,
        snapshot: SnapshotResult,
        work_request: ChildWorkRequest,
        _runtime: object,
    ) -> ChildRunner:
        relative = _first_snapshot_file(snapshot.root)
        snapshot_file = snapshot.root / relative
        source_file = work_request.repository / relative
        git_head = work_request.repository / ".git" / "HEAD"
        auth_file = self.codex_home / "auth.json"
        targets = CanaryProbeTargets(
            snapshot_root=snapshot.root,
            snapshot_read_file=snapshot_file,
            snapshot_write_file=snapshot_file,
            secret_read_file=auth_file,
            source_git_read_file=git_head,
            controller_database_read_file=self.store.path,
            source_worktree_write_file=source_file,
            controller_socket=self.controller_socket,
        )
        canary = LivePermissionCanary(
            codex_executable=self.codex_executable,
            ruby_executable=Path("/usr/bin/ruby"),
            codex_home=self.codex_home,
            runtime_parent=self.canary_runtime_parent,
            profile=profile,
            managed_config_inspector=self.managed_config_inspector,
            targets=targets,
            model="gpt-5.6-luna",
            reasoning_effort="low",
        )
        return ChildRunner(PermissionGate(canary))


def build_production_runtime(
    config: ControllerProcessConfig,
) -> ProductionRuntime:
    catalog = Catalog.load(config.catalog_path)
    _verify_platform(catalog)
    version = probe_codex_version(config.real_codex)
    if version not in catalog.supported_codex_versions:
        raise ControllerStartError(
            "CODEX_VERSION_UNSUPPORTED",
            f"Codex {version} is not allowed by the active catalog",
        )

    paths = config.paths
    for directory in (
        paths.base_dir,
        paths.base_dir / "ns",
        paths.namespace_dir,
        paths.namespace_dir / "state",
        paths.namespace_dir / "runtime",
        paths.namespace_dir / "canary",
        paths.namespace_dir / "contracts",
    ):
        _prepare_private_directory(directory)
    output_schema = paths.namespace_dir / "contracts" / "reader-result.schema.json"
    materialize_reader_schema(output_schema)

    store = SmartStore(paths.namespace_dir / "state")
    server: ControllerServer | None = None
    try:
        service = SmartService(store, catalog)
        server = ControllerServer(
            paths=paths,
            service=service,
            codex_home_hash=sha256_text(str(config.codex_home.resolve())),
        )
        inspector = FileManagedConfigInspector((config.catalog_path,))
        managed_state = inspector.inspect()
        runner_factory = LiveChildRunnerFactory(
            codex_executable=config.real_codex,
            codex_home=config.codex_home,
            canary_runtime_parent=paths.namespace_dir / "canary",
            managed_config_inspector=inspector,
            store=store,
            controller_socket=paths.socket_path,
        )
        worker = ChildWorker(
            snapshot_builder=SnapshotBuilder(
                SnapshotLimits(
                    max_files=catalog.limits["snapshot_max_files"],
                    max_file_bytes=catalog.limits[
                        "snapshot_max_file_bytes"
                    ],
                    max_total_bytes=catalog.limits[
                        "snapshot_max_total_bytes"
                    ],
                )
            ),
            child_runner_factory=runner_factory,
        )
        resource_gate = ResourceGate(
            root=paths.namespace_dir,
            min_free_disk_bytes=catalog.limits["min_free_disk_bytes"],
            min_available_memory_bytes=catalog.limits[
                "min_available_memory_bytes"
            ],
            min_available_fds=catalog.limits["min_available_fds"],
        )
        executor = RuntimeNodeExecutor(
            worker=worker,
            config=RuntimeExecutorConfig(
                runtime_parent=paths.namespace_dir / "runtime",
                codex_executable=config.real_codex,
                codex_version=version,
                reader_permission_profile_id=catalog.opaque_id(
                    "permission",
                    "reader",
                ),
                reader_permission_profile_name=catalog.profiles["reader"][
                    "permission_profile"
                ],
                managed_config_sha256=managed_state.sha256,
                output_schema=output_schema,
                timeout_seconds=catalog.limits["child_timeout_seconds"],
                max_output_bytes=catalog.limits["child_max_output_bytes"],
                auth_file=_required_auth_file(config.codex_home),
            ),
            resource_gate=resource_gate,
            artifact_registry=store,
        )
        stop_event = threading.Event()
        engine = ExecutionEngine(
            store,
            executor,
            max_workers=catalog.limits["root_processes"],
            max_sol_workers=catalog.limits["sol_processes"],
            lease_seconds=catalog.limits["lease_seconds"],
            heartbeat_seconds=catalog.limits["heartbeat_seconds"],
            shutdown_event=stop_event,
        )
        route_workers = max(
            1,
            catalog.limits["global_processes"]
            // catalog.limits["root_processes"],
        )
        return ProductionRuntime(
            server=server,
            store=store,
            engine=engine,
            route_workers=route_workers,
            stop_event=stop_event,
        )
    except BaseException:
        if server is not None:
            server.close()
        store.close()
        raise


def materialize_reader_schema(path: Path) -> None:
    parent = path.parent.resolve(strict=True)
    _prepare_private_directory(parent)
    encoded = (
        json.dumps(
            READER_RESULT_SCHEMA,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    if path.exists() and not path.is_symlink():
        try:
            current = path.read_bytes()
            metadata = path.stat()
        except OSError:
            current = b""
            metadata = None
        if (
            current == encoded
            and metadata is not None
            and stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == os.getuid()
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o400
        ):
            return
    temporary = parent / f".{path.name}.{os.getpid()}.{os.urandom(8).hex()}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        view = memoryview(encoded)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def install_signal_handlers(runtime: ProductionRuntime) -> None:
    def stop(_signum: int, _frame: Any) -> None:
        runtime.close()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGHUP, stop)


def _first_snapshot_file(root: Path) -> Path:
    for candidate in sorted(root.rglob("*"), key=lambda item: os.fspath(item)):
        if candidate.is_file() and not candidate.is_symlink():
            return candidate.relative_to(root)
    raise ControllerStartError(
        "SNAPSHOT_EMPTY",
        "permission canary requires at least one committed regular file",
    )


def _required_auth_file(codex_home: Path) -> Path:
    path = codex_home / "auth.json"
    if not path.is_file() or path.is_symlink():
        raise ControllerStartError(
            "FILE_AUTH_REQUIRED",
            "adaptive child v1 requires private file-based Codex authentication",
        )
    return path


def _verify_platform(catalog: Catalog) -> None:
    machine = platform.machine().lower()
    if machine == "aarch64":
        machine = "arm64"
    identifier = f"{platform.system().lower()}-{machine}"
    if identifier not in catalog.supported_platforms:
        raise ControllerStartError(
            "PLATFORM_UNSUPPORTED",
            f"platform {identifier} is not allowed by the active catalog",
        )


def _prepare_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ControllerStartError(
            "UNSAFE_STATE_DIRECTORY",
            f"private directory is a symlink: {path}",
        )
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    metadata = path.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ControllerStartError(
            "UNSAFE_STATE_DIRECTORY",
            f"private directory is unsafe: {path}",
        )

"""CLI: privacy-llm-gateway serve | check-config | calibrate  [--config PATH]

serve         run the API (server.listen) and /metrics (server.metrics_listen)
check-config  validate the config (incl. secrets) and exit 0, or print errors and exit 2
calibrate     score a labelled JSONL file through the classifier and print a threshold sweep
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import shutil
import signal
import sys
import tempfile

from .config import DEFAULT_CONFIG_PATH, ConfigError, LoadedConfig, load_config

EXIT_CONFIG = 2


def _load_or_exit(path: str) -> LoadedConfig:
    try:
        return load_config(path)
    except ConfigError as exc:
        print(f"config error in {path}:", file=sys.stderr)
        for line in str(exc).splitlines():
            print(f"  {line}", file=sys.stderr)
        sys.exit(EXIT_CONFIG)


def _uvicorn_server_class():
    import uvicorn

    class Server(uvicorn.Server):
        """Signal handling is done by the gateway (SIGTERM/SIGINT stop, SIGHUP reload)."""

        @contextlib.contextmanager
        def capture_signals(self):
            yield

    return Server


def _uv_config(app, host: str, port: int, **kw):
    import uvicorn

    return uvicorn.Config(
        app,
        host=host,
        port=port,
        log_config=None,
        access_log=False,
        server_header=False,
        proxy_headers=False,
        ws="none",
        timeout_graceful_shutdown=30,
        **kw,
    )


# --------------------------------------------------------------------------- single process


async def _serve_single(loaded: LoadedConfig) -> None:
    from . import metrics
    from .app import create_app, make_holder

    holder = make_holder(loaded)
    cfg = loaded.config
    api = create_app(holder, install_sighup=True)
    metrics_app = metrics.make_metrics_app(lambda: holder.current.config.server.metrics_auth_token)
    Server = _uvicorn_server_class()
    servers = [
        Server(_uv_config(api, *cfg.server.listen_addr, lifespan="on")),
        Server(_uv_config(metrics_app, *cfg.server.metrics_addr, lifespan="off")),
    ]

    def stop() -> None:
        for s in servers:
            s.should_exit = True

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop)
    results = await asyncio.gather(*(s.serve() for s in servers), return_exceptions=True)
    for r in results:
        if isinstance(r, BaseException):
            raise r
    if any(not s.started for s in servers):
        sys.exit(1)


# --------------------------------------------------------------------------- multi worker


def _serve_workers(loaded: LoadedConfig, path: str) -> None:
    """Parent binds the API socket, forks workers, serves aggregated /metrics."""
    cfg = loaded.config
    n = cfg.server.workers
    host, port = cfg.server.listen_addr
    sock = _uv_config(lambda *_: None, host, port).bind_socket()
    sock.set_inheritable(True)

    children: list[int] = []
    for _ in range(n):
        pid = os.fork()
        if pid == 0:  # worker
            code = 0
            try:
                asyncio.run(_worker_main(loaded, sock))
            except BaseException:  # noqa: BLE001
                code = 1
            os._exit(code)
        children.append(pid)

    asyncio.run(_parent_main(loaded, path, children))


async def _worker_main(loaded: LoadedConfig, sock) -> None:
    from .app import create_app, make_holder

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, signal.SIG_DFL)
    holder = make_holder(loaded)
    app = create_app(holder, install_sighup=True)
    server = _uvicorn_server_class()(_uv_config(app, *loaded.config.server.listen_addr, lifespan="on"))
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: setattr(server, "should_exit", True))
    await server.serve(sockets=[sock])


async def _parent_main(loaded: LoadedConfig, path: str, children: list[int]) -> None:
    from prometheus_client import multiprocess

    from . import metrics
    from .config import ConfigHolder
    from .logs import log

    holder = ConfigHolder(loaded, logger=None)
    server = _uvicorn_server_class()(
        _uv_config(
            metrics.make_metrics_app(lambda: holder.current.config.server.metrics_auth_token),
            *loaded.config.server.metrics_addr,
            lifespan="off",
        )
    )
    loop = asyncio.get_running_loop()

    def forward(sig: int) -> None:
        for pid in children:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, sig)

    def stop() -> None:
        forward(signal.SIGTERM)
        server.should_exit = True

    def hup() -> None:
        holder.reload()  # parent copy: only the metrics token is used here
        forward(signal.SIGHUP)

    loop.add_signal_handler(signal.SIGTERM, stop)
    loop.add_signal_handler(signal.SIGINT, stop)
    loop.add_signal_handler(signal.SIGHUP, hup)

    async def reap() -> None:
        alive = set(children)
        while alive:
            await asyncio.sleep(0.5)
            for pid in list(alive):
                done, status = os.waitpid(pid, os.WNOHANG)
                if done:
                    alive.discard(pid)
                    multiprocess.mark_process_dead(pid)
                    if not server.should_exit:
                        log.error("worker_exited", pid=pid, status=status)
                        stop()
        server.should_exit = True

    await asyncio.gather(server.serve(), reap())


# --------------------------------------------------------------------------- CLI


def _prepare_multiprocess_dir() -> None:
    d = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if not d:
        d = tempfile.mkdtemp(prefix="privacy-llm-gateway-prom-")
        os.environ["PROMETHEUS_MULTIPROC_DIR"] = d
    os.makedirs(d, exist_ok=True)
    for name in os.listdir(d):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            os.unlink(p)
        else:
            shutil.rmtree(p, ignore_errors=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="privacy-llm-gateway", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd")
    for name in ("serve", "check-config", "calibrate"):
        p = sub.add_parser(name)
        p.add_argument("--config", default=DEFAULT_CONFIG_PATH)
        if name == "calibrate":
            p.add_argument("--input", required=True, help="labelled JSONL (see calibration/examples.jsonl)")
            p.add_argument("--concurrency", type=int, default=4)
            p.add_argument("--output", help="write per-example scores (JSONL, no text) here")
    args = parser.parse_args(argv)
    cmd = args.cmd or "serve"
    path = getattr(args, "config", DEFAULT_CONFIG_PATH)

    loaded = _load_or_exit(path)

    if cmd == "check-config":
        cfg = loaded.config
        print(f"ok: {path} (sha256 {loaded.sha256[:12]}, {len(cfg.auth.keys)} keys, "
              f"{len(cfg.policy.sensitive_categories)} sensitive categories, workers {cfg.server.workers})")
        return

    if cmd == "calibrate":
        from .calibrate import run as calibrate_run

        sys.exit(calibrate_run(loaded, args.input, args.concurrency, args.output))

    if loaded.config.server.workers > 1:
        _prepare_multiprocess_dir()  # must happen before metrics is imported
    from . import logs

    logs.setup(loaded.config.logging.level)
    logs.log.event("startup", config_sha256=loaded.sha256, workers=loaded.config.server.workers,
                   listen=loaded.config.server.listen, metrics_listen=loaded.config.server.metrics_listen)
    if loaded.config.server.workers > 1:
        _serve_workers(loaded, path)
    else:
        asyncio.run(_serve_single(loaded))


if __name__ == "__main__":
    main()

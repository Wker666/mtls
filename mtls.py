#!/usr/bin/env python3

import argparse
import importlib.util
import os
import signal
import sys
from pathlib import Path
import threading
from typing import List, Type

from tls_hijack.protocol_type import ProtocolType
from tls_hijack.ssl_proxy import SslProxy
from tls_hijack.upstream_type import UpstreamType


def load_module_from_path(path: str, module_name: str | None = None):
    path_obj = Path(path).resolve()
    if not path_obj.is_file():
        raise FileNotFoundError(path_obj)

    if module_name is None:
        module_name = path_obj.stem 

    spec = importlib.util.spec_from_file_location(module_name, path_obj)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot import from {path_obj}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def load_callback_classes(path: str) -> List[Type]:
    mod = load_module_from_path(path)

    if not hasattr(mod, "callbacks"):
        raise RuntimeError(
            f"Module {mod.__name__} must define a 'callbacks' list, "
            f"e.g. callbacks = [MyCallbackClass]"
        )

    cbs = getattr(mod, "callbacks")
    if not isinstance(cbs, (list, tuple)) or not cbs:
        raise RuntimeError(
            f"'callbacks' in module {mod.__name__} must be a non-empty list of classes"
        )

    result: List[Type] = [cb for cb in cbs if isinstance(cb, type)]
    if not result:
        raise RuntimeError(
            f"'callbacks' in module {mod.__name__} contains no valid classes"
        )
    if hasattr(mod, "init_cb") and callable(getattr(mod, "init_cb")):
        init_cb = getattr(mod, "init_cb")
    else:
        init_cb = None
    return result, init_cb


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SSL proxy with pluggable callback script"
    )

    parser.add_argument(
        "-s",
        "--script",
        dest="callback_script_path",
        required=True,
        help="Path to the callback script, e.g. plugins/log.py",
    )

    parser.add_argument(
        "-u", 
        "--udp",
        action="store_true",
        default=False,
        help="Use UDP (DTLS) protocol instead of TCP (SSL/TLS).",
    )

    parser.add_argument(
        "-p",
        "--listen-port",
        type=int,
        default=443,
        help="Listen port (default: 443)",
    )

    parser.add_argument(
        "--cert-file",
        default="certs/ca-cert.pem",
        help="Path to server certificate file (default: certs/ca-cert.pem)",
    )
    parser.add_argument(
        "--key-file",
        default="certs/ca-key.pem",
        help="Path to server private key file (default: certs/ca-key.pem)",
    )

    parser.add_argument(
        "--tmp-pem-dir",
        dest="tmp_pem_dir",
        default="./tmp",
        help=(
            "Directory to store generated leaf certificate/key PEM files "
            "(default: ./tmp). WARNING: this directory may be cleared on startup."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=-1,
        help="Timeout for SSL connections Set to -1 to disable timeout.",
    )
    parser.add_argument(
        "--upstream",
        dest="upstream",
        default=None,
        help=(
            "Optional fixed upstream address in the form host:port. "
            "If omitted, the proxy will use the original target host and port."
        ),
    )

    return parser.parse_known_args()

def main():
    def handle_sigint(signum, frame):
        try:
            proxy.stop()
        except Exception as e:
            print(f"proxy.stop() 发生异常: {e}", file=sys.stderr)
        print('Goodbye!')
        sys.exit(0)

    args,unknown_args = parse_args()
    callback_classes, init_cb = load_callback_classes(args.callback_script_path)
    CallbackCls = callback_classes[0]

    tmp_pem_dir = Path(args.tmp_pem_dir).resolve()
    if tmp_pem_dir.exists():
        for child in tmp_pem_dir.iterdir():
            child.unlink()
    else:
        tmp_pem_dir.mkdir(parents=True)

    upstream_type = UpstreamType.SSL
    protocol = ProtocolType.UDP if args.udp else ProtocolType.TCP
    if protocol == ProtocolType.UDP:
        if os.geteuid() != 0:
            raise SystemExit("UDP proxy must run as root")

    upstream_host = None
    upstream_port = None
    if args.upstream:
        try:
            if protocol == ProtocolType.UDP:
                upstream_type = UpstreamType.UDP
            else:
                upstream_type = UpstreamType.TCP
            host, port_str = args.upstream.rsplit(":", 1)
            upstream_host = host
            upstream_port = int(port_str)
        except ValueError:
            raise SystemExit(f"Invalid --upstream value: {args.upstream!r}, expected host:port")
    
    listen_port = args.listen_port


    proxy = SslProxy(
        listen_port = listen_port,
        cert_file=args.cert_file,
        key_file=args.key_file,
        callback_cls=CallbackCls,
        pem_tmp_dir=args.tmp_pem_dir,
        timeout=args.timeout,
        upstream_type=upstream_type,
        upstream_host=upstream_host,
        upstream_port=upstream_port,
        protocol=protocol
    )

    if init_cb is not None:
        threading.Thread(target=proxy.start, daemon=True).start()
        init_cb(proxy,protocol,upstream_type,upstream_host,upstream_port,listen_port,unknown_args)
    else:
        signal.signal(signal.SIGINT, handle_sigint)
        ok = proxy.start()
        if not ok:
            print("Failed to start proxy")
            return 1
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

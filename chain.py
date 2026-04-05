import socket
import struct
import base64
import argparse
import threading
from typing import List, Dict, Optional


def parse_proxy(proxy_str: str) -> Dict:
    """
    Parse a proxy string in the format:
        type://[user:pass@]host:port
    Supported types: http, socks4, socks5
    """
    if "://" not in proxy_str:
        raise ValueError(f"Invalid proxy format (missing '://'): {proxy_str}")

    ptype, rest = proxy_str.split("://", 1)
    ptype = ptype.strip().lower()

    if ptype not in ("http", "socks4", "socks5"):
        raise ValueError(f"Unsupported proxy type '{ptype}'. Use http, socks4 or socks5.")

    # Handle optional auth
    if "@" in rest:
        auth_part, hostport = rest.split("@", 1)
        if ":" in auth_part:
            user, password = auth_part.split(":", 1)
        else:
            user, password = auth_part, None
    else:
        user = password = None
        hostport = rest

    # Handle host:port
    if ":" in hostport:
        host, port_str = hostport.rsplit(":", 1)
        port = int(port_str)
    else:
        host = hostport
        port = 8080 if ptype == "http" else 1080

    return {
        "type": ptype,
        "host": host.strip(),
        "port": port,
        "user": user.strip() if user else None,
        "pass": password.strip() if password else None,
    }


def connect_http(
    sock: socket.socket,
    target_host: str,
    target_port: int,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> socket.socket:
    """Tunnel through an HTTP proxy using the CONNECT method."""
    request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    if username and password:
        auth = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("utf-8")
        request += f"Proxy-Authorization: Basic {auth}\r\n"
    request += "\r\n"

    sock.sendall(request.encode("utf-8"))

    # Read response until we see the end of headers
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("HTTP proxy closed connection unexpectedly")
        response += chunk

    resp_str = response.decode("utf-8", errors="ignore")
    if not resp_str.startswith("HTTP/1.") or " 200 " not in resp_str:
        raise ConnectionError(f"HTTP proxy CONNECT failed: {resp_str.splitlines()[0]}")

    return sock


def connect_socks4(
    sock: socket.socket,
    target_host: str,
    target_port: int,
    username: Optional[str] = None,
) -> socket.socket:
    """Tunnel through a SOCKS4/SOCKS4a proxy (SOCKS4a for domain names)."""
    if username is None:
        username = ""

    # SOCKS4a: use 0.0.0.1 + domain name if target is not an IP
    try:
        ip_bytes = socket.inet_aton(target_host)
        request = (
            b"\x04\x01"  # version + command (CONNECT)
            + struct.pack("!H", target_port)
            + ip_bytes
            + username.encode("ascii") + b"\x00"
        )
    except socket.error:
        # Not an IP -> SOCKS4a domain name
        ip_bytes = b"\x00\x00\x00\x01"
        domain_bytes = target_host.encode("ascii") + b"\x00"
        request = (
            b"\x04\x01"
            + struct.pack("!H", target_port)
            + ip_bytes
            + username.encode("ascii") + b"\x00"
            + domain_bytes
        )

    sock.sendall(request)

    reply = sock.recv(8)
    if len(reply) < 8 or reply[1] != 0x5A:  # 0x5A = request granted
        raise ConnectionError(f"SOCKS4 connection refused (code: {reply[1] if len(reply) > 1 else 'unknown'})")

    return sock


def connect_socks5(
    sock: socket.socket,
    target_host: str,
    target_port: int,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> socket.socket:
    """Tunnel through a SOCKS5 proxy (supports username/password and domain names)."""
    # 1. Greeting + authentication methods
    if username and password:
        methods = b"\x00\x02"  # NO-AUTH + USERNAME/PASSWORD
        n_methods = 2
    else:
        methods = b"\x00"
        n_methods = 1

    greeting = struct.pack("!BB", 5, n_methods) + methods
    sock.sendall(greeting)

    resp = sock.recv(2)
    if len(resp) != 2 or resp[0] != 5:
        raise ConnectionError("SOCKS5 greeting failed")

    method = resp[1]
    if method == 0xFF:
        raise ConnectionError("SOCKS5: no acceptable authentication method")

    # 2. Username/password authentication if selected
    if method == 2 and username and password:
        auth_req = (
            b"\x01"
            + struct.pack("!B", len(username)) + username.encode("ascii")
            + struct.pack("!B", len(password)) + password.encode("ascii")
        )
        sock.sendall(auth_req)
        auth_resp = sock.recv(2)
        if len(auth_resp) != 2 or auth_resp[1] != 0:
            raise ConnectionError("SOCKS5 username/password authentication failed")

    # 3. Connection request (use domain name)
    request = (
        b"\x05\x01\x00"  # version + CONNECT + reserved
        + b"\x03"  # address type = DOMAINNAME
        + struct.pack("!B", len(target_host)) + target_host.encode("ascii")
        + struct.pack("!H", target_port)
    )
    sock.sendall(request)

    # 4. Read reply
    reply = sock.recv(4)
    if len(reply) < 4 or reply[0] != 5 or reply[1] != 0:
        raise ConnectionError(f"SOCKS5 request failed (code: {reply[1] if len(reply) > 1 else 'unknown'})")

    # Skip the rest of the reply (bound address + port)
    atyp = reply[3]
    if atyp == 1:      # IPv4
        sock.recv(6)
    elif atyp == 3:    # DOMAINNAME
        length = sock.recv(1)[0]
        sock.recv(length + 2)
    elif atyp == 4:    # IPv6
        sock.recv(18)
    else:
        raise ConnectionError("SOCKS5: unknown address type in reply")

    return sock


def chain_connect(proxies: List[Dict], target_host: str, target_port: int) -> socket.socket:
    """
    Create a socket chained through any number of HTTP / SOCKS4 / SOCKS5 proxies.
    """
    if not proxies:
        # Direct connection (no proxies in the chain)
        return socket.create_connection((target_host, target_port))

    # Step 1: Raw TCP connection to the first proxy
    first_proxy = proxies[0]
    sock = socket.create_connection((first_proxy["host"], first_proxy["port"]))

    # Step 2: For every proxy in the chain, ask it to connect to the *next* hop
    for i, proxy in enumerate(proxies):
        if i < len(proxies) - 1:
            # Next hop is another proxy
            next_host = proxies[i + 1]["host"]
            next_port = proxies[i + 1]["port"]
        else:
            # Final hop is the real target
            next_host = target_host
            next_port = target_port

        if proxy["type"] == "http":
            sock = connect_http(sock, next_host, next_port, proxy.get("user"), proxy.get("pass"))
        elif proxy["type"] == "socks5":
            sock = connect_socks5(sock, next_host, next_port, proxy.get("user"), proxy.get("pass"))
        elif proxy["type"] == "socks4":
            sock = connect_socks4(sock, next_host, next_port, proxy.get("user"))
        else:
            raise ValueError(f"Unknown proxy type: {proxy['type']}")

    return sock


def relay(client_sock: socket.socket, remote_sock: socket.socket):
    """Bidirectional relay between client and remote (chained) socket."""
    def forward(src: socket.socket, dst: socket.socket):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                src.close()
            except Exception:
                pass
            try:
                dst.close()
            except Exception:
                pass

    t1 = threading.Thread(target=forward, args=(client_sock, remote_sock), daemon=True)
    t2 = threading.Thread(target=forward, args=(remote_sock, client_sock), daemon=True)
    t1.start()
    t2.start()


def handle_socks5_client(client_sock: socket.socket, proxies: List[Dict]):
    """Handle a single incoming SOCKS5 client connection and chain the proxies."""
    try:
        # 1. SOCKS5 greeting (client tells us supported auth methods)
        greeting = client_sock.recv(2)
        if len(greeting) != 2 or greeting[0] != 0x05:
            return

        n_methods = greeting[1]
        if n_methods == 0:
            return
        methods = client_sock.recv(n_methods)

        # We only support NO-AUTH (0x00) for the local listener
        if 0x00 not in methods:
            client_sock.sendall(b'\x05\xff')  # no acceptable methods
            return

        client_sock.sendall(b'\x05\x00')  # choose NO-AUTH

        # 2. SOCKS5 request (client tells us the real destination)
        header = client_sock.recv(4)
        if len(header) != 4 or header[0] != 0x05 or header[1] != 0x01:  # only CONNECT supported
            # Command not supported
            client_sock.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            return

        atyp = header[3]

        if atyp == 0x01:      # IPv4
            addr = client_sock.recv(4)
            target_host = socket.inet_ntoa(addr)
        elif atyp == 0x03:    # DOMAINNAME
            length = client_sock.recv(1)[0]
            domain = client_sock.recv(length)
            target_host = domain.decode("utf-8", errors="replace")
        elif atyp == 0x04:    # IPv6
            addr = client_sock.recv(16)
            target_host = socket.inet_ntop(socket.AF_INET6, addr)
        else:
            # Address type not supported
            client_sock.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            return

        port_bytes = client_sock.recv(2)
        target_port = struct.unpack("!H", port_bytes)[0]

        # 3. Chain the proxies to reach the real target
        try:
            remote_sock = chain_connect(proxies, target_host, target_port)

            # 4. Send success reply to client
            success_reply = b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'  # succeeded + dummy bind addr
            client_sock.sendall(success_reply)

            # 5. Start bidirectional relay
            relay(client_sock, remote_sock)

        except Exception:
            # Any error in the chain → tell client it failed
            failure_reply = b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00'  # general failure
            client_sock.sendall(failure_reply)

    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Python chained proxy server.\n"
                    "Starts a local SOCKS5 proxy that forwards every connection "
                    "through a chain of HTTP / SOCKS4 / SOCKS5 proxies."
    )
    parser.add_argument(
        "--proxy",
        action="append",
        required=True,
        help='Proxy in format: http://host:port  or  socks5://user:pass@host:port  (repeat --proxy for chain)',
    )
    parser.add_argument(
        "--listen",
        default="127.0.0.1:1080",
        help="Local address to listen on (format: host:port). Default: 127.0.0.1:1080",
    )
    args = parser.parse_args()

    # Parse proxies (order = connection order: first proxy is the one we connect to first)
    proxies = [parse_proxy(p) for p in args.proxy]

    # Parse listen address
    if ":" in args.listen:
        listen_host, listen_port_str = args.listen.rsplit(":", 1)
        listen_port = int(listen_port_str)
    else:
        listen_host = "127.0.0.1"
        listen_port = int(args.listen)

    print(f"🚀 Starting local SOCKS5 proxy on {listen_host}:{listen_port}")
    print(f"   All traffic will be chained through {len(proxies)} proxy(ies):")
    for i, p in enumerate(proxies, 1):
        auth = f"{p['user']}:***@" if p.get("user") else ""
        print(f"     {i}. {p['type'].upper()}://{auth}{p['host']}:{p['port']}")

    # Create listening socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((listen_host, listen_port))
    server_sock.listen(10)   # backlog

    print("✅ Listening for incoming connections... (Ctrl+C to stop)")

    try:
        while True:
            client_sock, addr = server_sock.accept()
            print(f"   [+] New client from {addr[0]}:{addr[1]}")
            thread = threading.Thread(
                target=handle_socks5_client,
                args=(client_sock, proxies),
                daemon=True
            )
            thread.start()
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()

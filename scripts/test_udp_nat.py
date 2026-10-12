#!/usr/bin/env python3
"""IPv4 RFC 5780 discovery through the host's UDP routing (eBPF/TUN).

Uses fresh source ports for filtering and mapping. Does not implement SOCKS5
or honor proxy environment variables. Requires a two-address RFC 5780 server.
"""

import argparse
import ipaddress
import secrets
import socket
import struct
import sys
import time


COOKIE = 0x2112A442
MAPPED = 0x0001
CHANGE_REQUEST = 0x0003
XOR_MAPPED = 0x0020
OTHER_ADDRESS = 0x802C
ENDPOINT_INDEPENDENT = "Endpoint Independent"


class DiscoveryError(Exception):
    pass


def decode_address(value, transaction, xor=False):
    if len(value) < 4 or value[0] != 0:
        raise DiscoveryError("Malformed STUN address")
    family = value[1]
    size = {1: 4, 2: 16}.get(family)
    if size is None or len(value) != size + 4:
        raise DiscoveryError("Malformed STUN address family or length")
    port = struct.unpack("!H", value[2:4])[0]
    address = value[4:]
    if xor:
        port ^= COOKIE >> 16
        mask = struct.pack("!I", COOKIE) + transaction
        address = bytes(a ^ b for a, b in zip(address, mask))
    return str(ipaddress.ip_address(address)), port


def parse_response(data, transaction):
    if len(data) < 20:
        raise DiscoveryError("Truncated STUN header")
    kind, length, cookie = struct.unpack("!HHI", data[:8])
    if cookie != COOKIE or data[8:20] != transaction:
        raise DiscoveryError("Invalid STUN cookie or transaction")
    if length % 4 or len(data) != 20 + length:
        raise DiscoveryError("Invalid STUN message length")
    attributes = {}
    offset = 20
    while offset < len(data):
        if offset + 4 > len(data):
            raise DiscoveryError("Truncated STUN attribute header")
        attr, size = struct.unpack("!HH", data[offset:offset + 4])
        end = offset + 4 + size
        padded = end + (-size % 4)
        if padded > len(data):
            raise DiscoveryError("Truncated STUN attribute")
        attributes[attr] = data[offset + 4:end]
        offset = padded
    if kind == 0x0111:
        value = attributes.get(0x0009, b"")
        code = (value[2] & 7) * 100 + value[3] if len(value) >= 4 else "unknown"
        raise DiscoveryError(f"STUN server rejected request: {code}")
    if kind != 0x0101:
        raise DiscoveryError(f"Unexpected STUN response type: {kind:#x}")
    result = {}
    for attr in (MAPPED, XOR_MAPPED, OTHER_ADDRESS):
        if attr in attributes:
            result[attr] = decode_address(attributes[attr], transaction, attr == XOR_MAPPED)
    return result


def binding(sock, server, timeout, retries, change=0, expected_source=None):
    transaction = secrets.token_bytes(12)
    attributes = struct.pack("!HHI", CHANGE_REQUEST, 4, change) if change else b""
    request = struct.pack("!HHI", 0x0001, len(attributes), COOKIE) + transaction + attributes
    for attempt in range(retries + 1):
        sock.sendto(request, server)
        deadline = time.monotonic() + timeout * (2 ** attempt)
        while time.monotonic() < deadline:
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                data, source = sock.recvfrom(65535)
            except socket.timeout:
                break
            if len(data) < 20 or data[8:20] != transaction:
                continue
            result = parse_response(data, transaction)
            if expected_source is not None and source != expected_source:
                raise DiscoveryError(
                    f"Unexpected reply source {source}; expected {expected_source}. "
                    "Server may ignore CHANGE-REQUEST, or the proxy rewrites peer addresses."
                )
            return result
    raise socket.timeout(f"No STUN response from {server} (change={change})")


def mapped(response):
    address = response.get(XOR_MAPPED, response.get(MAPPED))
    if address is None:
        raise DiscoveryError("Server omitted mapped address")
    return address


def alternate(response, server):
    other = response.get(OTHER_ADDRESS)
    if other is None:
        raise DiscoveryError("Server lacks OTHER-ADDRESS; RFC 5780 discovery unsupported")
    if other[0] == server[0] or other[1] == server[1] or \
            ipaddress.ip_address(other[0]).version != 4:
        raise DiscoveryError("Discovery requires different IPv4 addresses and ports")
    return other


def filtering(sock, server, timeout, retries):
    initial = binding(sock, server, timeout, retries, expected_source=server)
    other = alternate(initial, server)
    external = mapped(initial)
    try:
        binding(sock, server, timeout, retries, change=6, expected_source=other)
        return ENDPOINT_INDEPENDENT, external
    except socket.timeout:
        pass
    try:
        binding(sock, server, timeout, retries, change=2,
                expected_source=(server[0], other[1]))
        return "Address Dependent", external
    except socket.timeout:
        # Verify that the primary service is still reachable before inferring
        # filtering from missing changed-source responses.
        binding(sock, server, timeout, retries, expected_source=server)
        return "Address and Port Dependent", external


def mapping(sock, server, timeout, retries):
    initial = binding(sock, server, timeout, retries, expected_source=server)
    other = alternate(initial, server)
    external = mapped(initial)
    second_target = (other[0], server[1])
    second = mapped(binding(sock, second_target, timeout, retries,
                            expected_source=second_target))
    # Check both alternate-address endpoints even if the first mapping matches.
    third = mapped(binding(sock, other, timeout, retries, expected_source=other))
    if external == second == third:
        return ENDPOINT_INDEPENDENT, external
    if second == third and external != second:
        return "Address Dependent", external
    return "Address and Port Dependent", external


def run(args):
    server = socket.getaddrinfo(args.server, args.port, socket.AF_INET,
                                socket.SOCK_DGRAM)[0][4]
    print(f"Server: {server[0]}:{server[1]} (IPv4)")
    results = {}
    # Keep the first socket open so the OS cannot reuse its ephemeral port.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as filter_socket, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as mapping_socket:
        filter_socket.bind((args.bind, 0))
        mapping_socket.bind((args.bind, 0))
        for name, probe, sock in (("Filtering", filtering, filter_socket),
                                  ("Mapping", mapping, mapping_socket)):
            print(f"{name} local socket: {sock.getsockname()}")
            try:
                behavior, external = probe(sock, server, args.timeout, args.retries)
                results[name] = behavior
                print(f"NAT {name}: {behavior}; external {external[0]}:{external[1]}")
            except (DiscoveryError, OSError) as error:
                results[name] = "Unknown"
                print(f"NAT {name}: Unknown ({error})")
    if "Unknown" in results.values():
        print("Full Cone: INCONCLUSIVE")
        return 2
    full_cone = all(value == ENDPOINT_INDEPENDENT for value in results.values())
    print(f"Full Cone: {'YES' if full_cone else 'NO'} (observed end-to-end behavior)")
    print("Timeout-based filtering results can also reflect packet loss or server/firewall issues.")
    return 0 if full_cone else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server", nargs="?", default="stunserver2025.stunprotocol.org")
    parser.add_argument("--port", type=int, default=3478)
    parser.add_argument("--bind", default="0.0.0.0", help="Local IPv4 address")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--retries", type=int, default=2)
    args = parser.parse_args()
    if args.timeout <= 0 or not 0 <= args.retries <= 5 or not 1 <= args.port <= 65535:
        parser.error("Require timeout > 0, retries 0..5, port 1..65535")
    try:
        return run(args)
    except (OSError, DiscoveryError) as error:
        print(f"Test failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

"""Local, deterministic RFC 5780 wire tests; no external service needed."""

import select
import socket
import struct
import sys
import threading
import unittest

import test_udp_nat as nat


@unittest.skipUnless(sys.platform.startswith("linux"), "Requires Linux 127.0.0.0/8 loopback binding")
class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.sockets = []
        for ip, port in (("127.0.0.1", 0), ("127.0.0.1", 0)):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((ip, port))
            self.sockets.append(sock)
        for primary in self.sockets[:2]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.2", primary.getsockname()[1]))
            self.sockets.append(sock)
        self.server = self.sockets[0].getsockname()
        self.other = self.sockets[3].getsockname()
        self.filter_mode = 0
        self.mapping_mode = 0
        self.include_other = True
        self.ignore_change = False
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.bind(("127.0.0.1", 0))

    def tearDown(self):
        self.stopped.set()
        self.thread.join()
        self.client.close()
        for sock in self.sockets:
            sock.close()

    def serve(self):
        while not self.stopped.is_set():
            ready, _, _ = select.select(self.sockets, [], [], 0.01)
            for sock in ready:
                data, client = sock.recvfrom(65535)
                transaction = data[8:20]
                change = struct.unpack("!I", data[24:28])[0] if len(data) == 28 else 0
                if change == 6 and self.filter_mode > 0:
                    continue
                if change == 2 and self.filter_mode > 1:
                    continue
                output = sock
                if not self.ignore_change:
                    if change == 6:
                        output = self.sockets[3]
                    elif change == 2:
                        output = self.sockets[1]
                target = sock.getsockname()
                port = 40000
                if self.mapping_mode and target[0] == "127.0.0.2":
                    port += 1
                    if self.mapping_mode == 2 and target[1] == self.other[1]:
                        port += 1
                packed_ip = socket.inet_aton("192.0.2.1")
                mask = struct.pack("!I", nat.COOKIE)
                address = struct.pack("!BBH", 0, 1, port ^ (nat.COOKIE >> 16))
                address += bytes(a ^ b for a, b in zip(packed_ip, mask))
                attributes = struct.pack("!HH", nat.XOR_MAPPED, len(address)) + address
                if self.include_other:
                    other = struct.pack("!BBH", 0, 1, self.other[1])
                    other += socket.inet_aton(self.other[0])
                    attributes += struct.pack("!HH", nat.OTHER_ADDRESS, len(other)) + other
                response = struct.pack("!HHI", 0x0101, len(attributes), nat.COOKIE)
                output.sendto(response + transaction + attributes, client)

    def test_mapping_modes_use_one_socket_across_targets(self):
        for mode, expected in enumerate((nat.ENDPOINT_INDEPENDENT,
                                        "Address Dependent", "Address and Port Dependent")):
            self.mapping_mode = mode
            result, address = nat.mapping(self.client, self.server, 0.05, 0)
            self.assertEqual(result, expected)
            self.assertEqual(address, ("192.0.2.1", 40000))

    def test_filtering_modes_check_changed_source(self):
        for mode, expected in enumerate((nat.ENDPOINT_INDEPENDENT,
                                        "Address Dependent", "Address and Port Dependent")):
            self.filter_mode = mode
            result, _ = nat.filtering(self.client, self.server, 0.05, 0)
            self.assertEqual(result, expected)

    def test_server_ignoring_change_is_not_reported_as_full_cone(self):
        self.ignore_change = True
        with self.assertRaisesRegex(nat.DiscoveryError, "Unexpected reply source"):
            nat.filtering(self.client, self.server, 0.05, 0)

    def test_basic_server_is_inconclusive(self):
        self.include_other = False
        with self.assertRaisesRegex(nat.DiscoveryError, "OTHER-ADDRESS"):
            nat.mapping(self.client, self.server, 0.05, 0)

    def test_truncated_attributes_are_rejected(self):
        transaction = bytes(12)
        malformed = struct.pack("!HHI", 0x0101, 4, nat.COOKIE) + transaction
        malformed += struct.pack("!HH", nat.XOR_MAPPED, 8)
        with self.assertRaisesRegex(nat.DiscoveryError, "Truncated STUN attribute"):
            nat.parse_response(malformed, transaction)


if __name__ == "__main__":
    unittest.main()

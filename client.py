
IP_ADDRESS = "192.168.1.2"
SERVER_ADDRESS = "192.168.1.1"
CLIENT_IDENTIFIER = b'\x01\x02\x03\x04'

import ipaddress
import random
import time
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from setuptools.command.build_py import assert_relative

# We use UDP port 67 (DHCP Server) to send data packets. The channel is single-directional
# As for authentication, we use asymmetric encryption. The client sends a request packet encrypted with a certain
# pubkey identified by clientid. The server decrypts the packet and verifies the data. If the data is valid, the server
# executes proxy auth command.

# The data contains a timestamp, client's IP address.

# Magic cookie to identify this as custom protocol
YIADDR = b'\xfe\x4e\x08\xce'


def pesudo_random(b: bytes) -> int:
    return (int.from_bytes(hashlib.sha256(b).digest()[5:9], 'little') >> 13) & 0xf


def construct_dhcp_request_packet(ip_address: ipaddress.IPv4Address,
                                  server_address: ipaddress.IPv4Address,
                                  client_identifier: bytes,
                                  pubkey: rsa.RSAPublicKey) -> bytes:
    assert len(client_identifier) == 4, 'Client identifier must be 4 bytes'

    packet = b''

    packet += b'\x01'  # Request OP
    packet += b'\x01'  # Hardware Type
    packet += b'\x10'  # Hardware Address Length, 16 bytes
    packet += b'\x00'  # Hops
    tid = random.randbytes(4)  # Transaction ID
    packet += tid
    packet += b'\x00\x00'  # Seconds Elapsed
    packet += b'\x00\x00'  # Bootp Flags
    packet += b'\x00\x00\x00\x00'  # Client IP
    packet += YIADDR  # Your IP
    packet += server_address.packed  # Server IP
    packet += b'\x00\x00\x00\x00'  # Gateway IP

    uuid = random.randbytes(16)

    # Based on tid, we embed the client identifier into the uuid field
    start_byte = pesudo_random(tid)
    if start_byte > 12:
        uuid = client_identifier[start_byte-12:] + uuid[start_byte-12:start_byte] + client_identifier[:start_byte-12]
    else:
        uuid = uuid[:start_byte] + client_identifier + uuid[start_byte+4:]

    packet += uuid  # Client Hardware Address

    plain_data = b''
    plain_data += ip_address.packed
    timestamp = int(time.time() * 1000).to_bytes(8, 'little')
    plain_data += timestamp

    # Treat pubkey as rsa pubkey and use it to encrypt the data
    encrypted_data: bytes = pubkey.encrypt(plain_data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

    # 192 bytes left here
    packet += 64 * b'\x00'  # Padding
    packet += encrypted_data

    packet += b'\x63\x82\x53\x63'  # Magic Cookie

    return packet


rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
rsa_pubkey = rsa_key.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
pubkey = serialization.load_der_public_key(rsa_pubkey)

print(rsa_key.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()).hex())

p = construct_dhcp_request_packet(ipaddress.IPv4Address(IP_ADDRESS), ipaddress.IPv4Address(SERVER_ADDRESS), CLIENT_IDENTIFIER, pubkey)

# Use udp to send the packet to the server port 67
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(p, (SERVER_ADDRESS, 67))

print(p.hex())

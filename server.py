import ipaddress
import hashlib
import os
import sys
import traceback
import argparse
import re
import socket

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

YIADDR = b'\xfe\x4e\x08\xce'

privkey_dict = {}
timestamp_dict = {}


def pesudo_random(b: bytes) -> int:
    return (int.from_bytes(hashlib.sha256(b).digest()[5:9], 'little') >> 13) & 0xf


def decode_dhcp_request_packet(packet: bytes) -> ipaddress.IPv4Address:
    assert len(packet) == 240, 'Invalid packet length'
    assert packet[0] == 1, 'Invalid OP code'
    assert packet[1] == 1, 'Invalid Hardware Type'
    assert packet[2] == 16, 'Invalid Hardware Address Length'
    assert packet[3] == 0, 'Invalid Hops'
    tid = packet[4:8]
    assert packet[8:10] == b'\x00\x00', 'Invalid Seconds Elapsed'
    assert packet[10:12] == b'\x00\x00', 'Invalid Bootp Flags'
    assert packet[12:16] == b'\x00\x00\x00\x00', 'Invalid Client IP'
    assert packet[16:20] == YIADDR, 'Invalid Your IP'
    server_ip = ipaddress.IPv4Address(packet[20:24])
    assert packet[24:28] == b'\x00\x00\x00\x00', 'Invalid Gateway IP'
    client_hwaddr = packet[28:44]

    start_byte = pesudo_random(tid)
    if start_byte > 12:
        client_identifier = client_hwaddr[start_byte:] + client_hwaddr[:start_byte-12]
    else:
        client_identifier = client_hwaddr[start_byte:start_byte+4]

    if client_identifier not in privkey_dict:
        raise ValueError('Client not registered')

    encrypted_data = packet[-132:-4]
    plain_data = privkey_dict[client_identifier].decrypt(encrypted_data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

    ip_address = ipaddress.IPv4Address(plain_data[:4])
    timestamp = int.from_bytes(plain_data[4:], 'little')

    if timestamp <= timestamp_dict.get(client_identifier, 0):
        raise ValueError('Invalid timestamp')

    timestamp_dict[client_identifier] = timestamp
    return ip_address


parser = argparse.ArgumentParser()
parser.add_argument('--new-client')
parser.add_argument('--client-dir', default='authorized_clients')
parser.add_argument('--bind-address', default='0.0.0.0')
args = parser.parse_args()

if args.new_client is not None:
    client_name_re = re.compile(r'^[a-zA-Z0-9-]+$')

    if not client_name_re.match(args.new_client):
        raise ValueError('Invalid client name, must be alphanumeric')

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    rsa_pubkey = rsa_key.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()
    rsa_privkey = rsa_key.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()).hex()
    clientid = hashlib.sha256(args.new_client.encode()).digest()[:4]
    while os.path.exists(os.path.join(args.client_dir, clientid.hex())):
        clientid = hashlib.sha256(clientid).digest()[:4]

    clientfile = os.path.join(args.client_dir, clientid.hex())
    with open(clientfile, 'w') as f:
        f.write(f"""# Client {args.new_client}
{rsa_pubkey}
{rsa_privkey}
""")
        print(f"Client {args.new_client} created with id {clientid.hex()}")

    with open(clientfile + '.pub', 'w') as f:
        f.write(f"{rsa_pubkey}\n")

    exit(0)

client_id_re = re.compile(r'^[0-9a-f]{8}$')

for f in os.listdir(args.client_dir):
    if not client_id_re.match(f):
        if f.endswith('.pub'):
            continue

        if f == 'timestamp.dict':
            with open(os.path.join(args.client_dir, f)) as f:
                for line in f:
                    k, v = line.strip().split()
                    if not client_id_re.match(k):
                        continue

                    try:
                        timestamp_dict[bytes.fromhex(k)] = int(v)
                    except ValueError:
                        continue
            print(f"Timestamp dict loaded")
            continue

        print(f"Skipping {f}, not a valid client id", file=sys.stderr)
        continue

    try:
        with open(os.path.join(args.client_dir, f)) as c:
            lines = c.readlines()

            privkey_line = -1
            for l, line in enumerate(lines):
                if len(line.strip()) == 1218:
                    privkey_line = l
                    break

            if privkey_line == -1:
                print(f"Skipping {f}, no private key found", file=sys.stderr)
                continue

            privkey_dict[bytes.fromhex(f)] = serialization.load_der_private_key(bytes.fromhex(lines[privkey_line].strip()), None)

            print(f"Loaded client {f}")
    except Exception as e:
        print(f"Error loading client {f}", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)


# --- --- --- Server Socket Code --- --- ---

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((args.bind_address, 67))

while True:
    try:
        data, addr = server.recvfrom(1024)
        ip_address = decode_dhcp_request_packet(data)
        if addr[0] != str(ip_address):
            raise ValueError('Auth address is not sender address')
        print(f"Authenticated {ip_address}")
    except AssertionError:
        print(f"Not a proxy authing packet from {addr}")
    except ValueError as e:
        print(f"Error processing request from {addr}: {e}")
    except Exception as e:
        print(f"Error processing request from {addr}")
        print(traceback.format_exc(), file=sys.stderr)
        continue
    except KeyboardInterrupt:
        with open(os.path.join(args.client_dir, 'timestamp.dict'), 'w') as f:
            for k, v in timestamp_dict.items():
                f.write(f"{k.hex()} {v}\n")

        break

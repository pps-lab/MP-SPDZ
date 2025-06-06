import platform
import socket, ssl
import struct
import time
from domains import *

# The following function is either taken directly or derived from:
# https://stackoverflow.com/questions/12248132/how-to-change-tcp-keepalive-timer-using-python-script
def set_keepalive_linux(sock, after_idle_sec=1, interval_sec=3, max_fails=5):
    """Set TCP keepalive on an open socket.

    It activates after 1 second (after_idle_sec) of idleness,
    then sends a keepalive ping once every 3 seconds (interval_sec),
    and closes the connection after 5 failed ping (max_fails), or 15 seconds
    """
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)

# The following function is either taken directly or derived from:
# https://stackoverflow.com/questions/12248132/how-to-change-tcp-keepalive-timer-using-python-script
def set_keepalive_osx(sock, after_idle_sec=1, interval_sec=3, max_fails=5):
    """Set TCP keepalive on an open socket.

    sends a keepalive ping once every 3 seconds (interval_sec)
    """
    # scraped from /usr/include, not exported by python's socket module
    TCP_KEEPALIVE = 0x10
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, interval_sec)

class Client:
    """Client to servers running secure computation. Works both as a client
    to all parties or a trusted client to a single party.

    :param hostnames: hostnames or IP addresses to connect to
    :param port_base: port number for first hostname,
      increases by one for every additional hostname
    :param my_client_id: number to identify client

    """
    def __init__(self, hostnames, port_base, my_client_id):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        name = 'C%d' % my_client_id
        prefix = 'Player-Data/%s' % name
        ctx.load_cert_chain(certfile=prefix + '.pem', keyfile=prefix + '.key')
        ctx.load_verify_locations(capath='Player-Data')

        self.sockets = []
        for i, hostname in enumerate(hostnames):
            for j in range(10000):
                try:
                    plain_socket = socket.create_connection(
                        (hostname, port_base + i))
                    break
                except ConnectionRefusedError:
                    if j < 60:
                        time.sleep(1)
                    else:
                        raise
                    
            if platform.system() == "Linux":
                set_keepalive_linux(plain_socket)
            elif platform.system() == "Darwin":
                set_keepalive_osx(plain_socket)

            octetStream(b'%d' % my_client_id).Send(plain_socket)
            self.sockets.append(ctx.wrap_socket(plain_socket,
                                                server_hostname='P%d' % i))

        self.specification = octetStream()
        self.specification.Receive(self.sockets[0])
        for sock in self.sockets[1:]:
            specification = octetStream()
            specification.Receive(sock)
            if specification.buf != self.specification.buf:
                raise Exception('inconsistent specification')
        type = self.specification.get_int(4)
        if type == ord('R'):
            self.domain = Z2(self.specification.get_int(4))
            self.clear_domain = Z2(self.specification.get_int(4))
        elif type == ord('p'):
            self.domain = Fp(self.specification.get_bigint())
            self.clear_domain = self.domain
        else:
            raise Exception('invalid type')

    def receive_triples(self, T, n):
        triples = [[0, 0, 0] for i in range(n)]
        os = octetStream()
        for socket in self.sockets:
            os.Receive(socket)
            if socket == self.sockets[0]:
                active = os.get_length() == 3 * n * T.size()
            n_expected = 3 if active else 1
            if os.get_length() != n_expected * T.size() * n:
                import sys
                print (os.get_length(), n_expected, T.size(), n, active, file=sys.stderr)
                raise Exception('unexpected data length')
            for triple in triples:
                for i in range(n_expected):
                    t = T()
                    t.unpack(os)
                    triple[i] += t
        res = []
        if active:
            for triple in triples:
                prod = triple[0] * triple[1]
                if prod != triple[2]:
                    raise Exception(
                        'invalid triple, diff %s' % hex(prod.v - triple[2].v))
        return triples

    def send_private_inputs(self, values):
        """ Send inputs privately to the computation servers.
        This assumes that the client is connected to all servers.

        :param values: list of input values

        """
        T = self.domain
        triples = self.receive_triples(T, len(values))
        os = octetStream()
        assert len(values) == len(triples)
        for value, triple in zip(values, triples):
            (T(value) + triple[0]).pack(os)
        for socket in self.sockets:
            os.Send(socket)

    def receive_outputs(self, n):
        """ Receive outputs privately from the computation servers.
        This assumes that the client is connected to all servers.

        :param n: number of outputs

        """
        T = self.domain
        triples = self.receive_triples(T, n)
        return [int(self.clear_domain(triple[0].v)) for triple in triples]

    def send_public_inputs(self, values):
        """ Send values in the clear. This works for public inputs
        to all servers or to send shares to a single server.

        :param values: list of values

        """
        os = octetStream()
        for value in values:
            self.domain(value).pack(os)
        for socket in self.sockets:
            os.Send(socket)

    def receive_plain_values(self, socket=None):
        """ Receive values in the clear. This works for public inputs
        to all servers or to send shares to a single server.

        :param socket: socket to use (need to specify it there is more than one)

        """
        if socket is None:
            if len(self.sockets) != 1:
                raise Exception('need to specify socket')
            socket = self.sockets[0]
        os = octetStream()
        os.Receive(socket)
        assert len(os) % self.domain.size() == 0
        return [int(os.get(self.domain))
                for i in range(len(os) // self.domain.size())]

class octetStream:
    def __init__(self, value=None):
        self.buf = b''
        self.ptr = 0
        if value is not None:
            self.buf += value

    def get_length(self):
        return len(self.buf)

    __len__ = get_length

    def reset_write_head(self):
        self.buf = b''
        self.ptr = 0

    def Send(self, socket):
        socket.sendall(struct.pack('<i', len(self.buf)))
        socket.sendall(self.buf)

    def Receive(self, socket):
        buffer = socket.recv(4)
        if len(buffer) < 4:
            raise Exception('Error while receiving, check the other side')
        length = struct.unpack('<I', buffer)[0]
        self.buf = b''
        while len(self.buf) < length:
            self.buf += socket.recv(length - len(self.buf))
        self.ptr = 0

    def store(self, value):
        self.buf += struct.pack('<q', value)

    def get_int(self, length):
        buf = self.consume(length)
        if length == 4:
            return struct.unpack('<i', buf)[0]
        elif length == 8:
            return struct.unpack('<q', buf)[0]
        raise ValueError()

    def get_bigint(self):
        sign = self.consume(1)[0]
        assert(sign in (0, 1))
        length = self.get_int(4)
        if length:
            res = 0
            buf = self.consume(length)
            for i, b in enumerate(reversed(buf)):
                res += b << (i * 8)
            if sign:
                res *= -1
            return res
        else:
            return 0

    def get(self, type):
        res = type()
        res.unpack(self)
        return res

    def consume(self, length):
        self.ptr += length
        assert self.ptr <= len(self.buf)
        return self.buf[self.ptr - length:self.ptr]

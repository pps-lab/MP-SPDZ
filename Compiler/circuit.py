"""
This module contains functionality using circuits in the so-called
`Bristol Fashion`_ format. You can download a few examples including
the ones used below into ``Programs/Circuits`` as follows::

    make Programs/Circuits

.. _`Bristol Fashion`: https://nigelsmart.github.io/MPC-Circuits

"""
import math

from Compiler.GC.types import *
from Compiler.library import function_block, get_tape
from Compiler import util
import itertools
import struct
import os

from six import assertCountEqual


class Circuit:
    """
    Use a Bristol Fashion circuit in a high-level program. The
    following example adds signed 64-bit inputs from two different
    parties and prints the result::

        from circuit import Circuit
        sb64 = sbits.get_type(64)
        adder = Circuit('adder64')
        a, b = [sbitvec(sb64.get_input_from(i)) for i in (0, 1)]
        print_ln('%s', adder(a, b).elements()[0].reveal())

    Circuits can also be executed in parallel as the following example
    shows::

        from circuit import Circuit
        sb128 = sbits.get_type(128)
        key = sb128(0x2b7e151628aed2a6abf7158809cf4f3c)
        plaintext = sb128(0x6bc1bee22e409f96e93d7e117393172a)
        n = 1000
        aes128 = Circuit('aes_128')
        ciphertexts = aes128(sbitvec([key] * n), sbitvec([plaintext] * n))
        ciphertexts.elements()[n - 1].reveal().print_reg()

    This executes AES-128 1000 times in parallel and then outputs the
    last result, which should be ``0x3ad77bb40d7a3660a89ecaf32466ef97``,
    one of the test vectors for AES-128.

    """

    def __init__(self, name):
        self.name = name
        self.filename = 'Programs/Circuits/%s.txt' % name
        if not os.path.exists(self.filename):
            if os.system('make Programs/Circuits'):
                raise CompilerError('Cannot download circuit descriptions. '
                                    'Make sure make and git are installed.')
        f = open(self.filename)
        self.functions = {}

    def __call__(self, *inputs):
        return self.run(*inputs)

    def run(self, *inputs):
        n = inputs[0][0].n, get_tape()
        if n not in self.functions:
            self.functions[n] = function_block(
                lambda *args: self.compile(*args))
            self.functions[n].name = '%s(%d)' % (self.name, inputs[0][0].n)
        flat_res = self.functions[n](*itertools.chain(*inputs))
        res = []
        i = 0
        for l in self.n_output_wires:
            v = []
            for j in range(l):
                v.append(flat_res[i])
                i += 1
            res.append(sbitvec.from_vec(v))
        return util.untuplify(res)

    def compile(self, *all_inputs):
        f = open(self.filename)
        lines = iter(f)
        next_line = lambda: next(lines).split()
        n_gates, n_wires = (int(x) for x in next_line())
        self.n_wires = n_wires
        input_line = [int(x) for x in next_line()]
        n_inputs = input_line[0]
        n_input_wires = input_line[1:]
        assert(n_inputs == len(n_input_wires))
        inputs = []
        s = 0
        for n in n_input_wires:
            inputs.append(all_inputs[s:s + n])
            s += n
        output_line = [int(x) for x in next_line()]
        n_outputs = output_line[0]
        self.n_output_wires = output_line[1:]
        assert(n_outputs == len(self.n_output_wires))
        next(lines)

        wires = [None] * n_wires
        self.wires = wires
        i_wire = 0
        for input, input_wires in zip(inputs, n_input_wires):
            assert(len(input) == input_wires)
            for i, reg in enumerate(input):
                wires[i_wire] = reg
                i_wire += 1

        for i in range(n_gates):
            line = next_line()
            t = line[-1]
            if t in ('XOR', 'AND'):
                assert line[0] == '2'
                assert line[1] == '1'
                assert len(line) == 6
                ins = [wires[int(line[2 + i])] for i in range(2)]
                if t == 'XOR':
                    wires[int(line[4])] = ins[0] ^ ins[1]
                else:
                    wires[int(line[4])] = ins[0] & ins[1]
            elif t == 'INV':
                assert line[0] == '1'
                assert line[1] == '1'
                assert len(line) == 5
                wires[int(line[3])] = ~wires[int(line[2])]

        return self.wires[-sum(self.n_output_wires):]

Keccak_f = None

def sha3_256(x):
    """
    This function implements SHA3-256 for inputs of any length::

        from circuit import sha3_256
        a = sbitvec.from_vec([])
        b = sbitvec.from_hex('cc')
        c = sbitvec.from_hex('41fb')
        d = sbitvec.from_hex('1f877c')
        e = sbitvec.from_vec([sbit(0)] * 8)
        f = sbitvec.from_hex('41fb6834928423874832892983984728289238949827929283743858382828372f17188141fb6834928423874832892983984728289238949827929283743858382828372f17188141fb6834928423874832892983984728289238949827')
        g = sbitvec.from_hex('41fb6834928423874832892983984728289238949827929283743858382828372f17188141fb6834928423874832892983984728289238949827929283743858382828372f17188141fb6834928423874832892983984728289238949827929283743858382828372f17188141fb6834928423874832892983984728289238949827929283743858382828372f171881')
        h = sbitvec.from_vec([sbit(0)] * 3000)
        for x in a, b, c, d, e, f, g, h:
            sha3_256(x).reveal_print_hex()

    This should output the hashes of the above inputs, beginning with
    the `test vectors
    <https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/ShortMsgKAT_SHA3-256.txt>`_
    of SHA3-256 for 0, 8, 16, and 24 bits as well as the hash of the
    0 byte::

        Reg[0] = 0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a #
        Reg[0] = 0x677035391cd3701293d385f037ba32796252bb7ce180b00b582dd9b20aaad7f0 #
        Reg[0] = 0x39f31b6e653dfcd9caed2602fd87f61b6254f581312fb6eeec4d7148fa2e72aa #
        Reg[0] = 0xbc22345e4bd3f792a341cf18ac0789f1c9c966712a501b19d1b6632ccd408ec5 #
        Reg[0] = 0x5d53469f20fef4f8eab52b88044ede69c77a6a68a60728609fc4a65ff531e7d0 #
        Reg[0] = 0xf5f673ec50d662039871fd53fae3ced069baf09030132d6d60d2ba7040b02b18 #
        Reg[0] = 0xa8a42e808f9dc0f43366d5de91511f42e9c3f8f37de0307f010bf629401edd2a #
        Reg[0] = 0xf722631013ecacd42b4c7259e9fe22b8c81a86e9fe0d4a626800e7f50c5a8978 #


    """

    global Keccak_f
    if Keccak_f is None:
        # only one instance
        Keccak_f = Circuit('Keccak_f')

    # whole bytes
    assert len(x.v) % 8 == 0
    # rate
    r = 1088
    # round up to be multiple of rate
    length_with_suffix = len(x.v) + 8 # to handle the case the fixed padding overflows the block
    n_blocks = max(math.ceil(length_with_suffix / r), 1)
    upper_block_length = n_blocks * r

    if x.v:
        n = x.v[0].n
    else:
        n = 1
    d = sbitvec([sbits.get_type(8)(0x06)] * n)
    sbn = sbits.get_type(n)
    padding = [sbn(0)] * (upper_block_length - 8 - len(x.v))

    P_flat = x.v + d.v + padding
    assert len(P_flat) == upper_block_length
    P_flat[-1] = ~P_flat[-1] # set last bit to 1

    def flatten(S):
        res = [None] * 1600
        for y in range(5):
            for x in range(5):
                for i in range(w):
                    j = (5 * y + x) * w + i // 8 * 8 + 7 - i % 8
                    res[1600 - 1 - j] = S[x][y][i]
        return res

    def unflatten(S_flat):
        res = [[[None] * w for j in range(5)] for i in range(5)]
        for y in range(5):
            for x in range(5):
                for i in range(w):
                    j = (5 * y + x) * w + i // 8 * 8 + 7 - i % 8
                    res[x][y][i] = S_flat[1600 - 1 -j]
        return res

    w = 64
    # Initial state
    S = [[[sbn(0) for i in range(w)] for i in range(5)] for i in range(5)]
    def insert_block(local_S, local_P):
        assert len(local_P) == r
        P1 = [local_P[i * w:(i + 1) * w] for i in range(r // w)]
        for x in range(5):
            for y in range(5):
                if x + 5 * y < r // w:
                    for i in range(w):
                        local_S[x][y][i] ^= P1[x + 5 * y][i]

    for block_id in range(n_blocks):
        block = P_flat[block_id * r:(block_id + 1) * r]
        insert_block(S, block)
        S = unflatten(Keccak_f(flatten(S)))

    Z = []
    while len(Z) <= 256:
        for y in range(5):
            for x in range(5):
                if x + 5 * y < r // w:
                    Z += S[x][y]
        if len(Z) <= 256:
            S = unflatten(Keccak_f(flatten(S)))
    return sbitvec.from_vec(Z[:256])

class ieee_float:
    """
    This gives access IEEE754 floating-point operations using Bristol
    Fashion circuits. The following example computes the standard
    deviation of 10 integers input by each of party 0 and 1::

        from circuit import ieee_float

        values = []

        for i in range(2):
            for j in range(10):
                values.append(sbitint.get_type(64).get_input_from(i))

        fvalues = [ieee_float(x) for x in values]

        avg = sum(fvalues) / ieee_float(len(fvalues))
        var = sum(x * x for x in fvalues) / ieee_float(len(fvalues)) - avg * avg
        stddev = var.sqrt()

        print_ln('avg: %s', avg.reveal())
        print_ln('var: %s', var.reveal())
        print_ln('stddev: %s', stddev.reveal())
    """

    _circuits = {}
    is_clear = False

    @classmethod
    def circuit(cls, name):
        if name not in cls._circuits:
            cls._circuits[name] = Circuit('FP-' + name)
        return cls._circuits[name]

    def __init__(self, value):
        if isinstance(value, (sbitint, sbitintvec)):
            self.value = self.circuit('i2f')(sbitvec.conv(value))
        elif isinstance(value, sbitvec):
            self.value = value
        elif util.is_constant_float(value):
            self.value = sbitvec(sbits.get_type(64)(
                struct.unpack('Q', struct.pack('d', value))[0]))
        else:
            raise Exception('cannot convert type %s' % type(value))

    def __add__(self, other):
        return ieee_float(self.circuit('add')(self.value, other.value))

    def __radd__(self, other):
        if util.is_zero(other):
            return self
        else:
            return NotImplemented

    def __neg__(self):
        v = self.value.v[:]
        v[-1] = ~v[-1]
        return ieee_float(sbitvec.from_vec(v))

    def __sub__(self, other):
        return self + -other

    def __mul__(self, other):
        return ieee_float(self.circuit('mul')(self.value, other.value))

    def __truediv__(self, other):
        return ieee_float(self.circuit('div')(self.value, other.value))

    def __eq__(self, other):
        res = sbitvec.from_vec(self.circuit('eq')(self.value,
                                                  other.value).v[:1])
        if res.v[0].n == 1:
            return res.elements()[0]
        else:
            return res

    def sqrt(self):
        return ieee_float(self.circuit('sqrt')(self.value))

    def to_int(self):
        res = sbitintvec.from_vec(self.circuit('f2i')(self.value))
        if res.v[0].n == 1:
            return res.elements()[0]
        else:
            return res

    def reveal(self):
        assert self.value.v[0].n == 1
        m = self.value.v[:52]
        e = self.value.v[52:63]
        s = [self.value.v[63]]
        m, e, s = [sbitvec.from_vec(x).elements()[0].reveal()
                   for x in (m, e, s)]
        return cbitfloat(2 ** 52 + m, e - 2 ** 10 - 51,
                         cbit((m.to_regint() == 0) * (e.to_regint() == 0)), s,
                         (e.to_regint() == 2 ** 11 - 1))

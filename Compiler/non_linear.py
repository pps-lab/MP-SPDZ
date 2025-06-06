from .comparison import *
from .floatingpoint import *
from .types import *
from . import comparison, program

class NonLinear:
    def mod2m(self, a, k, m, signed):
        """
        a_prime = a % 2^m

        k: bit length of a
        m: compile-time integer
        signed: True/False, describes a
        """
        if not util.is_constant(m):
            raise CompilerError('m must be a public constant')
        if m >= k:
            return a
        else:
            return self._mod2m(a, k, m, signed)

    def trunc_pr(self, a, k, m, signed=True):
        if isinstance(a, types.cint):
            return shift_two(a, m)
        prog = program.Program.prog
        if prog.use_trunc_pr and m and (
                not prog.options.ring or \
                prog.use_trunc_pr <= (int(prog.options.ring) - k)):
            prog.reading('probabilistic truncation', 'DEK20')
            if prog.options.ring:
                comparison.require_ring_size(k, 'truncation')
            else:
                prog.curr_tape.require_bit_length(k + prog.security)
            if not signed:
                a -= (1 << (k - 1))
            res = sint()
            trunc_pr(res, a, k, m)
            if not signed:
                res += (1 << (k - m - 1))
            return res
        return self._trunc_pr(a, k, m, signed)

    def trunc_round_nearest(self, a, k, m, signed):
        res = sint()
        comparison.Trunc(res, a + (1 << (m - 1)), k + 1, m, signed)
        return res

    def trunc(self, a, k, m, signed):
        if m == 0:
            return a
        return self._trunc(a, k, m, signed)

    def ltz(self, a, k):
        return -self.trunc(a, k, k - 1, True)

class Masking(NonLinear):
    def eqz(self, a, k):
        c, r = self._mask(a, k)
        d = [None]*k
        for i,b in enumerate(r[0].bit_decompose_clear(c, k)):
            d[i] = r[i].bit_xor(b)
        return 1 - types.sintbit.conv(self.kor(d))

class Prime(Masking):
    """ Non-linear functionality modulo a prime with statistical masking. """
    def _mod2m(self, a, k, m, signed):
        res = sint()
        if m == 1:
            Mod2(res, a, k, signed)
        else:
            Mod2mField(res, a, k, m, signed)
        return res

    def _mask(self, a, k):
        return maskField(a, k)

    def _trunc_pr(self, a, k, m, signed=None):
        return TruncPrField(a, k, m)

    def _trunc(self, a, k, m, signed=None):
        a_prime = self.mod2m(a, k, m, signed)
        tmp = cint()
        inv2m(tmp, m)
        return (a - a_prime) * tmp

    def bit_dec(self, a, k, m, maybe_mixed=False):
        if maybe_mixed:
            return BitDecFieldRaw(a, k, m)
        else:
            return BitDecField(a, k, m)

    def kor(self, d):
        return KOR(d)

    def require_bit_length(self, bit_length, op):
        prog = program.Program.prog
        if bit_length > 32:
            prog.curr_tape.require_bit_length(bit_length - 1, reason=op)

class KnownPrime(NonLinear):
    """ Non-linear functionality modulo a prime known at compile time. """
    def __init__(self, prime):
        self.prime = prime

    def _mod2m(self, a, k, m, signed):
        if signed:
            a += cint(1) << (k - 1)
        prog = program.Program.prog
        return sint.bit_compose(self.bit_dec(a, k, m, prog.use_edabit()))

    def _trunc_pr(self, a, k, m, signed):
        # nearest truncation
        return self.trunc_round_nearest(a, k, m, signed)

    def _trunc(self, a, k, m, signed=None):
        return TruncZeros(a - self._mod2m(a, k, m, signed), k, m, signed)

    def trunc_round_nearest(self, a, k, m, signed):
        a += cint(1) << (m - 1)
        if signed:
            a += cint(1) << (k - 1)
            k += 1
        res = self._trunc(a, k, m, False)
        if signed:
            res -= cint(1) << (k - m - 2)
        return res

    def bit_dec(self, a, k, m, maybe_mixed=False):
        assert k <= self.prime.bit_length()
        bits = BitDecFull(a, m, maybe_mixed=maybe_mixed)
        assert len(bits) == m
        return bits

    def eqz(self, a, k):
        # always signed
        a += two_power(k)
        prog = program.Program.prog
        return 1 - types.sintbit.conv(KORL(
            self.bit_dec(a, k, k, prog.use_edabit())))

    def ltz(self, a, k):
        if k + 1 < self.prime.bit_length():
            # https://dl.acm.org/doi/10.1145/3474123.3486757
            # "negative" values wrap around when doubling, thus becoming odd
            return self.mod2m(2 * a, k + 1, 1, False)
        else:
            return super(KnownPrime, self).ltz(a, k)

    def require_bit_length(self, bit_length, op):
        pass

class Ring(Masking):
    """ Non-linear functionality modulo a power of two known at compile time.
    """
    def __init__(self, ring_size):
        self.ring_size = ring_size

    def _mod2m(self, a, k, m, signed):
        res = sint()
        Mod2mRing(res, a, k, m, signed)
        return res

    def _mask(self, a, k):
        return maskRing(a, k)

    def _trunc_pr(self, a, k, m, signed):
        return TruncPrRing(a, k, m, signed=signed)

    def _trunc(self, a, k, m, signed=None):
        return comparison.TruncRing(None, a, k, m, signed=signed)

    def bit_dec(self, a, k, m, maybe_mixed=False):
        if maybe_mixed:
            return BitDecRingRaw(a, k, m)
        else:
            return BitDecRing(a, k, m)

    def kor(self, d):
        return KORL(d)

    def trunc_round_nearest(self, a, k, m, signed):
        if k == self.ring_size:
            # cannot work with bit length k+1
            tmp = TruncRing(None, a, k, m - 1, signed)
            return TruncRing(None, tmp + 1, k - m + 1, 1, signed)
        else:
            return super(Ring, self).trunc_round_nearest(a, k, m, signed)

    def ltz(self, a, k):
        return LtzRing(a, k)

    def require_bit_length(self, bit_length, op):
        comparison.require_ring_size(bit_length, op)

# Copyright (c) 2025 Rivos, Inc.
# SPDX-License-Identifier: Apache2

"""OpenTitan ROM image support.

   :author: Emmanuel Blot <eblot@rivosinc.com>
"""

from binascii import hexlify
from io import BytesIO
from logging import getLogger
from typing import BinaryIO, Optional, Union

from ..util.elf import ElfBlob
from ..util.file import guess_file_type
from ..util.prince import PrinceCipher

# ruff: noqa: E402
_CRYPTO_EXC: Optional[Exception] = None
try:
    from Crypto.Hash import cSHAKE256
except ModuleNotFoundError:
    try:
        # see pip3 install -r requirements.txt
        from Cryptodome.Hash import cSHAKE256
    except ModuleNotFoundError as exc:
        _CRYPTO_EXC = exc


class ROMImage:
    """
    """

    ADDR_SUBST_PERM_ROUNDS = 2
    DATA_SUBST_PERM_ROUNDS = 2
    PRINCE_HALF_ROUNDS = 2
    DATA_BITS = 4 * 8
    ECC_BITS = 7
    WORD_BITS = DATA_BITS + ECC_BITS
    WORD_BYTES = (WORD_BITS + 7) // 8
    DIGEST_BYTES = 32
    DIGEST_WORDS = DIGEST_BYTES // 4

    SBOX4 = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
    SBOX4_INV = [5, 14, 15, 8, 12, 1, 2, 13, 11, 4, 6, 3, 0, 7, 9, 10]

    def __init__(self, name: Union[str, int, None] = None):
        logname = 'romimg'
        if isinstance(name, (int, str)):
            logname = f'{logname}.{name}'
        self._log = getLogger(logname)
        self._name = name
        self._data = b''
        self._key = 0
        self._nonce = 0
        self._addr_nonce = 0
        self._data_nonce = 0
        self._addr_width = 0
        self._khi = 0
        self._klo = 0
        self._digest = bytes(32)

    def load(self, rfp: BinaryIO, size: Optional[int] = None):
        ftype = guess_file_type(rfp)
        loader = getattr(self, f'_load_{ftype}', None)
        if not loader:
            raise ValueError(f'Unsupported ROM file type: {ftype}')
        loader(rfp, size)

    @property
    def digest(self):
        return self._digest

    @property
    def key(self):
        return self._key.to_bytes(16, 'big')

    @key.setter
    def key(self, value: bytes):
        if not isinstance(value, bytes):
            raise TypeError('Key must be bytes')
        self._key = int.from_bytes(value, 'big')
        self._khi = self._key >> 64
        self._klo = self._key & 0xFFFFFFFFFFFFFFFF

    @property
    def nonce(self):
        return self._nonce.to_bytes(8, 'big')

    @nonce.setter
    def nonce(self, value: bytes):
        if not isinstance(value, bytes):
            raise TypeError('Nonce must be bytes')
        self._nonce = int.from_bytes(value, 'big')
        self._addr_nonce = 0
        self._data_nonce = 0

    def _load_hex(self, rfp: BinaryIO, size: Optional[int] = None) -> None:
        data: list[int] = []  # 64-bit values
        for lpos, line in enumerate(rfp.readlines(), start=1):
            line = line.strip()
            if len(line) != 10:
                raise ValueError(f'Unsupported ROM HEX format at line {lpos}')
            try:
                data.append(int(line, 16))
            except ValueError as exc:
                raise ValueError(f'Invalid HEX data at line {lpos}: {exc}')
        word_size = lpos
        addr_bits = self.ctz(word_size)
        data_nonce_width = 64 - addr_bits
        self._addr_nonce = self._nonce >> data_nonce_width
        self._data_nonce = self._nonce & ((1 << data_nonce_width) - 1)
        self._addr_width = addr_bits
        self._log.info('data_nonce_width: %d', data_nonce_width)
        self._log.info('addr_width: %d', self._addr_width)
        self._log.info('addr_nonce: %06x', self._addr_nonce)
        self._log.info('data_nonce: %012x', self._data_nonce)
        self._log.info('key_hi:     %016x', self._khi)
        self._log.info('key_lo:     %016x', self._klo)
        digest = self._unscramble(data)
        bndigest = bytes(reversed(digest))
        self._log.info('digest:     %s', hexlify(bndigest).decode())
        self._digest = digest

    def _load_bin(self, rfp: BinaryIO, size: Optional[int] = None) -> None:
        if not size:
            raise ValueError('ROM size not specified')
        if _CRYPTO_EXC:
            raise ModuleNotFoundError('Crypto module not found')
        data = bytearray(rfp.read())
        # digest storage is not included in digest computation
        data_len = len(data)
        size -= self.DIGEST_BYTES
        if data_len > size:
            raise ValueError('ROM size is too small')
        if data_len < size:
           data.extend(bytes(size - data_len))
        shake = cSHAKE256.new(custom=b'ROM_CTRL')
        shake.update(data)
        digest = shake.read(32)
        self._log.info('size:       %d bytes', size)
        bndigest = bytes(reversed(digest))
        self._log.info('digest:     %s', hexlify(bndigest).decode())
        self._digest = digest
        self._data = data

    def _load_elf(self, rfp: BinaryIO, size: Optional[int] = None) -> None:
        elf = ElfBlob()
        elf.load(rfp)
        bin_io = BytesIO(elf.blob)
        self._load_bin(bin_io, size)

    @classmethod
    def ctz(cls, val):
        if val == 0:
            raise ValueError('CTZ undefined')
        pos = 0
        while (val & 1) == 0:
            val >>= 1
            pos += 1
        return pos

    @classmethod
    def bitswap(cls, in_, mask, shift):
        return ((in_ & mask) << shift) | ((in_ & ~mask) >> shift)

    @classmethod
    def bitswap64(cls, val):
        val = cls.bitswap(val, 0x5555555555555555, 1)
        val = cls.bitswap(val, 0x3333333333333333, 2)
        val = cls.bitswap(val, 0x0f0f0f0f0f0f0f0f, 4)
        val = cls.bitswap(val, 0x00ff00ff00ff00ff, 8)
        val = cls.bitswap(val, 0x0000ffff0000ffff, 16)
        val = (val << 32) | (val >> 32)

        return val

    @classmethod
    def sbox(cls, in_, width, sbox):
        assert width < 64

        full_mask = (1 << width) - 1
        width &= ~3
        sbox_mask = (1 << width) - 1

        out = in_ & (full_mask & ~sbox_mask)
        for ix in range(0, width, 4):
            nibble = (in_ >> ix) & 0xf
            out |= sbox[nibble] << ix

        return out

    @classmethod
    def flip(cls, in_, width):
        out = cls.bitswap64(in_)
        out >>= 64 - width

        return out

    @classmethod
    def perm(cls, in_, width, invert):
        assert width < 64

        full_mask = (1 << width) - 1
        width &= ~1
        bfly_mask = (1 << width) - 1

        out = in_ & (full_mask & ~bfly_mask)

        width >>= 1
        if not invert:
            for ix in range(width):
                bit = (in_ >> (ix << 1)) & 1
                out |= bit << ix
                bit = (in_ >> ((ix << 1) + 1)) & 1
                out |= bit << (width + ix)
        else:
            for ix in range(width):
                bit = (in_ >> ix) & 1
                out |= bit << (ix << 1)
                bit = (in_ >> (ix + width)) & 1
                out |= bit << ((ix << 1) + 1)

        return out

    @classmethod
    def subst_perm_enc(cls, in_, key, width, num_round):
        state = in_
        while num_round:
            num_round -= 1
            state ^= key
            state = cls.sbox(state, width, cls.SBOX4)
            state = cls.flip(state, width)
            state = cls.perm(state, width, False)
        state ^= key

        return state

    @classmethod
    def subst_perm_dec(cls, val, key, width, num_round):
        state = val
        while num_round:
            num_round -= 1
            state ^= key
            state = cls.perm(state, width, True)
            state = cls.flip(state, width)
            state = cls.sbox(state, width, cls.SBOX4_INV)
        state ^= key

        return state

    def addr_sp_enc(self, addr):
        return self.subst_perm_enc(addr, self._addr_nonce, self._addr_width,
                                   self.ADDR_SUBST_PERM_ROUNDS)

    @classmethod
    def data_sp_dec(cls, val):
        return cls.subst_perm_dec(val, 0, cls.WORD_BITS,
                                  cls.DATA_SUBST_PERM_ROUNDS)

    def _get_keystream(self, addr: int):
        scramble = (self._data_nonce << self._addr_width) | addr
        stream = PrinceCipher.run(scramble, self._khi, self._klo,
                                  self.PRINCE_HALF_ROUNDS)
        return stream & ((1 << self.WORD_BITS) - 1)

    def _unscramble_word(self, addr: int, value: int):
        keystream = self._get_keystream(addr)
        spd = self.data_sp_dec(value)
        return keystream ^ spd


    def _unscramble(self, src: list[int]) -> bytes:
        # do not attempt to detect or correct errors for now
        size = len(src)
        scr_word_size = (size - self.DIGEST_BYTES) // 4
        log_addr = 0
        dst: list[int] = [0] * size
        while log_addr < scr_word_size:
            phy_addr = self.addr_sp_enc(log_addr)
            assert(phy_addr < size)

            srcdata = src[phy_addr]
            clrdata = self._unscramble_word(log_addr, srcdata)
            dst[log_addr] = clrdata & 0xffffffff
            log_addr += 1
        wix = 0
        digest_parts: list[int] = []
        while wix < self.DIGEST_WORDS:
            phy_addr = self.addr_sp_enc(log_addr)
            assert(phy_addr < size)
            digest_parts.append(src[phy_addr] & 0xffffffff)
            wix += 1
            log_addr += 1
        digest = b''.join((dp.to_bytes(4, 'little') for dp in digest_parts))
        for addr in range(0x20, 0x30):
            self._log.debug('@ %06x: %08x', addr, dst[addr])
        data = bytearray()
        for val in dst:
            data.extend(val.to_bytes(4, 'little'))
        self._data = bytes(data)
        return digest

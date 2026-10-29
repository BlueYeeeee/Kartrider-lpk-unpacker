"""P3563 LPK v4 decoding, verified against 344 local archives.

Preserves native buffered-read order and the exact-drain counter reset.
Only flags 6/7 with zero section count are supported.
"""
import hashlib
import struct
import zlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

class LpkError(ValueError):
    """Unsupported, truncated, or invalid archive content."""

DEFAULT_MIXING = "NhucnUGGZIHvxdga"

MASK = bytes.fromhex('7b2f3548439502b9ae91a6e1d8d624b433101d3dc1bbc6f4a5feb3696b56e475')

class NativeReadStream:
    """Match native reads: round buffers to 64 bytes, reset only on exact drain."""

    def __init__(self, data, key, start=0):
        self.data, self.key, self.raw_position = (data, key, start)
        self.position = 0
        self.buffer = b''
        self.counter = 0

    def read(self, size):
        if not 0 < size <= 1 << 20:
            raise LpkError(size)
        requested = size
        output = bytearray()
        while size:
            if not self.buffer:
                length = (size + 63) // 64 * 64
                raw = self.data[self.raw_position:self.raw_position + length]
                if not len(raw) == length:
                    raise LpkError('truncated stream')
                nonce = struct.pack('<Q', self.counter) + bytes(8)
                self.buffer = Cipher(algorithms.ChaCha20(self.key, nonce), mode=None).decryptor().update(raw)
                self.counter += length // 64
                self.raw_position += length
            length = len(self.buffer)
            take = min(size, length)
            output.extend(self.buffer[:take])
            self.buffer = self.buffer[take:]
            size -= take
            if take == length and size == 0:
                # Crossing a buffer boundary does not reset this counter.
                self.counter = 0
        self.position += requested
        return bytes(output)

    def u32(self):
        return struct.unpack('<I', self.read(4))[0]

def decode(filename, mixing):
    disk = Path(filename).read_bytes()
    name = Path(filename).name.lower()
    name_sum = sum(map(ord, name))
    h = name_sum % 312 + 30
    if not struct.unpack('b', disk[:1])[0] >> 1 & 255 ^ disk[h] == 4:
        raise LpkError('Invalid LPK data')
    raw_length = struct.unpack_from('<I', disk, h + 1)[0] ^ struct.unpack('b', disk[:1])[0] >> 1 & 4294967295
    if not 0 < raw_length <= 1024:
        raise LpkError(raw_length)
    header_end = h + 5 + 2 * raw_length
    text = name + mixing
    header_key = bytes((ord(text[i % len(text)]) + i & 255 ^ MASK[i] for i in range(32)))
    header = NativeReadStream(disk, header_key, header_end)
    checksum, count = (header.u32(), header.u32())
    if not 0 < count < 100000:
        raise LpkError(count)
    start = header_end + 8 + name_sum * 3 % 212 + 64
    key = bytes((ord(text[-1 - i % len(text)]) * (2 + i % 3) + i & 255 ^ MASK[i] for i in range(32)))
    stream = NativeReadStream(disk, key, start)
    records = []
    for _ in range(count):
        plen = stream.u32()
        if not 0 < plen <= 4096:
            raise LpkError(plen)
        path = stream.read(plen * 2).decode('utf-16le')
        csum, flags, blocks, dsize, csize, extra, sections = [stream.u32() for _ in range(7)]
        if not flags in (6, 7):
            raise LpkError((path, flags))
        if not sections == 0:
            raise LpkError((path, sections))
        digest = stream.read(16)
        tag_low, tag_high = (stream.u32(), stream.u32())
        if not csum == flags + blocks + dsize + csize + sum(digest) & 4294967295:
            raise LpkError(path)
        records.append({'path': path, 'plen': plen, 'csum': csum, 'flags': flags, 'blocks': blocks, 'dsize': dsize, 'csize': csize, 'md5': digest.hex(), 'extra': extra, 'tag': struct.pack('<2I', tag_low, tag_high).hex()})
    # Align the underlying read-ahead position, not the logical table end.
    data_begin = (stream.raw_position + 1023) // 1024 * 1024
    for r in records:
        if not data_begin + r['blocks'] * 1024 + r['csize'] <= len(disk):
            raise LpkError(r['path'])
    return {'filename': name, 'fileCount': count, 'headerChecksum': checksum, 'tableStart': start, 'tableLength': stream.position, 'tableReadEnd': stream.raw_position, 'dataBegin': data_begin, 'records': records}

def parameters(mixing):
    value = 2166136261
    for c in mixing:
        value = (value ^ ord(c)) * 16777619 & 4294967295
    source = struct.pack('<3I', value, value >> 1, value >> 1 ^ 108)
    mask = bytes(((17 * i ^ 8 * i) + (i >> 2 ^ 90 + 43 * i) - i % 11 & 255 for i in range(12)))
    nonce = bytes((a ^ b for a, b in zip(source, mask)))
    return (list(map(int, str(value))), nonce[8:12] + bytes(4) + nonce[:8])

def extract(disk, record, digits, nonce):
    if not record['flags'] in (6, 7):
        raise LpkError('Invalid LPK data')
    start = record['dataBegin'] + record['blocks'] * 1024
    stored = disk[start:start + record['csize']]
    if not len(stored) == record['csize']:
        raise LpkError('Invalid LPK data')
    path = record['path'].encode('utf-16le')
    units = struct.unpack('<' + 'H' * (len(path) // 2), path)
    md5 = bytes.fromhex(record['md5'])
    key = []
    for i in range(32):
        value = (digits[(i + 1) % len(digits)] + i) % 5 + md5[digits[(i + 2) % len(digits)] + i & 15] + (digits[i % len(digits)] & 1)
        key.append((value & 255) * (units[i % len(units)] & 255) + i & 255 ^ MASK[i])
    length = min(1024, len(stored))
    clear = Cipher(algorithms.ChaCha20(bytes(key), nonce), mode=None).decryptor().update(stored[:length]) + stored[length:]
    if record['flags'] & 1:
        decoder = zlib.decompressobj()
        output = decoder.decompress(clear) + decoder.flush()
        if not decoder.eof:
            raise LpkError('incomplete zlib')
        trailing = len(decoder.unused_data)
        if trailing:
            used = len(clear) - trailing
            if not (len(clear) <= 1024 and (used + 63) // 64 * 64 == len(clear)):
                raise LpkError('unexpected zlib trailing bytes')
    else:
        expected = (record['dsize'] + 63) // 64 * 64 if record['dsize'] <= 1024 else record['dsize']
        if not len(clear) == expected:
            raise LpkError('unexpected uncompressed storage length')
        output = clear[:record['dsize']]
    if not len(output) == record['dsize']:
        raise LpkError('decoded size mismatch')
    if not hashlib.md5(output).hexdigest() == record['md5']:
        raise LpkError('MD5 mismatch')
    return output

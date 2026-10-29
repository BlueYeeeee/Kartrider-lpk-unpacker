import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from lpk_unpacker import main, output_path
from lpk_v4 import DEFAULT_MIXING, LpkError, NativeReadStream, decode, extract, parameters


class BufferTests(unittest.TestCase):
    def test_exact_drain_resets_but_crossing_keeps_counter(self):
        stream = NativeReadStream(bytes(512), bytes(32))
        stream.read(4)
        self.assertEqual((len(stream.buffer), stream.counter), (60, 1))
        stream.read(100)
        self.assertEqual((len(stream.buffer), stream.counter), (24, 2))
        stream.read(24)
        self.assertEqual((len(stream.buffer), stream.counter), (0, 0))
        self.assertEqual(stream.raw_position, 128)

    def test_truncated_input_is_rejected(self):
        with self.assertRaises(LpkError):
            NativeReadStream(bytes(63), bytes(32)).read(4)

    def test_archive_paths_stay_inside_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.assertEqual(output_path(root, 'stage/test.xml'), root / 'stage/test.xml')
            for path in ('../escape', '/absolute', 'C:/drive', 'a/../../escape', 'a\\escape', 'a//b'):
                with self.subTest(path=path), self.assertRaises(LpkError):
                    output_path(root, path)


@unittest.skipUnless(os.environ.get('LPK_DATA_DIR'), 'set LPK_DATA_DIR for original-data checks')
class OriginalDataTests(unittest.TestCase):
    def test_sample_extraction_corruption_and_overwrite(self):
        source = Path(os.environ['LPK_DATA_DIR']) / 'DataPack9_00040.lpk'
        index = decode(source, DEFAULT_MIXING)
        self.assertEqual((index['fileCount'], index['dataBegin']), (391, 0xD000))
        record = next(r for r in index['records'] if r['path'] == 'stage/tuning/paramGraphLine.png')
        record = {**record, 'dataBegin': index['dataBegin']}
        digits, nonce = parameters(DEFAULT_MIXING)
        disk = source.read_bytes()
        data = extract(disk, record, digits, nonce)
        self.assertEqual(hashlib.md5(data).hexdigest(), 'bffd37482f641323b16f6d10547cf996')
        broken = bytearray(disk)
        broken[record['dataBegin'] + record['blocks'] * 1024] ^= 1
        with self.assertRaises(LpkError):
            extract(broken, record, digits, nonce)
        with tempfile.TemporaryDirectory() as folder:
            args = [str(source), '--path', record['path'], '--output', folder]
            self.assertEqual(main(args), 0)
            target = output_path(Path(folder), record['path'])
            before = target.read_bytes()
            with self.assertRaises(LpkError):
                main(args)
            self.assertEqual(target.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()

import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from forensic_imager.core import Control, Disk, Options
from forensic_imager.ewf import EwfSink, EwfTools


class EwfIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tools = EwfTools.discover()
        if self.tools is None:
            self.skipTest("libewf CLI absent : test E01 réel non exécuté")
        parent = Path.home() / "ForensicImager-tests"
        parent.mkdir(exist_ok=True)
        self.temp = TemporaryDirectory(dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def test_real_ewf_roundtrip_all_compression_modes(self):
        for compression in ("none", "fast", "best"):
            with self.subTest(compression=compression):
                self.tools.probe(self.directory, compression)

    def test_real_writer_handles_dotted_name_4k_geometry_and_metadata(self):
        data = bytes(range(256)) * 512
        disk = Disk(99, "synthetic", "Test", "", len(data), 4096, "", "test")
        options = Options(
            disk,
            self.directory / "preuve.42.E01",
            format="E01",
            examiner="Élodie",
            case_number="42",
            description="Test synthétique",
        )
        control = Control()
        sink = EwfSink(options.destination, control, self.tools, options)
        self.addCleanup(sink.abort)
        sink.write(data)
        sink.finish()
        actual = b"".join(sink.chunks(32768))
        self.assertEqual(hashlib.sha256(actual).digest(), hashlib.sha256(data).digest())
        image = sink.publish()
        self.assertEqual(image.name, "preuve.42.E01")
        self.assertTrue(image.exists())


if __name__ == "__main__":
    unittest.main()

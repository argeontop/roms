"""Tests synthétiques : aucun disque physique n'est ouvert."""

import hashlib
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from forensic_imager.core import (
    Acquisition,
    BadSector,
    Cancelled,
    Control,
    Disk,
    Options,
    Progress,
    RawSink,
)


class MemorySource:
    def __init__(self, data, bad_offsets=(), sector_size=512):
        self.data = data
        self.bad_offsets = set(bad_offsets)
        self.sector_size = sector_size
        self.reads = []
        self.closed = False

    def read_at(self, offset, size):
        self.reads.append((offset, size))
        if any(offset <= bad < offset + size for bad in self.bad_offsets):
            raise BadSector("CRC synthétique")
        return self.data[offset : offset + size]

    def close(self):
        self.closed = True


class CoreTests(unittest.TestCase):
    def setUp(self):
        parent = Path.home() / "ForensicImager-tests"
        parent.mkdir(exist_ok=True)
        self.temp = TemporaryDirectory(dir=parent)
        self.directory = Path(self.temp.name)
        self.data = bytes(range(256)) * 34
        self.disk = Disk(99, "synthetic", "Test", "SERIAL", len(self.data), 512, "", "test")
        self.options = Options(
            self.disk,
            self.directory / "preuve.dd",
            algorithms=("md5", "sha1", "sha256"),
            block_size=1024,
            examiner="Élodie",
            case_number="CAS-42",
            description="Données synthétiques",
        )
        self.control = Control()
        self.events = []

    def tearDown(self):
        self.temp.cleanup()

    def acquire(self, source=None, sink_factory=RawSink, emit=None, options=None):
        source = source or MemorySource(self.data)
        acquisition = Acquisition(
            options or self.options,
            self.directory,
            lambda: source,
            sink_factory,
            self.control,
            emit or self.events.append,
        )
        result = acquisition.run()
        self.assertTrue(source.closed)
        self.assertTrue(Path(result.report).is_file())
        return result

    def test_three_passes_all_hashes_and_exact_tail(self):
        source = MemorySource(self.data)

        def sink_factory(target, control):
            self.assertEqual(sum(size for _, size in source.reads), len(self.data))
            return RawSink(target, control)

        result = self.acquire(source, sink_factory)
        expected = {
            name: hashlib.new(name, self.data).hexdigest() for name in self.options.algorithms
        }
        self.assertEqual(result.status, "CONFORME")
        self.assertEqual(result.hashes_before, expected)
        self.assertEqual(result.hashes_copy, expected)
        self.assertEqual(result.hashes_after, expected)
        self.assertEqual(Path(result.image).read_bytes(), self.data)
        self.assertEqual(sum(size for _, size in source.reads), len(self.data) * 2)
        report = Path(result.report).read_text(encoding="utf-8")
        self.assertIn("Élodie", report)
        self.assertIn("CAS-42", report)

    def test_bad_sector_is_zero_filled_without_shifting_following_bytes(self):
        source = MemorySource(self.data, bad_offsets=(512, 8192))
        result = self.acquire(source)
        expected = bytearray(self.data)
        expected[512:1024] = bytes(512)
        expected[8192:8704] = bytes(512)
        self.assertTrue(result.status.startswith("DÉGRADÉ"))
        self.assertEqual(Path(result.image).read_bytes(), expected)
        self.assertEqual(result.bad_sectors, {"Hash source avant copie": 2, "Copie": 2})
        log = (self.directory / "acquisition.log").read_text(encoding="utf-8")
        self.assertIn("LBA=1", log)
        self.assertIn("LBA=16", log)

    def test_4k_logical_sectors_and_sub_block_final_read(self):
        data = bytes(range(256)) * 48
        disk = replace(self.disk, size=len(data), sector_size=4096)
        options = replace(self.options, disk=disk, block_size=8192)
        result = self.acquire(MemorySource(data, (4096,), 4096), options=options)
        expected = data[:4096] + bytes(4096) + data[8192:]
        self.assertEqual(Path(result.image).read_bytes(), expected)
        self.assertEqual(result.bad_sectors["Copie"], 1)

    def test_source_changes_between_passes_is_not_validated(self):
        source = MemorySource(self.data)

        def sink_factory(target, control):
            source.data = bytes(len(self.data))
            return RawSink(target, control)

        result = self.acquire(source, sink_factory)
        self.assertTrue(result.status.startswith("NON CONFORME"))
        self.assertNotEqual(result.hashes_before, result.hashes_after)
        self.assertEqual(result.hashes_copy, result.hashes_after)

    def test_bad_sector_recovers_only_on_copy_is_mismatch(self):
        source = MemorySource(self.data, (512,))

        def sink_factory(target, control):
            source.bad_offsets.clear()
            return RawSink(target, control)

        result = self.acquire(source, sink_factory)
        self.assertTrue(result.status.startswith("NON CONFORME"))

    def test_destination_corruption_detected_after_writer_close(self):
        class CorruptSink(RawSink):
            def finish(self):
                super().finish()
                with self.partial.open("r+b") as stream:
                    stream.write(b"CORRUPTED")

        result = self.acquire(sink_factory=CorruptSink)
        self.assertTrue(result.status.startswith("NON CONFORME"))
        self.assertEqual(result.hashes_before, result.hashes_copy)
        self.assertNotEqual(result.hashes_copy, result.hashes_after)

    def test_short_read_is_fatal_not_zero_filled(self):
        result = self.acquire(MemorySource(self.data[:-1]))
        self.assertTrue(result.status.startswith("ÉCHEC"))
        self.assertEqual(result.bad_sectors, {})
        self.assertFalse(result.image)

    def test_disconnect_during_copy_preserves_partial_and_report(self):
        source = MemorySource(self.data)

        def sink_factory(target, control):
            source.read_at = lambda offset, size: (_ for _ in ()).throw(
                OSError("Périphérique déconnecté")
            )
            return RawSink(target, control)

        result = self.acquire(source, sink_factory)
        self.assertTrue(result.status.startswith("ÉCHEC"))
        self.assertTrue((self.directory / "preuve.dd.partial").exists())
        self.assertFalse((self.directory / "preuve.dd").exists())
        self.assertIn("déconnecté", result.error)

    def test_disk_full_never_becomes_success(self):
        class FullSink(RawSink):
            def write(self, data):
                raise OSError(28, "No space left")

        result = self.acquire(sink_factory=FullSink)
        self.assertTrue(result.status.startswith("ÉCHEC"))
        self.assertFalse(result.hashes_after)

    def test_space_precheck_prevents_source_read(self):
        source = MemorySource(self.data)
        with patch("forensic_imager.core.shutil.disk_usage") as usage:
            usage.return_value.free = 0
            result = self.acquire(source)
        self.assertTrue(result.status.startswith("ÉCHEC"))
        self.assertEqual(source.reads, [])

    def test_cancel_during_copy_keeps_partial(self):
        def emit(event):
            if isinstance(event, Progress) and event.phase == "Copie" and event.done == 0:
                self.control.cancel()

        result = self.acquire(emit=emit)
        self.assertTrue(result.status.startswith("ANNULÉ"))
        self.assertFalse(result.hashes_after)
        self.assertTrue((self.directory / "preuve.dd.partial").exists())

    def test_cancel_while_paused_wakes_worker(self):
        self.control.pause()
        waiting = threading.Event()
        ended = threading.Event()

        def wait_for_resume():
            waiting.set()
            try:
                self.control.checkpoint()
            except Cancelled:
                ended.set()

        worker = threading.Thread(target=wait_for_resume)
        worker.start()
        self.assertTrue(waiting.wait(1))
        self.assertFalse(ended.is_set())
        self.control.cancel()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertTrue(ended.is_set())

    def test_pause_then_resume(self):
        self.control.pause()
        passed = threading.Event()

        def proceed():
            self.control.checkpoint()
            passed.set()

        worker = threading.Thread(target=proceed)
        worker.start()
        self.assertFalse(passed.wait(0.05))
        self.control.resume()
        worker.join(2)
        self.assertTrue(passed.is_set())

    def test_existing_image_never_overwritten(self):
        target = self.directory / "preuve.dd"
        target.write_bytes(b"EXISTING")
        result = self.acquire()
        self.assertTrue(result.status.startswith("ÉCHEC"))
        self.assertEqual(target.read_bytes(), b"EXISTING")

    def test_malformed_geometry_rejected(self):
        options = replace(self.options, disk=replace(self.disk, size=123))
        acquisition = Acquisition(
            options,
            self.directory,
            lambda: self.fail("source opened"),
            RawSink,
            self.control,
            self.events.append,
        )
        result = acquisition.run()
        self.assertTrue(result.status.startswith("ÉCHEC"))

    def test_report_fallback_when_destination_disappears(self):
        acquisition = Acquisition(
            self.options,
            self.directory / "missing",
            lambda: MemorySource(self.data),
            RawSink,
            self.control,
            self.events.append,
        )
        with patch("forensic_imager.core.Path.home", return_value=self.directory):
            result = acquisition.run()
        self.assertTrue(result.status.startswith("ÉCHEC"))
        self.assertIn("ForensicImager-reports", result.report)
        self.assertTrue(Path(result.report).is_file())


if __name__ == "__main__":
    unittest.main()

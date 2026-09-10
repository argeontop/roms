import struct
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

import pywintypes
import win32con

from forensic_imager.core import BadSector, Control, Disk
from forensic_imager.windows import (
    IOCTL_DISK_GET_DISK_ATTRIBUTES,
    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
    IOCTL_DISK_GET_LENGTH_INFO,
    IOCTL_STORAGE_CHECK_VERIFY2,
    PhysicalSource,
    validate_destination,
    validate_identity,
)


class WindowsTests(unittest.TestCase):
    def setUp(self):
        self.disk = Disk(7, r"\\.\PhysicalDrive7", "test", "serial", 8192, 512, "", "USB")
        self.control = Control()

    def io_control(self, handle, code, input_buffer, output_size):
        if code == IOCTL_DISK_GET_LENGTH_INFO:
            return struct.pack("<q", 8192)
        if code == IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
            return struct.pack("<qIIIIq", 1, 12, 1, 16, 512, 8192)
        if code == IOCTL_DISK_GET_DISK_ATTRIBUTES:
            return struct.pack("<IIQ", 16, 0, 2)
        if code == IOCTL_STORAGE_CHECK_VERIFY2:
            return b""
        raise AssertionError(code)

    def make_source(self, ioctl=None):
        identity = patch("forensic_imager.windows.validate_identity")
        create = patch("forensic_imager.windows.win32file.CreateFile")
        device_io = patch(
            "forensic_imager.windows.win32file.DeviceIoControl",
            side_effect=ioctl or self.io_control,
        )
        identity.start()
        create_mock = create.start()
        create_mock.return_value.__int__.return_value = 123
        device_io.start()
        self.addCleanup(identity.stop)
        self.addCleanup(create.stop)
        self.addCleanup(device_io.stop)
        source = PhysicalSource(self.disk, True, self.control)
        self.addCleanup(source.close)
        return source, create_mock

    def test_source_handle_is_always_read_only(self):
        _, create = self.make_source()
        self.assertEqual(create.call_args.args[1], win32con.GENERIC_READ)
        self.assertEqual(create.call_args.args[4], win32con.OPEN_EXISTING)

    def test_forced_readonly_refuses_unprotected_disk(self):
        def ioctl(handle, code, input_buffer, output_size):
            if code == IOCTL_DISK_GET_DISK_ATTRIBUTES:
                return struct.pack("<IIQ", 16, 0, 0)
            return self.io_control(handle, code, input_buffer, output_size)

        with self.assertRaisesRegex(OSError, "Lecture seule forcée"):
            self.make_source(ioctl)

    def test_crc_is_recoverable_only_when_media_present(self):
        source, _ = self.make_source()
        with (
            patch("forensic_imager.windows.win32file.SetFilePointer"),
            patch(
                "forensic_imager.windows.win32file.ReadFile",
                side_effect=pywintypes.error(23, "ReadFile", "CRC"),
            ),
            self.assertRaises(BadSector),
        ):
            source.read_at(0, 512)

    def test_io_error_with_disconnected_media_is_fatal(self):
        def ioctl(handle, code, input_buffer, output_size):
            if code == IOCTL_STORAGE_CHECK_VERIFY2:
                raise pywintypes.error(1167, "DeviceIoControl", "disconnected")
            return self.io_control(handle, code, input_buffer, output_size)

        source, _ = self.make_source(ioctl)
        with (
            patch("forensic_imager.windows.win32file.SetFilePointer"),
            patch(
                "forensic_imager.windows.win32file.ReadFile",
                side_effect=pywintypes.error(1117, "ReadFile", "I/O error"),
            ),
        ):
            with self.assertRaises(OSError) as result:
                source.read_at(0, 512)
        self.assertNotIsInstance(result.exception, BadSector)

    def test_same_disk_destination_refused_even_with_different_letter(self):
        with (
            patch("forensic_imager.windows.destination_disks", return_value=({7}, "NTFS")),
            self.assertRaisesRegex(OSError, "disque source"),
        ):
            validate_destination(Path("Z:/"), self.disk, "raw")

    def test_spanned_volume_containing_source_is_refused(self):
        with (
            patch("forensic_imager.windows.destination_disks", return_value=({5, 7}, "NTFS")),
            self.assertRaisesRegex(OSError, "disque source"),
        ):
            validate_destination(Path("Z:/"), self.disk, "E01")

    def test_distinct_physical_destination_accepted(self):
        other = replace(self.disk, number=9)
        with (
            patch("forensic_imager.windows.destination_disks", return_value=({9}, "NTFS")),
            patch("forensic_imager.windows.detect_disks", return_value=[other]),
        ):
            validate_destination(Path("Z:/"), self.disk, "raw")

    def test_reconnected_disk_with_different_serial_refused(self):
        with (
            patch(
                "forensic_imager.windows.detect_disks",
                return_value=[replace(self.disk, serial="other")],
            ),
            self.assertRaisesRegex(OSError, "changé"),
        ):
            validate_identity(self.disk)

    def test_active_system_disk_refused(self):
        with (
            patch(
                "forensic_imager.windows.detect_disks",
                return_value=[replace(self.disk, system=True)],
            ),
            self.assertRaisesRegex(OSError, "système"),
        ):
            validate_identity(self.disk)

    def test_cancel_reaches_both_source_and_ewf(self):
        source, ewf = Mock(), Mock()
        self.control.set_interrupt(source)
        self.control.set_interrupt(ewf, "ewf")
        self.control.cancel()
        source.assert_called_once()
        ewf.assert_called_once()


if __name__ == "__main__":
    unittest.main()

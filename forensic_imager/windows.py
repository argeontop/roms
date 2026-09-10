"""Accès Windows. Aucune ouverture en écriture ni modification du disque source."""

from __future__ import annotations

import ctypes
import struct
import subprocess
import sys
import threading
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Protocol, cast

import pythoncom
import pywintypes
import win32api
import win32com.client
import win32con
import win32file

from forensic_imager.core import BadSector, Control, Disk

IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0
IOCTL_DISK_GET_DISK_ATTRIBUTES = 0x000700F0
IOCTL_STORAGE_CHECK_VERIFY2 = 0x002D0800
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000
DISK_ATTRIBUTE_READ_ONLY = 2
RECOVERABLE_ERRORS = {23, 27, 30, 1117}


class WmiRecord(Protocol):
    Index: int
    DeviceID: str
    Model: str | None
    SerialNumber: str | None
    Size: str | None
    BytesPerSector: int
    InterfaceType: str | None
    MediaType: str | None
    Number: int
    BusType: int
    IsSystem: bool
    IsBoot: bool
    LogicalSectorSize: int

    def Associators_(self, *, AssocClass: str) -> Iterable[WmiRecord]: ...


class WmiService(Protocol):
    def ExecQuery(self, query: str) -> Iterable[WmiRecord]: ...


def detect_disks() -> list[Disk]:
    """WMI via pywin32, y compris partitions sans lettre et disques USB."""
    pythoncom.CoInitialize()
    try:
        service = cast(WmiService, win32com.client.GetObject(r"winmgmts:\\.\root\cimv2"))
        storage = cast(
            WmiService,
            win32com.client.GetObject(r"winmgmts:\\.\root\Microsoft\Windows\Storage"),
        )
        modern = {int(row.Number): row for row in storage.ExecQuery("SELECT * FROM MSFT_Disk")}
        disks = []
        for row in service.ExecQuery("SELECT * FROM Win32_DiskDrive"):
            number = int(row.Index)
            info = modern.get(number)
            if info is None:
                # L'absence de MSFT_Disk empêche de vérifier le disque système.
                continue
            letters = []
            for partition in row.Associators_(AssocClass="Win32_DiskDriveToDiskPartition"):
                for volume in partition.Associators_(AssocClass="Win32_LogicalDiskToPartition"):
                    letters.append(volume.DeviceID)
            bus = int(info.BusType)
            kind = {
                7: "USB / externe",
                11: "SATA / interne probable",
                17: "NVMe / interne probable",
                1: "SCSI",
                8: "RAID",
                9: "iSCSI",
                14: "virtuel",
                15: "virtuel (fichier)",
                16: "Storage Spaces",
                12: "SD / amovible",
                13: "MMC / amovible",
            }.get(bus, row.InterfaceType or "inconnu")
            disks.append(
                Disk(
                    number=number,
                    path=row.DeviceID,
                    model=(row.Model or "").strip(),
                    serial=(row.SerialNumber or "").strip(),
                    size=int(info.Size or 0),
                    sector_size=int(info.LogicalSectorSize),
                    letters=", ".join(sorted(letters)),
                    kind=kind,
                    system=bool(info.IsSystem or info.IsBoot),
                )
            )
        return sorted(disks, key=lambda disk: disk.number)
    finally:
        pythoncom.CoUninitialize()


def is_admin() -> bool:
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def elevate(script: Path) -> bool:
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.ShellExecuteW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    shell.ShellExecuteW.restype = ctypes.c_void_p
    result = shell.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        subprocess.list2cmdline([str(script.resolve())]),
        str(script.resolve().parent),
        1,
    )
    return bool(result and result > 32)


def validate_identity(expected: Disk) -> None:
    actual = next((disk for disk in detect_disks() if disk.number == expected.number), None)
    if actual is None or (
        actual.path,
        actual.model,
        actual.serial,
        actual.size,
        actual.sector_size,
    ) != (expected.path, expected.model, expected.serial, expected.size, expected.sector_size):
        raise OSError("Le périphérique a changé depuis sa sélection. Rafraîchissez la liste.")
    if actual.system:
        raise OSError(
            "Le disque système/de démarrage actif est refusé. "
            "Démarrez Windows depuis un autre disque pour l'acquérir."
        )
    if "Storage Spaces" in actual.kind or "virtuel (fichier)" in actual.kind:
        raise OSError(
            "Source virtuelle/Storage Spaces non prise en charge en acquisition physique."
        )


def destination_disks(directory: Path) -> tuple[set[int], str]:
    """Résout aussi les points de montage et jonctions avant de lire les extents."""
    resolved = directory.resolve(strict=True)
    root = win32file.GetVolumePathName(str(resolved))
    if win32file.GetDriveType(root) not in (win32con.DRIVE_FIXED, win32con.DRIVE_REMOVABLE):
        raise OSError("Destination locale requise (pas de chemin réseau/SUBST non résolu).")
    volume = win32file.GetVolumeNameForVolumeMountPoint(root)
    handle = win32file.CreateFile(
        volume.rstrip("\\"),
        0,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
        None,
        win32con.OPEN_EXISTING,
        0,
        None,
    )
    try:
        data = win32file.DeviceIoControl(
            handle.handle, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, None, 65536
        )
        count = struct.unpack_from("<I", data)[0]
        if not count or len(data) < 8 + count * 24:
            raise OSError("Impossible d'identifier tous les disques de destination.")
        numbers = {struct.unpack_from("<I", data, 8 + index * 24)[0] for index in range(count)}
    finally:
        handle.Close()
    return numbers, win32api.GetVolumeInformation(root)[4]


def validate_destination(directory: Path, source: Disk, format_name: str) -> None:
    numbers, filesystem = destination_disks(directory)
    if source.number in numbers:
        raise OSError("La destination est sur le disque source : opération interdite.")
    if filesystem.upper() not in {"NTFS", "EXFAT", "REFS"}:
        raise OSError("Destination NTFS, exFAT ou ReFS requise (FAT32 non pris en charge).")
    # Des volumes virtuels peuvent masquer leur disque de stockage sous-jacent.
    inventory = {disk.number: disk for disk in detect_disks()}
    for number in numbers:
        disk = inventory.get(number)
        if disk is None or "virtuel (fichier)" in disk.kind or "Storage Spaces" in disk.kind:
            raise OSError("Impossible de prouver que la destination est physiquement distincte.")


class PhysicalSource:
    def __init__(self, disk: Disk, force_readonly: bool, control: Control) -> None:
        validate_identity(disk)
        self.disk = disk
        self.control = control
        self.handle = win32file.CreateFile(
            disk.path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_SEQUENTIAL_SCAN,
            None,
        )
        self.thread_handle: int | None = None
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CancelSynchronousIo.argtypes = [ctypes.c_void_p]
        self.kernel.CancelSynchronousIo.restype = ctypes.c_int
        self.kernel.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        self.kernel.OpenThread.restype = ctypes.c_void_p
        self.kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel.CloseHandle.restype = ctypes.c_int
        try:
            length = struct.unpack(
                "<q",
                win32file.DeviceIoControl(self.handle.handle, IOCTL_DISK_GET_LENGTH_INFO, None, 8),
            )[0]
            geometry = win32file.DeviceIoControl(
                self.handle.handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, None, 256
            )
            sector = struct.unpack_from("<I", geometry, 20)[0]
            if length != disk.size or sector != disk.sector_size:
                raise OSError("La géométrie réelle diffère de l'inventaire WMI.")
            if force_readonly:
                self.require_readonly()
            self.force_readonly = force_readonly
            self.thread_handle = cast(
                int | None,
                self.kernel.OpenThread(win32con.THREAD_TERMINATE, False, threading.get_native_id()),
            )
            if not self.thread_handle:
                raise ctypes.WinError(ctypes.get_last_error())
            control.set_interrupt(self.cancel_read)
        except Exception:
            self.close()
            raise

    def require_readonly(self) -> None:
        data = win32file.DeviceIoControl(
            self.handle.handle, IOCTL_DISK_GET_DISK_ATTRIBUTES, None, 16
        )
        attributes = struct.unpack_from("<Q", data, 8)[0]
        if not attributes & DISK_ATTRIBUTE_READ_ONLY:
            raise OSError(
                "Lecture seule forcée : Windows ne déclare pas ce disque en lecture seule. "
                "Préparez sa protection avant l'acquisition (voir le mode d'emploi), "
                "ou désactivez explicitement cette option. Le logiciel ne modifie pas cet attribut."
            )

    def cancel_read(self) -> None:
        if self.thread_handle:
            self.kernel.CancelSynchronousIo(int(self.thread_handle))

    def read_at(self, offset: int, size: int) -> bytes:
        self.control.checkpoint()
        if self.force_readonly:
            self.require_readonly()
        try:
            win32file.SetFilePointer(self.handle.handle, offset, win32con.FILE_BEGIN)
            # Les stubs pywin32 310 déclarent encore str pour ce buffer binaire.
            read_file = cast(Callable[[int, int], tuple[int, bytes]], win32file.ReadFile)
            _, data = read_file(self.handle.handle, size)
            return data
        except pywintypes.error as exc:
            self.control.checkpoint()
            if exc.winerror not in RECOVERABLE_ERRORS:
                raise OSError(f"Lecture arrêtée à {offset} : {exc}") from exc
            # Une déconnexion ne doit jamais devenir des gigaoctets de zéros.
            try:
                win32file.DeviceIoControl(self.handle.handle, IOCTL_STORAGE_CHECK_VERIFY2, None, 0)
            except pywintypes.error as presence_error:
                raise OSError(
                    f"Média absent ou état indéterminé à {offset} : {presence_error}"
                ) from presence_error
            raise BadSector(f"WinError {exc.winerror}: {exc.strerror}") from exc

    def close(self) -> None:
        self.control.set_interrupt(None)
        self.handle.Close()
        if self.thread_handle:
            self.kernel.CloseHandle(self.thread_handle)
            self.thread_handle = None

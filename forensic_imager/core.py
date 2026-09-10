"""Moteur indépendant de Tkinter : trois passes, journal et rapport persistants."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Protocol, TextIO

from forensic_imager import __version__

MIB = 1024 * 1024


@dataclass(frozen=True)
class Disk:
    number: int
    path: str
    model: str
    serial: str
    size: int
    sector_size: int
    letters: str
    kind: str
    system: bool = False

    @property
    def label(self) -> str:
        return (
            f"Disque {self.number} — {self.model} — {self.size / 1024**3:.2f} Gio "
            f"— {self.letters or 'sans lettre'} — {self.kind}"
        )


@dataclass(frozen=True)
class Options:
    disk: Disk
    destination: Path
    format: str = "raw"
    algorithms: tuple[str, ...] = ("sha256",)
    block_size: int = 4 * MIB
    force_readonly: bool = True
    compression: str = "fast"
    examiner: str = ""
    case_number: str = ""
    description: str = ""
    requested_format: str = "raw"


@dataclass(frozen=True)
class Progress:
    phase: str
    phase_index: int
    done: int
    total: int
    speed: float
    eta: float


@dataclass(frozen=True)
class Log:
    message: str


@dataclass
class Result:
    status: str = "EN COURS"
    error: str = ""
    started: str = field(default_factory=lambda: datetime.now().astimezone().isoformat())
    ended: str = ""
    duration: float = 0
    hashes_before: dict[str, str] = field(default_factory=dict)
    hashes_copy: dict[str, str] = field(default_factory=dict)
    hashes_after: dict[str, str] = field(default_factory=dict)
    bad_sectors: dict[str, int] = field(default_factory=dict)
    completed_bytes: dict[str, int] = field(default_factory=dict)
    report: str = ""
    image: str = ""


Event = Progress | Log | Result


class Cancelled(Exception):
    pass


class BadSector(OSError):
    """Erreur de média récupérable, après contrôle de présence du périphérique."""


class Control:
    def __init__(self) -> None:
        self.cancelled = threading.Event()
        self.running = threading.Event()
        self.running.set()
        self._lock = threading.Lock()
        self._interrupts: dict[str, Callable[[], None]] = {}

    def pause(self) -> None:
        self.running.clear()

    def resume(self) -> None:
        self.running.set()

    def cancel(self) -> None:
        self.cancelled.set()
        self.running.set()
        with self._lock:
            for callback in self._interrupts.values():
                callback()

    def set_interrupt(self, callback: Callable[[], None] | None, key: str = "source") -> None:
        with self._lock:
            if callback:
                self._interrupts[key] = callback
            else:
                self._interrupts.pop(key, None)
            if callback and self.cancelled.is_set():
                callback()

    def checkpoint(self) -> None:
        while not self.running.wait(0.1):
            if self.cancelled.is_set():
                raise Cancelled()
        if self.cancelled.is_set():
            raise Cancelled()


class Source(Protocol):
    def read_at(self, offset: int, size: int) -> bytes: ...
    def close(self) -> None: ...


class Sink(Protocol):
    def write(self, data: bytes) -> None: ...
    def finish(self) -> None: ...
    def chunks(self, block_size: int) -> Iterator[bytes]: ...
    def abort(self) -> None: ...
    def publish(self) -> Path: ...


class RawSink:
    def __init__(self, target: Path, control: Control) -> None:
        self.target = target
        self.partial = target.with_suffix(target.suffix + ".partial")
        self.file = self.partial.open("xb", buffering=0)

    def write(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = self.file.write(view)
            if not written:
                raise OSError("Écriture destination nulle.")
            view = view[written:]

    def finish(self) -> None:
        self.file.flush()
        os.fsync(self.file.fileno())
        self.file.close()

    def chunks(self, block_size: int) -> Iterator[bytes]:
        with self.partial.open("rb", buffering=0) as stream:
            while data := stream.read(block_size):
                yield data

    def abort(self) -> None:
        if not self.file.closed:
            self.file.close()

    def publish(self) -> Path:
        if self.target.exists():
            raise FileExistsError(self.target)
        self.partial.rename(self.target)
        return self.target


def check_space(directory: Path, remaining: int, format_name: str) -> None:
    # La compression n'est jamais supposée réduire la taille du média.
    reserve = max(64 * MIB, remaining // 20) if format_name == "E01" else 64 * MIB
    required = remaining + reserve
    if shutil.disk_usage(directory).free < required:
        raise OSError(
            f"Espace insuffisant : au moins {required / 1024**3:.2f} Gio libres requis "
            "(données restantes et marge comprises)."
        )


class Acquisition:
    def __init__(
        self,
        options: Options,
        directory: Path,
        source_factory: Callable[[], Source],
        sink_factory: Callable[[Path, Control], Sink],
        control: Control,
        emit: Callable[[Event], None],
    ) -> None:
        self.options = options
        self.directory = directory
        self.source_factory = source_factory
        self.sink_factory = sink_factory
        self.control = control
        self.emit = emit
        self.result = Result()
        self.audit: TextIO | None = None
        self._last_progress = 0.0
        self._last_log = 0.0
        self._phase_start = 0.0

    def record(self, message: str) -> None:
        line = f"{datetime.now().astimezone().isoformat()} {message}"
        if self.audit:
            self.audit.write(line + "\n")
        self.emit(Log(line))

    def progress(self, phase: str, index: int, done: int) -> None:
        now = time.monotonic()
        self.result.completed_bytes[phase] = done
        if now - self._last_progress < 0.2 and done != self.options.disk.size:
            return
        self._last_progress = now
        speed = done / max(now - self._phase_start, 0.001)
        eta = (self.options.disk.size - done) / speed if speed else 0.0
        self.emit(Progress(phase, index, done, self.options.disk.size, speed, eta))
        if now - self._last_log >= 2 or done == self.options.disk.size:
            self._last_log = now
            self.record(
                f"{phase} : {done} octets traités, "
                f"{done // self.options.disk.sector_size} secteurs."
            )

    def recovered_read(self, source: Source, offset: int, size: int, phase: str) -> bytes:
        self.control.checkpoint()
        try:
            data = source.read_at(offset, size)
            if len(data) != size:
                raise OSError("Lecture courte : périphérique tronqué ou déconnecté.")
            return data
        except BadSector:
            pass

        sector_size = self.options.disk.sector_size
        recovered = bytearray()
        failures = 0
        # Un bloc défectueux est relu secteur par secteur, sans décaler l'image.
        for position in range(offset, offset + size, sector_size):
            self.control.checkpoint()
            length = min(sector_size, offset + size - position)
            for attempt in range(2):
                try:
                    data = source.read_at(position, length)
                    if len(data) != length:
                        raise OSError(f"Lecture courte à l'offset {position}.")
                    break
                except BadSector as exc:
                    if attempt == 0:
                        continue
                    data = bytes(length)
                    failures += 1
                    self.result.bad_sectors[phase] = self.result.bad_sectors.get(phase, 0) + 1
                    if self.audit:
                        self.audit.write(
                            f"{phase} SECTEUR ILLISIBLE offset={position} "
                            f"LBA={position // sector_size} octets={length} "
                            f"remplacement=00 erreur={exc}\n"
                        )
            recovered.extend(data)
        if failures:
            self.record(
                f"{phase} : {failures} secteurs remplacés par des zéros à partir de {offset}."
            )
        return bytes(recovered)

    def source_pass(
        self, source: Source, phase: str, index: int, sink: Sink | None
    ) -> dict[str, str]:
        hashes = {name: hashlib.new(name) for name in self.options.algorithms}
        self._phase_start = time.monotonic()
        self.record(f"Début : {phase}")
        self.progress(phase, index, 0)
        last_space_check = 0.0
        for offset in range(0, self.options.disk.size, self.options.block_size):
            self.control.checkpoint()
            if sink and time.monotonic() - last_space_check > 1:
                check_space(self.directory, self.options.disk.size - offset, self.options.format)
                last_space_check = time.monotonic()
            data = self.recovered_read(
                source, offset, min(self.options.block_size, self.options.disk.size - offset), phase
            )
            if sink:
                sink.write(data)
            for digest in hashes.values():
                digest.update(data)
            self.progress(phase, index, offset + len(data))
        return {name: digest.hexdigest() for name, digest in hashes.items()}

    def verify(self, sink: Sink) -> dict[str, str]:
        hashes = {name: hashlib.new(name) for name in self.options.algorithms}
        done = 0
        self._phase_start = time.monotonic()
        self.record("Début : vérification de l'image après fermeture du writer")
        self.progress("Vérification", 2, 0)
        for data in sink.chunks(self.options.block_size):
            self.control.checkpoint()
            done += len(data)
            if done > self.options.disk.size:
                raise OSError("Image plus grande que la source.")
            for digest in hashes.values():
                digest.update(data)
            self.progress("Vérification", 2, done)
        if done != self.options.disk.size:
            raise OSError(f"Image incomplète : {done}/{self.options.disk.size} octets.")
        return {name: digest.hexdigest() for name, digest in hashes.items()}

    def run(self) -> Result:
        source: Source | None = None
        sink: Sink | None = None
        started = time.monotonic()
        try:
            if not self.options.algorithms or not set(self.options.algorithms) <= {
                "md5",
                "sha1",
                "sha256",
            }:
                raise ValueError("Sélectionnez au moins un hash valide.")
            disk = self.options.disk
            if disk.size <= 0 or disk.sector_size <= 0 or disk.size % disk.sector_size:
                raise ValueError("Géométrie du disque invalide.")
            if self.options.block_size <= 0 or self.options.block_size % disk.sector_size:
                raise ValueError("Le buffer doit être un multiple de la taille de secteur.")
            self.audit = (self.directory / "acquisition.log").open(
                "x", encoding="utf-8", buffering=1
            )
            self.record(f"Forensic Imager {__version__} — source {disk.path}")
            self.record(
                f"Format demandé={self.options.requested_format}, effectif={self.options.format}; "
                f"lecture seule forcée={self.options.force_readonly}"
            )
            self.control.checkpoint()
            source = self.source_factory()
            check_space(self.directory, disk.size, self.options.format)
            self.result.hashes_before = self.source_pass(source, "Hash source avant copie", 0, None)
            self.control.checkpoint()
            target = self.directory / self.options.destination.name
            sink = self.sink_factory(target, self.control)
            self.result.hashes_copy = self.source_pass(source, "Copie", 1, sink)
            sink.finish()
            self.result.hashes_after = self.verify(sink)
            self.control.checkpoint()
            equal = self.result.hashes_before == self.result.hashes_copy == self.result.hashes_after
            self.result.status = "CONFORME" if equal else "NON CONFORME — HASH DIFFÉRENTS"
            if equal and self.result.bad_sectors:
                self.result.status = "DÉGRADÉ — HASH NORMALISÉS CONCORDANTS"
            self.result.image = str(sink.publish())
            self.record(self.result.status)
        except Cancelled:
            self.result.status = "ANNULÉ — IMAGE NON VALIDÉE"
        except Exception as exc:
            self.result.status = (
                "ANNULÉ — IMAGE NON VALIDÉE"
                if self.control.cancelled.is_set()
                else "ÉCHEC — IMAGE NON VALIDÉE"
            )
            self.result.error = f"{type(exc).__name__}: {exc}"
        finally:
            self.control.set_interrupt(None)
            for resource in (sink, source):
                if resource:
                    try:
                        if resource is sink:
                            sink.abort()
                        elif source:
                            source.close()
                    except Exception as exc:
                        self.result.error += f"\nFermeture : {exc}"
                        self.result.status = "ÉCHEC — ERREUR DE FERMETURE"
            if self.audit:
                try:
                    self.audit.close()
                except OSError as exc:
                    self.result.error += f"\nJournal : {exc}"
                    self.result.status = "ÉCHEC — JOURNAL NON FINALISÉ"
            self.result.ended = datetime.now().astimezone().isoformat()
            self.result.duration = time.monotonic() - started
            self.save_report()
            self.emit(self.result)
        return self.result

    def save_report(self) -> None:
        self.result.report = str(self.directory / "rapport.txt")
        options = asdict(self.options)
        options["destination"] = str(self.options.destination)
        text = (
            f"RAPPORT D'ACQUISITION FORENSIQUE — version {__version__}\n"
            f"Résultat : {self.result.status}\n"
            f"Début : {self.result.started}\nFin : {self.result.ended}\n"
            f"Durée : {self.result.duration:.2f} secondes (pauses incluses)\n\n"
            "PARAMÈTRES ET IDENTITÉ DU MÉDIA\n"
            + json.dumps(options, ensure_ascii=False, indent=2)
            + "\n\nRÉSULTATS DES TROIS PASSES\n"
            + json.dumps(asdict(self.result), ensure_ascii=False, indent=2)
            + "\n\nINTERPRÉTATION\n"
            "Les hashes E01 portent sur les octets du média décompressé, pas sur le conteneur.\n"
            "Les secteurs illisibles sont remplacés par des zéros, à offsets inchangés.\n"
            "Avec des secteurs illisibles, les hashes sont ceux d'un flux normalisé : "
            "ils ne prouvent pas l'identité des octets d'origine perdus.\n"
            "Une comparaison concordante des trois passes ne constitue pas un snapshot "
            "atomique d'un disque actif. Un bloqueur matériel reste recommandé.\n"
            "Voir acquisition.log pour les LBA et erreurs; conserver tous les segments E01.\n"
            "Un fichier .partial ou un rapport ANNULÉ/ÉCHEC n'est pas une acquisition validée.\n"
        )
        report = self.directory / "rapport.txt"
        try:
            report.write_text(text, encoding="utf-8")
        except OSError as exc:
            # Le rapport reste accessible même si le disque de destination disparaît.
            fallback = Path.home() / "ForensicImager-reports"
            try:
                fallback.mkdir(exist_ok=True)
                report = fallback / f"{self.directory.name}-rapport.txt"
                report.write_text(
                    text + f"\nErreur destination du rapport : {exc}\n", encoding="utf-8"
                )
                self.result.error += f"\nRapport sauvegardé ailleurs : {exc}"
            except OSError as fallback_exc:
                self.result.error += f"\nRapport impossible : {exc}; {fallback_exc}"
                self.result.report = ""
                self.result.status = "ÉCHEC — RAPPORT NON ENREGISTRÉ"
                return
        self.result.report = str(report)

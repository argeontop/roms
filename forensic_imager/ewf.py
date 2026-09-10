"""E01 EnCase6 via les exécutables libewf, sans dépendre de l'ABI de pyewf."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from forensic_imager.core import Control, Options

NO_WINDOW = subprocess.CREATE_NO_WINDOW


@dataclass(frozen=True)
class EwfTools:
    acquire: str
    export: str

    @classmethod
    def discover(cls) -> EwfTools | None:
        tools = Path(__file__).resolve().parent.parent / "tools"
        paths = []
        for name in ("ewfacquirestream.exe", "ewfexport.exe"):
            local = tools / name
            executable = str(local) if local.is_file() else shutil.which(name)
            if executable is None:
                return None
            paths.append(executable)
        return cls(*paths)

    def probe(self, directory: Path, compression: str) -> None:
        """Valide écriture, compression ET relecture sur des données synthétiques."""
        probe = directory / "controle-libewf"
        probe.mkdir()
        data = bytes(range(256)) * 4096
        with (probe / "controle.log").open("xb") as log:
            process = subprocess.run(
                [
                    self.acquire,
                    "-q",
                    "-f",
                    "encase6",
                    "-c",
                    compression,
                    "-B",
                    str(len(data)),
                    "-P",
                    "512",
                    "-t",
                    str(probe / "test"),
                ],
                input=data,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=60,
                creationflags=NO_WINDOW,
                check=False,
            )
            if process.returncode:
                raise OSError(f"Test écriture libewf échoué, voir {probe / 'controle.log'}.")
            export = subprocess.run(
                [self.export, "-u", "-q", "-f", "raw", "-t", "-", str(probe / "test.E01")],
                stdout=subprocess.PIPE,
                stderr=log,
                timeout=60,
                creationflags=NO_WINDOW,
                check=False,
            )
            if export.returncode or export.stdout != data:
                raise OSError(f"Test aller-retour libewf échoué, voir {probe / 'controle.log'}.")
        shutil.rmtree(probe)


class EwfSink:
    def __init__(self, target: Path, control: Control, tools: EwfTools, options: Options) -> None:
        self.control = control
        self.tools = tools
        self.directory = target.parent / "E01-incomplet"
        self.directory.mkdir()
        self.base = self.directory / target.stem
        self.log = (target.parent / "libewf.log").open("xb", buffering=0)
        self.process: subprocess.Popen[bytes] | None = None
        self.export_process: subprocess.Popen[bytes] | None = None
        try:
            self.process = subprocess.Popen(
                [
                    tools.acquire,
                    "-q",
                    "-f",
                    "encase6",
                    "-c",
                    options.compression,
                    "-B",
                    str(options.disk.size),
                    "-P",
                    str(options.disk.sector_size),
                    "-S",
                    str(1024**3),
                    "-M",
                    "physical",
                    "-C",
                    options.case_number or "Non renseigné",
                    "-e",
                    options.examiner or "Non renseigné",
                    "-D",
                    options.description or "Acquisition physique",
                    "-t",
                    str(self.base),
                ],
                stdin=subprocess.PIPE,
                stdout=self.log,
                stderr=subprocess.STDOUT,
                creationflags=NO_WINDOW,
                bufsize=0,
            )
            control.set_interrupt(self.interrupt, "ewf")
        except Exception:
            self.abort()
            raise

    def interrupt(self) -> None:
        for process in (self.process, self.export_process):
            if process and process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass

    def write(self, data: bytes) -> None:
        self.control.checkpoint()
        if self.process is None or self.process.stdin is None:
            raise OSError("Writer E01 non initialisé.")
        view = memoryview(data)
        while view:
            self.control.checkpoint()
            written = self.process.stdin.write(view)
            if not written:
                raise OSError("Libewf a fermé son entrée. Voir libewf.log.")
            view = view[written:]

    def finish(self) -> None:
        if self.process is None or self.process.stdin is None:
            raise OSError("Writer E01 absent.")
        self.process.stdin.close()
        if self.process.wait() != 0:
            raise OSError("Échec de finalisation E01. Voir libewf.log.")
        self.control.checkpoint()

    def chunks(self, block_size: int) -> Iterator[bytes]:
        first_segment = Path(str(self.base) + ".E01")
        self.export_process = subprocess.Popen(
            [self.tools.export, "-u", "-q", "-f", "raw", "-t", "-", str(first_segment)],
            stdout=subprocess.PIPE,
            stderr=self.log,
            creationflags=NO_WINDOW,
        )
        process = self.export_process
        try:
            if process.stdout is None:
                raise OSError("Sortie de vérification E01 absente.")
            while data := process.stdout.read(block_size):
                self.control.checkpoint()
                yield data
            if process.wait() != 0:
                raise OSError("Vérification/lecture E01 impossible. Voir libewf.log.")
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            if process.stdout:
                process.stdout.close()

    def publish(self) -> Path:
        final = self.directory.with_name("E01")
        self.directory.rename(final)
        self.directory = final
        return final / (self.base.name + ".E01")

    def abort(self) -> None:
        self.control.set_interrupt(None, "ewf")
        self.interrupt()
        for process in (self.process, self.export_process):
            if process:
                process.wait()
                if process.stdin and not process.stdin.closed:
                    process.stdin.close()
                if process.stdout and not process.stdout.closed:
                    process.stdout.close()
        self.log.close()

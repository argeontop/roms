"""Interface française ; seuls les messages de la file modifient les widgets."""

from __future__ import annotations

import os
import queue
import subprocess
import threading
import tkinter as tk
import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from forensic_imager.core import (
    MIB,
    Acquisition,
    Control,
    Disk,
    Event,
    Log,
    Options,
    Progress,
    RawSink,
    Result,
    Sink,
)
from forensic_imager.ewf import EwfSink, EwfTools
from forensic_imager.windows import (
    PhysicalSource,
    detect_disks,
    validate_destination,
    validate_identity,
)

BUFFERS = {"512 Kio": MIB // 2, "1 Mio": MIB, "4 Mio": 4 * MIB, "8 Mio": 8 * MIB}
COMPRESSION = {"Aucune": "none", "Rapide": "fast", "Maximale": "best"}


@dataclass(frozen=True)
class Inventory:
    disks: list[Disk]
    error: str = ""


@dataclass(frozen=True)
class PreparationError:
    message: str


@dataclass(frozen=True)
class Fallback:
    options: Options
    reason: str


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("Forensic Imager — Acquisition physique pour Autopsy")
        root.geometry("1060x850")
        root.minsize(930, 780)
        self.messages: queue.Queue[Event | Inventory | PreparationError | Fallback] = queue.Queue(
            maxsize=512
        )
        self.disks: list[Disk] = []
        self.control = Control()
        self.worker: threading.Thread | None = None
        self.busy = False
        self.refreshing = False
        self.closing = False
        self.last_report = ""
        self.form: list[ttk.Combobox | ttk.Entry | ttk.Button | ttk.Checkbutton] = []
        self.dest = tk.StringVar()
        self.format = tk.StringVar(value=".dd")
        self.buffer = tk.StringVar(value="4 Mio")
        self.compression = tk.StringVar(value="Rapide")
        self.readonly = tk.BooleanVar(value=True)
        self.hashes = {
            name: tk.BooleanVar(value=name == "sha256") for name in ("md5", "sha1", "sha256")
        }
        self.examiner = tk.StringVar()
        self.case_number = tk.StringVar()
        self.description = tk.StringVar()
        self.status = tk.StringVar(value="Inventaire des disques…")
        self.metrics = tk.StringVar(value="Aucune acquisition en cours")
        self.build()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(100, self.poll)
        self.refresh()

    def build(self) -> None:
        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Acquisition forensique", font=("Segoe UI", 19, "bold")).pack(
            anchor="w"
        )
        ttk.Label(
            outer,
            text="1. Hash du disque source     2. Copie intégrale     3. Relecture et comparaison",
        ).pack(anchor="w", pady=(4, 12))
        form = ttk.LabelFrame(outer, text="Source et destination", padding=12)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text="Disque physique").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.disk_combo = ttk.Combobox(form, state="readonly")
        self.disk_combo.grid(row=0, column=1, sticky="ew")
        self.refresh_button = ttk.Button(form, text="Rafraîchir la liste", command=self.refresh)
        self.refresh_button.grid(row=0, column=2, padx=(8, 0))
        self.form.extend([self.disk_combo, self.refresh_button])
        ttk.Label(form, text="Fichier destination").grid(row=1, column=0, sticky="w", pady=8)
        entry = ttk.Entry(form, textvariable=self.dest)
        entry.grid(row=1, column=1, sticky="ew")
        browse = ttk.Button(form, text="Parcourir…", command=self.browse)
        browse.grid(row=1, column=2, padx=(8, 0))
        self.form.extend([entry, browse])
        ttk.Label(
            form, text="Un sous-dossier unique contiendra l'image, le journal et le rapport."
        ).grid(row=2, column=1, sticky="w")

        settings = ttk.LabelFrame(outer, text="Paramètres d'acquisition", padding=12)
        settings.pack(fill="x", pady=10)
        for col in (1, 3, 5):
            settings.columnconfigure(col, weight=1)
        for column, label, variable, choices in (
            (0, "Format", self.format, (".dd", ".raw", ".E01")),
            (2, "Buffer", self.buffer, tuple(BUFFERS)),
            (4, "Compression E01", self.compression, tuple(COMPRESSION)),
        ):
            ttk.Label(settings, text=label).grid(row=0, column=column, sticky="w", padx=(0, 8))
            combo = ttk.Combobox(settings, textvariable=variable, values=choices, state="readonly")
            combo.grid(row=0, column=column + 1, sticky="ew", padx=(0, 12))
            self.form.append(combo)
            if column == 0:
                combo.bind("<<ComboboxSelected>>", self.format_changed)
            if column == 4:
                self.compression_combo = combo
        ttk.Label(settings, text="Hashes").grid(row=1, column=0, sticky="w", pady=10)
        hashes = ttk.Frame(settings)
        hashes.grid(row=1, column=1, columnspan=5, sticky="w")
        for name, hash_variable in self.hashes.items():
            box = ttk.Checkbutton(hashes, text=name.upper(), variable=hash_variable)
            box.pack(side="left", padx=(0, 22))
            self.form.append(box)
        readonly = ttk.Checkbutton(
            settings,
            text="Lecture seule forcée — exiger la protection Windows du disque",
            variable=self.readonly,
        )
        readonly.grid(row=2, column=0, columnspan=6, sticky="w")
        self.form.append(readonly)
        ttk.Label(
            settings,
            text="Toujours ouvert en lecture seule. L'option exige un disque déjà protégé ; "
            "elle ne remplace pas un bloqueur matériel.",
            wraplength=960,
        ).grid(row=3, column=0, columnspan=6, sticky="w", pady=(4, 0))

        case = ttk.LabelFrame(outer, text="Métadonnées du dossier", padding=12)
        case.pack(fill="x")
        case.columnconfigure(1, weight=1)
        for row, label, variable in (
            (0, "Examinateur", self.examiner),
            (1, "Numéro de dossier", self.case_number),
            (2, "Description", self.description),
        ):
            ttk.Label(case, text=label).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=3)
            entry = ttk.Entry(case, textvariable=variable)
            entry.grid(row=row, column=1, sticky="ew")
            self.form.append(entry)

        progress = ttk.Frame(outer)
        progress.pack(fill="x", pady=12)
        ttk.Label(progress, textvariable=self.status).pack(anchor="w")
        self.bar = ttk.Progressbar(progress, maximum=100)
        self.bar.pack(fill="x", pady=5)
        ttk.Label(progress, textvariable=self.metrics).pack(anchor="w")
        actions = ttk.Frame(outer)
        actions.pack(fill="x")
        self.start_button = ttk.Button(actions, text="Démarrer l'acquisition", command=self.start)
        self.start_button.pack(side="left")
        self.pause_button = ttk.Button(actions, text="Pause", command=self.pause, state="disabled")
        self.pause_button.pack(side="left", padx=8)
        self.cancel_button = ttk.Button(
            actions, text="Annuler", command=self.cancel, state="disabled"
        )
        self.cancel_button.pack(side="left")
        self.report_button = ttk.Button(
            actions, text="Ouvrir le rapport", command=self.open_report, state="disabled"
        )
        self.report_button.pack(side="right")
        self.log = scrolledtext.ScrolledText(
            outer, height=9, state="disabled", wrap="word", font=("Consolas", 9)
        )
        self.log.pack(fill="both", expand=True, pady=(12, 0))
        self.format_changed()

    def format_changed(self, event: tk.Event[tk.Misc] | None = None) -> None:
        self.compression_combo.configure(
            state="readonly" if self.format.get() == ".E01" and not self.busy else "disabled"
        )

    def emit(self, event: Event) -> None:
        if isinstance(event, Result):
            self.messages.put(event)
        else:
            try:
                self.messages.put_nowait(event)
            except queue.Full:
                pass  # Le journal complet reste écrit sur disque.

    def append_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        if int(self.log.index("end-1c").split(".")[0]) > 1500:
            self.log.delete("1.0", "301.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    def refresh(self) -> None:
        if self.busy or self.refreshing:
            return
        self.refreshing = True
        self.refresh_button.configure(state="disabled")
        self.start_button.configure(state="disabled")
        self.status.set("Détection des disques via WMI…")
        threading.Thread(target=self.inventory_worker, daemon=True).start()

    def inventory_worker(self) -> None:
        try:
            self.messages.put(Inventory(detect_disks()))
        except Exception as exc:
            self.messages.put(Inventory([], str(exc)))

    def browse(self) -> None:
        name = filedialog.asksaveasfilename(
            title="Choisir le nom de l'image (un sous-dossier sera créé)",
            defaultextension=self.format.get(),
            filetypes=[("Image disque", "*" + self.format.get()), ("Tous les fichiers", "*.*")],
            initialfile="image" + self.format.get(),
        )
        if name:
            self.dest.set(name)

    def set_busy(self, busy: bool) -> None:
        self.busy = busy
        for widget in self.form:
            state = (
                "disabled"
                if busy
                else ("readonly" if isinstance(widget, ttk.Combobox) else "normal")
            )
            widget.configure(state=state)
        self.start_button.configure(state="disabled" if busy else "normal")
        for button in (self.pause_button, self.cancel_button):
            button.configure(state="normal" if busy else "disabled")
        self.pause_button.configure(text="Pause")
        self.format_changed()

    def start(self) -> None:
        if self.busy or self.refreshing:
            return
        try:
            selected = self.disk_combo.current()
            if selected < 0 or selected >= len(self.disks):
                raise ValueError("Sélectionnez un disque physique.")
            if not self.dest.get().strip():
                raise ValueError("Choisissez un fichier de destination.")
            destination = Path(self.dest.get().strip())
            if not destination.is_absolute() or not destination.parent.is_dir():
                raise ValueError("Choisissez un chemin absolu dans un dossier existant.")
            if any(character in destination.name for character in '<>:"|?*'):
                raise ValueError("Nom de fichier Windows invalide.")
            destination = destination.with_suffix(self.format.get())
            names = tuple(
                name for name, selected_hash in self.hashes.items() if selected_hash.get()
            )
            if not names:
                raise ValueError("Sélectionnez au moins un algorithme de hash.")
            if len(self.examiner.get()) > 255 or len(self.case_number.get()) > 255:
                raise ValueError("Examinateur et numéro de dossier : 255 caractères maximum.")
            if len(self.description.get()) > 4096:
                raise ValueError("Description : 4096 caractères maximum.")
            options = Options(
                disk=self.disks[selected],
                destination=destination,
                format="E01" if self.format.get() == ".E01" else "raw",
                requested_format=self.format.get(),
                algorithms=names,
                block_size=BUFFERS[self.buffer.get()],
                force_readonly=self.readonly.get(),
                compression=COMPRESSION[self.compression.get()],
                examiner=self.examiner.get(),
                case_number=self.case_number.get(),
                description=self.description.get(),
            )
            if not options.force_readonly and not messagebox.askyesno(
                "Protection du média",
                "Le logiciel ouvrira la source uniquement en lecture, mais Windows ou d'autres "
                "processus peuvent encore la modifier. Les trois passes peuvent diverger.\n\n"
                "Continuer sans exiger l'attribut Windows lecture seule ?",
            ):
                return
            self.begin(options)
        except (ValueError, OSError) as exc:
            messagebox.showerror("Paramètres invalides", str(exc))

    def begin(self, options: Options) -> None:
        self.control = Control()
        self.last_report = ""
        self.report_button.configure(state="disabled")
        self.bar["value"] = 0
        self.set_busy(True)
        self.status.set("Contrôles de sécurité et préparation…")
        self.metrics.set("Le test libewf éventuel peut prendre jusqu'à deux minutes.")
        self.worker = threading.Thread(target=self.acquire_worker, args=(options,), daemon=False)
        self.worker.start()

    def acquire_worker(self, options: Options) -> None:
        try:
            validate_identity(options.disk)
            validate_destination(options.destination.parent, options.disk, options.format)
            self.control.checkpoint()
            directory = options.destination.parent / (
                options.destination.stem
                + "_"
                + datetime.now().strftime("%Y%m%d_%H%M%S")
                + "_"
                + uuid.uuid4().hex[:8]
            )
            directory.mkdir()
            tools = EwfTools.discover() if options.format == "E01" else None
            if options.format == "E01":
                try:
                    if tools is None:
                        raise OSError("ewfacquirestream.exe et ewfexport.exe introuvables.")
                    tools.probe(directory, options.compression)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    self.messages.put(Fallback(options, str(exc)))
                    return
            self.control.checkpoint()

            def make_source() -> PhysicalSource:
                validate_destination(directory, options.disk, options.format)
                return PhysicalSource(options.disk, options.force_readonly, self.control)

            def make_sink(target: Path, control: Control) -> Sink:
                validate_destination(directory, options.disk, options.format)
                if options.format == "E01":
                    if tools is None:
                        raise OSError("Libewf indisponible.")
                    return EwfSink(target, control, tools, options)
                return RawSink(target, control)

            Acquisition(options, directory, make_source, make_sink, self.control, self.emit).run()
        except Exception as exc:
            self.messages.put(PreparationError(f"Préparation interrompue : {exc}"))

    def pause(self) -> None:
        if self.control.running.is_set():
            self.control.pause()
            self.pause_button.configure(text="Reprendre")
            self.status.set("Pause demandée — après l'opération d'E/S en cours")
        else:
            self.control.resume()
            self.pause_button.configure(text="Pause")
            self.status.set("Reprise…")

    def cancel(self) -> None:
        if self.busy and messagebox.askyesno(
            "Annuler l'acquisition ?", "Les données partielles et le rapport seront conservés."
        ):
            self.control.cancel()
            self.pause_button.configure(state="disabled")
            self.cancel_button.configure(state="disabled")
            self.status.set("Annulation demandée — attente de fermeture des E/S")

    def open_report(self) -> None:
        try:
            os.startfile(self.last_report)
        except OSError as exc:
            messagebox.showerror("Rapport", str(exc))

    def finish(self, result: Result) -> None:
        self.set_busy(False)
        self.last_report = result.report
        self.report_button.configure(state="normal" if result.report else "disabled")
        self.status.set(result.status)
        self.append_log(
            f"{result.status}\n{result.error}\nImage : {result.image or 'partielle/non créée'}"
            f"\nRapport : {result.report or 'non enregistré'}"
        )
        message = (
            f"{result.status}\n\n{result.error}\n\n"
            f"Rapport : {result.report or 'impossible à enregistrer'}"
        )
        if result.status == "CONFORME":
            messagebox.showinfo("Acquisition terminée", message)
        elif "NON CONFORME" in result.status or result.status.startswith("ÉCHEC"):
            messagebox.showerror("Intégrité non validée", message)
        else:
            messagebox.showwarning("Acquisition avec réserves", message)
        if self.closing:
            self.root.destroy()

    def poll(self) -> None:
        for _ in range(200):
            try:
                event = self.messages.get_nowait()
            except queue.Empty:
                break
            if isinstance(event, Inventory):
                self.refreshing = False
                self.disks = event.disks
                self.disk_combo["values"] = [disk.label for disk in self.disks]
                self.disk_combo.set("")
                self.refresh_button.configure(state="normal")
                self.start_button.configure(state="normal")
                self.status.set(f"{len(self.disks)} disque(s) détecté(s). Sélectionnez la source.")
                if event.error:
                    self.append_log(event.error)
                    messagebox.showerror("Détection impossible", event.error)
            elif isinstance(event, Log):
                self.append_log(event.message)
            elif isinstance(event, Progress):
                percent = event.done / event.total * 100
                self.bar["value"] = (event.phase_index * 100 + percent) / 3
                if self.control.running.is_set() and not self.control.cancelled.is_set():
                    self.status.set(f"Passe {event.phase_index + 1}/3 — {event.phase}")
                self.metrics.set(
                    f"{percent:.1f} % de la passe | "
                    f"{(event.phase_index * 100 + percent) / 3:.1f} % global | "
                    f"{event.speed / MIB:.1f} Mio/s | "
                    f"Restant estimé (passe) : {event.eta / 60:.1f} min"
                )
            elif isinstance(event, Result):
                self.finish(event)
                if self.closing:
                    return
            elif isinstance(event, PreparationError):
                self.set_busy(False)
                self.status.set("Préparation interrompue")
                self.append_log(event.message)
                messagebox.showerror("Acquisition non démarrée", event.message)
                if self.closing:
                    self.root.destroy()
                    return
            elif isinstance(event, Fallback):
                self.set_busy(False)
                if self.control.cancelled.is_set() or self.closing:
                    self.status.set("Annulé avant acquisition")
                    if self.closing:
                        self.root.destroy()
                        return
                elif messagebox.askyesno(
                    "E01 indisponible — repli RAW",
                    f"{event.reason}\n\nCréer à la place une image brute .dd, "
                    "directement importable dans Autopsy ?",
                ):
                    options = replace(
                        event.options,
                        format="raw",
                        destination=event.options.destination.with_suffix(".dd"),
                    )
                    self.dest.set(str(options.destination))
                    self.format.set(".dd")
                    self.begin(options)
                else:
                    self.status.set("Acquisition non démarrée : E01 indisponible")
        self.root.after(100, self.poll)

    def close(self) -> None:
        if self.busy:
            if messagebox.askyesno(
                "Quitter ?", "Annuler l'acquisition, sauvegarder le rapport puis quitter ?"
            ):
                self.closing = True
                self.control.cancel()
                self.status.set("Fermeture après annulation et sauvegarde du rapport…")
        else:
            self.root.destroy()

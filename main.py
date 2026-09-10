"""Point d'entrée Windows 10/11, Python 3.11 ou supérieur avec Tcl/Tk."""

import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox

if sys.platform == "win32":
    from forensic_imager.ui import App
    from forensic_imager.windows import elevate, is_admin


def main() -> None:
    root = tk.Tk()
    root.withdraw()
    if sys.platform != "win32":
        messagebox.showerror("Windows requis", "Ce logiciel nécessite Windows 10/11.")
        root.destroy()
        return
    if not is_admin():
        if messagebox.askyesno(
            "Droits administrateur requis",
            "La lecture d'un disque physique nécessite des droits administrateur.\n\n"
            "Relancer avec élévation UAC ?",
        ):
            if not elevate(Path(__file__)):
                messagebox.showerror(
                    "Élévation refusée",
                    "L'autorisation UAC a été refusée ou a échoué. "
                    "Ouvrez un terminal en tant qu'administrateur puis lancez python main.py.",
                )
        root.destroy()
        return
    App(root)
    root.deiconify()
    root.mainloop()


if __name__ == "__main__":
    main()

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
import threading
import re
import sys

from opl480pcheatgen import __version__

class OPLCheatGUI:
    def __init__(self, root):
        self.root = root
        root.title(
            f"OPL480pCheatGen — 480p/240p Cheat Generator v{__version__} — © 2025 ArcanBytes | tiempoinfinito.com"
        )
        self.current_cht_text = ""
        self.current_cht_filename = None

        # File input
        self.file_path = tk.StringVar()
        file_frame = ttk.Frame(root)
        file_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(file_frame, text="Game ISO:").pack(side='left')
        ttk.Entry(file_frame, textvariable=self.file_path, width=60).pack(side='left', padx=5)
        ttk.Button(file_frame, text="Browse", command=self.select_file).pack(side='left')

        # Options
        # Default mode patches the game to 480p. Allow user to select other modes
        # via a drop-down menu. "No change" disables the interlace patch.
        self.video_mode = tk.StringVar(value="480p")
        self.pal60_patch = tk.BooleanVar()
        self.dy_patch = tk.BooleanVar()
        self.dy_value = tk.IntVar(value=51)
        self.aggressive_patch = tk.BooleanVar()
        options = ttk.LabelFrame(root, text="Options")
        options.pack(fill='x', padx=10, pady=5)

        mode_frame = ttk.Frame(options)
        ttk.Label(mode_frame, text="Video patch:").pack(side='left')
        self.mode_cb = ttk.Combobox(
            mode_frame,
            textvariable=self.video_mode,
            values=["480p", "240p", "No change"],
            state="readonly",
            width=12,
        )
        self.mode_cb.pack(side='left', padx=5)
        mode_frame.pack(anchor='w', padx=10)

        ttk.Checkbutton(options, text="Enable 60Hz (for PAL games)", variable=self.pal60_patch).pack(anchor='w', padx=10)
        dy_frame = ttk.Frame(options)
        self.dy_chk = ttk.Checkbutton(dy_frame, text="Vertical offset", variable=self.dy_patch)
        self.dy_chk.pack(side='left')
        self.dy_spin = tk.Spinbox(dy_frame, from_=-100, to=100, width=5, textvariable=self.dy_value)
        self.dy_spin.pack(side='left', padx=5)
        dy_frame.pack(anchor='w', padx=10, pady=(0,5))

        ttk.Checkbutton(options, text="Aggressive patch", variable=self.aggressive_patch).pack(anchor='w', padx=10)

        self.mode_cb.bind("<<ComboboxSelected>>", lambda e: self.update_dy_state())
        self.update_dy_state()

        # Generate button
        ttk.Button(root, text="Generate .cht", command=self.generate_cht).pack(pady=10)

        # Output preview/log. Frame to hold log + scrollbar
        ttk.Label(root, text="Output log:").pack(anchor='w', padx=10, pady=(10, 0))
        log_frame = ttk.Frame(root)
        log_frame.pack(fill='both', expand=True, padx=10, pady=(5, 0))

        scrollbar = ttk.Scrollbar(log_frame, orient='vertical')
        self.output = tk.Text(log_frame, height=15, width=150, yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.output.yview)
        scrollbar.pack(side='right', fill='y')
        self.output.pack(side='left', fill='both', expand=True)
        self.output.config(state='disabled')
        
        # Frame to hold cht preview + scrollbar
        ttk.Label(root, text="CHT preview:").pack(anchor='w', padx=10, pady=(10, 0))
        cht_frame = ttk.Frame(root)
        cht_frame.pack(fill='both', expand=True, padx=10, pady=(0, 5))

        cht_scroll = ttk.Scrollbar(cht_frame, orient='vertical')
        self.cht_preview = tk.Text(cht_frame, height=15, width=150, yscrollcommand=cht_scroll.set)
        cht_scroll.config(command=self.cht_preview.yview)
        cht_scroll.pack(side='right', fill='y')
        self.cht_preview.pack(side='left', fill='both', expand=True)
        self.cht_preview.config(state='disabled')

        # Overwrite checkbox and Write button
        write_frame = ttk.Frame(root)
        write_frame.pack(fill='x', padx=10, pady=(5, 10))

        self.overwrite_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(write_frame, text="Save in script folder and overwrite", variable=self.overwrite_var).pack(side='left')
        self.write_btn = ttk.Button(write_frame, text="Write .cht file", command=self.write_cht_file, state='disabled')
        self.write_btn.pack(side='right')

    def select_file(self):
        path = filedialog.askopenfilename(filetypes=[("PS2 ISO files", "*.iso *.ISO")])
        if path:
            self.file_path.set(path)

    def update_dy_state(self):
        enabled = self.video_mode.get() != "No change"
        state = "normal" if enabled else "disabled"
        self.dy_chk.config(state=state)
        self.dy_spin.config(state=state)
        if not enabled:
            self.dy_patch.set(False)
            
    def show_cht_preview(self, text):
        self.current_cht_text = text
        self.cht_preview.config(state='normal')
        self.cht_preview.delete(1.0, tk.END)
        self.cht_preview.insert(tk.END, text.strip())
        self.cht_preview.config(state='disabled')
        self.write_btn.config(state='normal')

    def generate_cht(self):
        self.output.config(state='normal')
        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, "Processing...\n")
        self.output.config(state='disabled')

        path = self.file_path.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Please select a valid ISO or ELF file.")
            return

        if getattr(sys, 'frozen', False):
            # When running from PyInstaller-built .exe, call bundled .exe
            script_or_exe = os.path.join(os.path.dirname(sys.executable), 'OPL480pCheatGen.exe')
            cmd = [script_or_exe, path, "--preview-only"]
        else:
            # When running from .py, explicitly invoke Python interpreter
            cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "OPL480pCheatGen.py"), path, "--preview-only"]

        mode = self.video_mode.get()
        if mode == "No change":
            cmd.append("--no-interlace-patch")
        elif mode == "240p":
            cmd.append("--force-240p")
        if self.pal60_patch.get():
            cmd.append("--pal60")
        if self.dy_patch.get():
            cmd.extend(["--dy", str(self.dy_value.get())])
        if self.aggressive_patch.get():
            cmd.append("--aggressive")
        
        def run_patch():
            try:                
                startupinfo = None
                # This setting is specific to Windows to suppress the CMD window.
                # It only applies if we are running the compiled .exe.
                if getattr(sys, 'frozen', False) and os.name == 'nt':
                    startupinfo = subprocess.STARTUPINFO()
                    # Show hidden window (SW_HIDE)
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE

                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True, startupinfo=startupinfo)

                # Extract the expected .cht filename from the log
                for line in output.splitlines():
                    if line.startswith("Title:") and "/ID " in line:
                        self.current_cht_filename = line.split("/ID")[-1].strip().strip('"') + ".cht"
                        break

                cht_content = extract_cht_from_log(output)
                self.root.after(0, lambda: self.show_output(output))
                self.root.after(0, lambda: self.show_cht_preview(cht_content))
            except subprocess.CalledProcessError as e:
                # Handles errors if the CLI returns an error code
                error_output = f"[ERROR] CLI tool returned an error (code: {e.returncode}):\n{e.output}"
                self.root.after(0, self.show_output, error_output)
                output_snippet = e.output.strip()
                self.root.after(0, lambda out=output_snippet: messagebox.showerror("CLI Error", f"There was an error running the CLI tool:\n{out}"))
            except FileNotFoundError:
                # Handles the case where the CLI executable is missing
                error_msg = f"[ERROR] Executable not found {script_or_exe}. Make sure it is in the same directory as the GUI or in your PATH."
                self.root.after(0, self.show_output, error_msg)
                self.root.after(0, lambda: messagebox.showerror("Error", error_msg))
            except Exception as e:
                # Unexpected Errors
                error_msg = f"[ERROR] Unexpected error occurred while running the CLI: {e}"
                self.root.after(0, self.show_output, error_msg)
                self.root.after(0, lambda: messagebox.showerror("Unexpected Error", error_msg))

        threading.Thread(target=run_patch, daemon=True).start()      

    def show_output(self, text):
        self.output.config(state='normal')
        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, text)
        self.output.config(state='disabled')
        
    def write_cht_file(self):
        if not self.current_cht_text or not self.current_cht_filename:
            messagebox.showerror("Error", "No .cht content or filename available.")
            return

        if self.overwrite_var.get():
            if getattr(sys, 'frozen', False):
                app_dir = os.path.dirname(sys.executable)
            else:
                app_dir = os.path.dirname(__file__)

            output_path = os.path.join(app_dir, self.current_cht_filename)

        else:
            output_path = filedialog.asksaveasfilename(
                defaultextension=".cht",
                initialfile=self.current_cht_filename,
                filetypes=[("OPL cheat file", "*.cht")])
            if not output_path:
                return  # User cancelled

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(self.current_cht_text.strip() + "\n")
            messagebox.showinfo("Success", f".cht file written to:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to write .cht file:\n{e}")

    
def extract_cht_from_log(log):
    lines = log.splitlines()
    start, end = -1, len(lines)

    # Normalize quotes and look for known .cht header formats
    for i in range(len(lines) - 1):
        line = lines[i].replace("“", '"').replace("”", '"')
        next_line = lines[i + 1].strip().lower()

        if (line.startswith('"') and " /ID " in line) or \
           (line and next_line == "mastercode"):
            start = i
            break

    for i in range(len(lines)):
        if "[INFO] Wrote:" in lines[i]:
            end = i
            break

    if start != -1 and start < end:
        cht_lines = lines[start:end]
        return "\n".join(cht_lines).strip()

    return "// Error: Could not extract .cht content from log"

# Launch
if __name__ == "__main__":
    root = tk.Tk()
    gui = OPLCheatGUI(root)
    root.mainloop() 

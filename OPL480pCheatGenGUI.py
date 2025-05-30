import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
import threading
import re
import sys

class OPLCheatGUI:
    def __init__(self, root):
        self.root = root
        root.title("OPL480pCheatGen — 480p/240p Cheat Generator v1.0.1 — © 2025 ArcanBytes | tiempoinfinito.com")
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
        self.force_240p = tk.BooleanVar()
        self.disable_interlace = tk.BooleanVar(value=True)
        self.pal60_patch = tk.BooleanVar()
        options = ttk.LabelFrame(root, text="Options")
        options.pack(fill='x', padx=10, pady=5)

        ttk.Checkbutton(options, text="Force 240p output", variable=self.force_240p).pack(anchor='w', padx=10)
        #ttk.Checkbutton(options, text="Disable interlace mode (480i)", variable=self.disable_interlace).pack(anchor='w', padx=10)
        ttk.Checkbutton(options, text="Enable 60Hz (for PAL games)", variable=self.pal60_patch).pack(anchor='w', padx=10)

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

        if not self.disable_interlace.get():
            cmd.append("--no-interlace-patch")
        if self.force_240p.get():
            cmd.append("--force-240p")
        if self.pal60_patch.get():
            cmd.append("--pal60")    
        
        def run_patch():
            try:
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)

                # Extract the expected .cht filename from the log
                for line in output.splitlines():
                    if line.startswith("Title:") and "/ID " in line:
                        self.current_cht_filename = line.split("/ID")[-1].strip().strip('"') + ".cht"
                        break

                cht_content = extract_cht_from_log(output)
                self.root.after(0, lambda: self.show_output(output))
                self.root.after(0, lambda: self.show_cht_preview(cht_content))
            except subprocess.CalledProcessError as e:
                self.root.after(0, self.show_output, f"[ERROR]\n{e.output}")

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
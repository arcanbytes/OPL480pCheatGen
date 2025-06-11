import os
import shutil
import zipfile
import PyInstaller.__main__

from opl480pcheatgen import __version__

def clean():
    for folder in ["build", "dist", "__pycache__"]:
        if os.path.exists(folder):
            shutil.rmtree(folder)
    for file in os.listdir("."):
        if file.endswith(".spec"):
            os.remove(file)

def build_exe(entry_script, name, data_files=[], icon=None, is_gui=False):
    args = [
        entry_script,
        '--onefile',
        f'--name={name}',
        '--noconfirm',
        '--clean',
    ]

    if is_gui: # Si es una aplicación GUI, añade --noconsole
        args.append('--noconsole') # O '--windowed'

    for data in data_files:
        args += ['--add-data', f'{data};.']
    if icon:
        args += ['--icon', icon]

    PyInstaller.__main__.run(args)

def package_release():
    os.makedirs("release", exist_ok=True)
    zip_name = f"OPL480pCheatGen_v{__version__}.zip"
    with zipfile.ZipFile(os.path.join("release", zip_name), 'w') as z:
        z.write('dist/OPL480pCheatGenGUI.exe', arcname='OPL480pCheatGenGUI.exe')
        z.write('dist/OPL480pCheatGen.exe', arcname='OPL480pCheatGen.exe')
        z.write('dist/mastercodes.json', arcname='mastercodes.json')
        z.write('README.md')
        z.write('LICENSE')

if __name__ == "__main__":
    print("[INFO] Cleaning...")
    clean()

    print("[INFO] Building CLI version...")
    build_exe(
        'OPL480pCheatGen.py',
        'OPL480pCheatGen',
        ['opl480pcheatgen/mastercodes.json'],
        icon='img/OPL480pCheatGen_cmd.ico',
        is_gui=False,
    )
    shutil.copy2('opl480pcheatgen/mastercodes.json', 'dist/mastercodes.json')

    print("[INFO] Building GUI version...")
    build_exe(
        'OPL480pCheatGenGUI.py',
        'OPL480pCheatGenGUI',
        icon='img/OPL480pCheatGen.ico',
        is_gui=True,
    )

    print("[INFO] Packaging release...")
    package_release()

    print(f"[DONE] Release zip created in ./release: OPL480pCheatGen_v{__version__}.zip")
    clean()

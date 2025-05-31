import os
import shutil
import zipfile
import PyInstaller.__main__

def clean():
    for folder in ["build", "dist", "__pycache__"]:
        if os.path.exists(folder):
            shutil.rmtree(folder)
    for file in os.listdir("."):
        if file.endswith(".spec"):
            os.remove(file)

def build_exe(entry_script, name, data_files=[], icon=None):
    args = [
        entry_script,
        '--onefile',
        f'--name={name}',
        '--noconfirm',
        '--clean',
    ]
    for data in data_files:
        args += ['--add-data', f'{data};.']
    if icon:
        args += ['--icon', icon]

    PyInstaller.__main__.run(args)

def package_release():
    os.makedirs("release", exist_ok=True)
    with zipfile.ZipFile("release/OPL480pCheatGen_v1.0.1.zip", 'w') as z:
        z.write('dist/OPL480pCheatGenGUI.exe', arcname='OPL480pCheatGenGUI.exe')
        z.write('dist/OPL480pCheatGen.exe', arcname='OPL480pCheatGen.exe')
        z.write('dist/mastercodes.json', arcname='mastercodes.json')
        z.write('README.md')
        z.write('LICENSE')

if __name__ == "__main__":
    print("[INFO] Cleaning...")
    clean()

    print("[INFO] Building CLI version...")
    build_exe('OPL480pCheatGen.py', 'OPL480pCheatGen', [])
    shutil.copy2('mastercodes.json', 'dist/mastercodes.json')

    print("[INFO] Building GUI version...")
    build_exe('OPL480pCheatGenGUI.py', 'OPL480pCheatGenGUI', [], icon='img/OPL480pCheatGen.ico')

    print("[INFO] Packaging release...")
    package_release()

    print("[DONE] Release zip created in ./release: OPL480pCheatGen_v1.0.1.zip")

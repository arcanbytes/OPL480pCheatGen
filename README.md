# OPL480pCheatGen

![Banner](img/OPL480pCheatGen_banner.png)


**OPL480pCheatGen** is a tool for generating `.cht` cheat files compatible with [Open PS2 Loader (OPL)](https://github.com/ifcaro/Open-PS2-Loader), allowing you to force 480p, 240p, and progressive video modes in your PlayStation 2 games **without modifying ISOs**.

> ✅ No patching required  
> ✅ Runs offline  
> ✅ Generates `.cht` files for use with OPL  
> ✅ Works directly with ISO files

---

## 📦 Download

You can always get the latest compiled version here:
👉 [Download Latest Release](https://github.com/arcanbytes/OPL480pCheatGen/releases/latest)

---

## ⚙️ Features

- ✅ **Video Mode Detection**: 480p, 240p, and 480i
- ✅ **Auto-detect ELF from ISO** via `SYSTEM.CNF` (no user input needed)
- ✅ **Optional Patches**:
  - Enable PAL 60Hz (for PAL-region games)
  - Skip PAL 60Hz patch if a 60 Hz mode already exists
  - Force 240p output
  - Adjust vertical offset (DY) 
- ✅ **Fully Offline**: Loads titles and mastercodes from a built-in database (5300+ entries)
- ✅ **Supports GUI and CLI**

---

## 🖥️ Graphical Interface (Recommended)

Run `OPL480pCheatGenGUI.exe`:

- Select an ISO 
- Choose your patch options
- Preview the `.cht` content
- Click **Write .cht file** to save

✔️ Saves `.cht` next to the `.exe` by default  
✔️ Ideal for use with OPL Manager Cheat Editor 

<img src="img/OPL480pCheatGen_screenshot_01.jpg" width="850">

---

## 🧪 Command-Line Interface

Run the tool directly via Python or the `.exe`:

```bash
# Basic usage examples
python OPL480pCheatGen.py "Game.iso"
OPL480pCheatGen.exe "F:\RetroBat\roms\ps2\Game.iso" --preview-only --force-240p

# Optional flags:
--preview-only        # Show .cht content in console, do not write file
--pal60               # Enable PAL 60Hz mode (for PAL games)
--force-240p          # Use 240p instead of 480p
--dy 51               # Override vertical offset (DY)
--mastercode "CODE"   # Manually override mastercode
```

---

## ⚠️ Generated Codes Effectiveness

It's important to note that the effectiveness of generated `.cht` codes for forcing progressive video modes on real PS2 consoles can be limited and vary significantly between games. The application of these patches often involves a "trial and error" approach due to the specific characteristics of each game and its video output handling. Adjusting the DY vertical offset may also introduce flickering in certain gamess (for example, **Art Tonelico II**), so experiment with other titles and disable the option if flicker occurs. Additionally, forcing 60Hz in PAL games often results in a black screen.

If, after applying the generated `.cht` codes, you experience issues such as:
- Black screen.
- Image flickering.
- Visual artifacts.
- Corrupted graphics.
- The game failing to launch correctly.

We recommend trying the integrated OPL GSM (Graphics Synthesizer Mode Selector), specifically the "HDTV 480p Mode" found within each game's configuration. GSM is a hardware-level video scaling solution that often offers broader compatibility, though it may introduce its own performance issues or visual glitches in certain titles.

---

## 📝 License

MIT License – see LICENSE file for details.
Copyright (c) 2025 ArcanBytes<br>
<img src="img/OPL480pCheatGen.png" width="300">

---

## 🙏 Credits

Created by ArcanBytes, built for the PS2 homebrew and OPL community.<br> 
Mastercode database based on: [PS2-Widescreen/Bare-Mastercodes-bin](https://github.com/PS2-Widescreen/Bare-Mastercodes-bin)<br>
Original inspiration / idea: [asmodean's ps2force480p](http://asmodean.reverse.net/pages/ps2force480p.html)

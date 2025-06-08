import os
import re
import json

MASTERCODE_DIR = "MASTERCODES"  # Point to the local folder with all .cht files. Mastercodes obtained from https://github.com/PS2-Widescreen/Bare-Mastercodes-bin/tree/main/MASTERCODES
OUTPUT_JSON = "../opl480pcheatgen/mastercodes.json"

database = {}

for root, _, files in os.walk(MASTERCODE_DIR):
    for file in files:
        if not file.lower().endswith('.cht'):
            continue
        path = os.path.join(root, file)
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        if not lines or "mastercode" not in "\n".join(lines).lower():
            continue

        title_line = lines[0]
        id_match = re.search(r'/ID ([A-Z]{4}_[0-9]{3}\.[0-9]{2})', title_line)
        if not id_match:
            continue
        game_id = id_match.group(1)
        title = title_line.replace('"', '')

        try:
            mc_index = [i for i, line in enumerate(lines) if line.lower() == "mastercode"][0]
            code_line = lines[mc_index + 1]
            database[game_id] = {
                "title": title,
                "mastercode": code_line
            }
        except IndexError:
            continue

# Save to JSON
output_dir = os.path.dirname(OUTPUT_JSON)
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
    json.dump(database, f, indent=2, ensure_ascii=False)

print(f"[INFO] Saved {len(database)} entries to {OUTPUT_JSON}")
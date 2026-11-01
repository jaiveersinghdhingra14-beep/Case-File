import re
from pathlib import Path

html = Path(r"D:\Case-File\frontend\dashboard.html").read_text(encoding="utf-8")

# 1. Header info
print("=== 1. HEADER INFO ===")
for m in re.finditer(r'<div class="meta-info">(.*?)</div>', html, re.DOTALL):
    clean = re.sub(r'<[^>]+>', ' ', m.group(1))
    print("Meta:", " ".join(clean.split()))

# 2. KPI Cards
print("\n=== 2. KPI CARDS ===")
for card in re.findall(r'<div class="kpi-card">(.*?)</div>\s*</div>', html, re.DOTALL):
    clean = re.sub(r'<[^>]+>', ' ', card)
    print("KPI:", " ".join(clean.split()))

# 3. Narrative
print("\n=== 3. NARRATIVE (first 500 chars) ===")
narr_m = re.search(r'<div class="narrative-box">(.*?)</div>', html, re.DOTALL)
if narr_m:
    clean = re.sub(r'<[^>]+>', ' ', narr_m.group(1))
    clean_txt = " ".join(clean.split())[:500]
    print("Narrative:", clean_txt.encode('ascii', errors='replace').decode('ascii'))

# 4. Patterns Table
print("\n=== 4. ATTACK PATTERNS TABLE ===")
if "No high-velocity bursts detected" in html:
    print("Patterns Table: No high-velocity bursts detected in sample window.")
else:
    rows = re.findall(r'<tr>(.*?)</tr>', html, re.DOTALL)
    print(f"Total pattern table rows: {len(rows)}")

# 5. Timeline Stats
print("\n=== 5. CHRONOLOGICAL TIMELINE ===")
timeline_m = re.search(r'Chronological Forensic Timeline.*?<div class="card-body">(.*?)</div>\s*</div>', html, re.DOTALL)
if timeline_m:
    clean = re.sub(r'<[^>]+>', ' ', timeline_m.group(1)[:500])
    print("Timeline Header:", " ".join(clean.split()))

# Count timeline step items
steps = re.findall(r'class="step-badge"', html)
print(f"Total step badges: {len(steps)}")

# 6. Playbook
print("\n=== 6. CONTAINMENT PLAYBOOK ===")
playbook_m = re.search(r'Automated Incident Containment Playbook.*?<pre>(.*?)</pre>', html, re.DOTALL)
if playbook_m:
    print("Playbook snippet:\n", playbook_m.group(1)[:300])

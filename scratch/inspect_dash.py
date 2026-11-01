import re
from pathlib import Path

html_path = Path(r"D:\Case-File\frontend\dashboard.html")
html = html_path.read_text(encoding="utf-8")

# Find KPI values
print("--- ALL KPIS ---")
for card in re.findall(r'<div class="kpi-card">(.*?)</div>\s*</div>', html, re.DOTALL):
    clean = re.sub(r'<[^>]+>', ' ', card)
    print(' '.join(clean.split()))

# Find Narrative Summary
print("\n--- NARRATIVE SUMMARY ---")
narr_m = re.search(r'<div class="narrative-box">(.*?)</div>', html, re.DOTALL)
if narr_m:
    clean_txt = narr_m.group(1)[:400].encode('ascii', errors='replace').decode('ascii')
    print(clean_txt)

# Find Patterns Table
print("\n--- PATTERNS TABLE ---")
if "No high-velocity bursts detected in sample window." in html:
    print("WARNING: 'No high-velocity bursts detected in sample window.'")
else:
    print("Patterns are present!")

# Find Network / Graph
print("\n--- GRAPH ---")
node_matches = re.findall(r'id:\s*([^\s,]+),\s*label:\s*([^\s,]+)', html)
print(f"Total node matches: {len(node_matches)}")
if node_matches:
    print("First 5 nodes:", node_matches[:5])

# Find Timeline Steps
print("\n--- TIMELINE ---")
steps = re.findall(r'class="timeline-step"', html)
print(f"Total timeline-step elements: {len(steps)}")
titles = re.findall(r'class="timeline-title"[^>]*>(.*?)</div>', html)
print(f"Total timeline-title elements: {len(titles)}")
for t in titles[:5]:
    clean_t = t.encode('ascii', errors='replace').decode('ascii')
    print("  Title:", clean_t)

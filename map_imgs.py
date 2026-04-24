import zipfile, re, hashlib, os

docx = r'E:\NT230\DoAn\daanlon_fixed.docx'
img_dir = r'E:\NT230\DoAn\extracted_images'

with zipfile.ZipFile(docx) as z:
    xml = z.open('word/document.xml').read().decode('utf-8')
    rels_xml = z.open('word/_rels/document.xml.rels').read().decode('utf-8')

refs = re.findall(r'r:embed="(rId\d+)"', xml)
rids = dict(re.findall(r'Id="(rId\d+)"[^>]*Target="([^"]+)"', rels_xml))

print("=== Image order in document ===")
for i, r in enumerate(refs, 1):
    target = rids.get(r, '?')
    fname = os.path.basename(target)
    fpath = os.path.join(img_dir, fname)
    if os.path.exists(fpath):
        h = hashlib.md5(open(fpath, 'rb').read()).hexdigest()[:8]
    else:
        h = '?'
    print(f"  [{i:02d}] {r} -> {fname}  md5={h}")

# Find duplicates by hash
from collections import defaultdict
hash_map = defaultdict(list)
for i, r in enumerate(refs, 1):
    target = rids.get(r, '?')
    fname = os.path.basename(target)
    fpath = os.path.join(img_dir, fname)
    if os.path.exists(fpath):
        h = hashlib.md5(open(fpath, 'rb').read()).hexdigest()
        hash_map[h].append((i, fname))

print()
print("=== Duplicate images (same MD5) ===")
found = False
for h, items in hash_map.items():
    if len(items) > 1:
        found = True
        print(f"  MD5 {h[:8]}: positions {[x[0] for x in items]} -> files {[x[1] for x in items]}")
if not found:
    print("  None found")

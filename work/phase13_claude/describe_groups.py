"""Describe the canonical five-letter groups; no search or cipher classification."""
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
EXPECTED = {
    'ct1': (615, 'd442e136d63bfc066c20374e2b454ca5581b164e940b307d5600d0d463df943e'),
    'ct2': (160, 'd2cdadbefb0bef2fbcdcf83bf6de1b104583e166f14f0a3d2b545024b3188df0'),
}
result = {'method': 'Fixed alignment at the first body letter; groups of five. Descriptive counts only.',
          'searches': 0, 'cipher_family_inferred': False, 'messages': {}}
groups = {}
for name, (length, expected_hash) in EXPECTED.items():
    path = ROOT / 'work' / 'source' / (name + '.txt')
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected_hash
    text = raw.decode('ascii').upper()
    assert len(text) == length and text.isalpha() and len(text) % 5 == 0
    gs = [text[i:i+5] for i in range(0, len(text), 5)]
    groups[name] = gs
    c = Counter(gs)
    by_position = [Counter(g[i] for g in gs) for i in range(5)]
    result['messages'][name] = {
        'source': str(path.relative_to(ROOT)), 'raw_sha256': expected_hash,
        'normalized_sha256': hashlib.sha256(text.encode()).hexdigest(),
        'letters': length, 'groups': len(gs), 'distinct_groups': len(c),
        'repeated_groups': {g: n for g, n in sorted(c.items()) if n > 1},
        'letter_counts_by_group_position': [dict(sorted(p.items())) for p in by_position],
        'overall_letter_counts': dict(sorted(Counter(text).items())),
    }
result['shared_groups'] = sorted(set(groups['ct1']) & set(groups['ct2']))
result['interpretation_limit'] = ('Repeated groups and positional counts do not identify a codebook, '
    'transposition, language, key, or plaintext. No significance test or model comparison was performed.')
(OUT / 'group_description.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({k: {x: v[x] for x in ['letters', 'groups', 'distinct_groups', 'repeated_groups']}
                  for k, v in result['messages'].items()}, ensure_ascii=False))
print('Shared groups:', result['shared_groups'])

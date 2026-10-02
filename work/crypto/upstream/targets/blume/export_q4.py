"""Export the Spanish quadgram table as q4_es.bin (26^4 float32, log10 probabilities, floor for unseen)."""
import struct, itertools, os
from trans import Q
q = Q()
HERE = os.path.dirname(os.path.abspath(__file__))
vals = []
for a, b, c, d in itertools.product(range(26), repeat=4):
    k = chr(97 + a) + chr(97 + b) + chr(97 + c) + chr(97 + d)
    vals.append(q.d.get(k, q.floor))
open(os.path.join(HERE, 'q4_es.bin'), 'wb').write(struct.pack('%df' % len(vals), *vals))
print('wrote', len(vals), 'floor', q.floor, 'sample "que "', q.d.get('quee'), q.d.get('ando'))


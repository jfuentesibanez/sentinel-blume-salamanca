BLUME / SENTINEL — FASE 4, 2026-10-01

Esta fase investiga el cuello de botella K2 en controles sintéticos. No
ejecuta un ataque a BLUME y no contiene un texto histórico descifrado.
work/phase3_crypto, work/phase2_crypto y work/crypto se usan sin modificarlos.

Hallazgo metodológico
Se ha consultado la tesis de George Lasry (2018), §§5.3.2 y 9.4.6, y el
código oficial CrypTool-2, commit bbcc87bb77f9b3f83c4ded7cb563029b0fbb081c,
ADFGVXAnalyzer/common/TranspositionTransformations.cs. El código ofrece
ciclos entre tres segmentos disjuntos de igual longitud (1–3), ambos sentidos,
todos los ciclos de tres elementos y slides circulares. La fase3 utilizaba
otra variante de tres bloques y slides que no envolvían el final de la clave.

El port source_moves.h reproduce exactamente el conjunto de movimientos
seleccionado del constructor (slides=true, swaps=true, inversions=false),
incluidos sus límites estrictos. La referencia Python independiente simula
la inversión guardada en el constructor y la asignación de transform().
Coincide en los 23 anchos3..25: 102163 movimientos únicos sin identidad.
Para ancho25 son16649 movimientos frente a4086 en fase3. Los conjuntos no
se contienen mutuamente: source añade13084 y omite521 de fase3. A15 añade
2104 y omite160. La identidad se omite exclusivamente en la búsqueda.

No se afirma reproducir el ejecutable original de2014: este código común
es del analizador ADFGVX actual. ADFGVX habilita también inversions=true;
aquí se seleccionan las familias pertinentes para la comparación columnar.
Además, std::shuffle uniforme por barrido sustituye el randomize() de swaps
aleatorios sucesivos de C#. El solver K1 y la IDP mantienen las variantes y
limitaciones documentadas en la fase3. source_ledger.json conserva fuentes,
líneas, hashes y estas reservas. root_source_audit.json es la revisión
independiente de geometría, representación y ausencia de verdad en solver.

Comparación pequeña
smoke_positive.jsonl: dos semillas nuevas20261201–20261202 por corpus
(prosa y proxy de telegrama) y banda(12x15,20x25). Se compara old/source y
single/joint, 32filas. Ambos solvers reciben iguales límites:8reinicios K1,
3rondas,5s/300000evalIDP K2,3s/2000000eval K1 y3s/2000000eval HC finalK2.
Se selecciona por q3; la verdad sintética sólo se usa después del solver.
Una misma seed repite claves entre corpus y las comparaciones son pareadas;
no se presupone independencia ni una tasa estable con estas dos semillas.

La variante source recupera2/8 pares conjuntos completos, old1/8: source
resuelve2/2 en prosa12x15 frente a1/2old. Proxy sigue0/4 en ambos, y20x25
sigue0/4 en ambos. Single obtiene0/8source frente a1/8old. Los8resultados
source20x25 (single+joint) indican agotamiento de un presupuesto de etapa.
Los límites iguales no implican iguales evaluaciones, pues el vecindario
source cuesta más. Los manifiestos conservan recursos y hashes originales.

smoke_negative.jsonl añade una seed20261221, corpusproxy, ambas bandas,
old/source y single/joint: 8filas. Cada ciphertext se baraja de forma
independiente conservando longitud y frecuencias. Ninguna recupera las775
letras originales. Es una comprobación negativa pequeña, sin umbral q3
universal ni demostración de que un máximo lingüístico sea descifrado.

Un diagnóstico K2-only de un par20x25joint ya observado como fallido compara
5s con15s, conservando300000evaluaciones como límite. Sus resultados y
causa de agotamiento están separados en k2_budget_diagnostic.jsonl. No es
otra tanda de validación ni un ataque completo o histórico.
Con5s termina2de5climbs y agota tiempo; con15s termina los5 en9.22s,
sin agotar el límite. La mejor IDP y clave permanecen idénticas e incorrectas.
En este caso aumentar sólo el tiempo no elimina la meseta de la búsqueda.

El resultado no cumple el criterio de ampliar a20–30pares proxy por banda
y posteriormente BLUME. El siguiente trabajo debe mejorar la recuperación
K2 o diagnosticar sus mesetas; este fallo no excluye ninguna región de claves.

Reproducción desde la raíz del proyecto
c++ -O3 -std=c++17 work/phase4_crypto/geometry.cpp -o work/phase4_crypto/geometry
python3 work/phase4_crypto/check_source_moves.py
c++ -O3 -std=c++17 work/phase4_crypto/phase4.cpp -o work/phase4_crypto/phase4
python3 work/phase4_crypto/run_smoke.py
python3 work/phase4_crypto/run_smoke.py --negative --seed 20261221 --count 1
Los ejecutables guardados pertenecen al Mac actual; recompilar en otro host.
El runner sobrescribe sus propios smoke_positive/negative; copiar resultados
si se quiere conservarlos. Las fases previas no se reescriben.

Licencia
Las adaptaciones de los movimientos siguen Apache2.0; copyright CrypTool2
Team. Se conserva el archivo original y source/LICENSE. La infraestructura
propia y las variantes experimentales están identificadas por separado.

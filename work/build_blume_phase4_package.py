from pathlib import Path
import json, hashlib, shutil, zipfile

ROOT = Path(__file__).resolve().parent.parent
NAME = 'Sentinel_BLUME_nuevas_pistas_2026-10-01'
OUT = ROOT / 'outputs' / NAME
OUT.mkdir(parents=True, exist_ok=True)

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def put(rel):
    src = ROOT / rel
    dst = OUT / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)

hist = json.loads((ROOT / 'work/history/phase4-archive-followup.json').read_text())
# The delivery keeps the original scan and a short excerpt of its printed text.
for finding in hist['new_findings']:
    if 'transcription_printed_body' in finding:
        finding.pop('transcription_printed_body')
        finding.pop('translation_es', None)
        finding['printed_excerpt'] = 'muss dringenst ins ausland reisen'
        finding['summary_es'] = 'Pide ayuda para conseguir permiso de tránsito por Francia para un viaje urgente; conserva saludo y cortesía.'
hist['delivery_note'] = 'Copia de entrega con resumen y extracto breve; el texto impreso completo puede consultarse en la imagen original adjunta.'
p = OUT / 'work/history/phase4-archive-followup.json'
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(json.dumps(hist, ensure_ascii=False, indent=2)+'\n')

paths = [
    'work/history/phase4-archive/victor-Unterlagen_0000004-00000104.jpg',
    'work/history/phase4-archive/victor-Unterlagen_0000004-00000106.jpg',
    'work/history/phase4-archive/victor-Unterlagen_0000004-manifest.json',
    'work/history/phase4-archive/Umschlag_0000001-00000001.jpg',
    'work/history/phase4-archive/Umschlag_0000001-manifest.json',
    'work/history/phase4-archive/Olten-Firmenarchive-2026-06-08.pdf',
    'work/history/phase4-archive/Olten-Firmenarchive-2026-06-08.txt',
    'work/history/phase4-archive/Olten-FA013-p11.png',
    'work/history/phase4-archive/archeco-FA013-record.html',
    'work/history/phase4-archive/HLS-HansHunziker-evidence.json',
    'work/history/bar-blume277-adjacent/images/Dokument_0000071-00000513.jpg',
    'work/history/bar-blume277-adjacent/images/Unterlagen_0000068-00000499.jpg',
    'work/crypto/double_search.cpp', 'work/crypto/model_es.bin',
    'work/crypto/holdout_es.txt', 'work/crypto/holdout_proxy.txt',
    'work/crypto/model_provenance.json', 'work/crypto/prepare_model.py',
    'work/phase3_crypto/ict_search.h', 'work/phase3_crypto/phase3.cpp',
    'work/phase3_crypto/METHOD.txt', 'work/phase4_crypto/source/LICENSE',
]
for candidate in (ROOT / 'work/history/phase4-archive').glob('*.json'):
    if candidate.name.startswith(('query-', 'search-')) or candidate.name == 'BAR-C08-neighbors-entity.json':
        paths.append(str(candidate.relative_to(ROOT)))
for candidate in (ROOT / 'work/phase4_crypto').rglob('*'):
    if candidate.is_file() and candidate.suffix in {'.h', '.cpp', '.py', '.json', '.jsonl', '.txt', '.cs'}:
        if candidate.name != 'tree-main.json' and not candidate.name.endswith('_progress.jsonl'):
            paths.append(str(candidate.relative_to(ROOT)))
for rel in sorted(set(paths)):
    put(rel)

positive = [json.loads(x) for x in (ROOT / 'work/phase4_crypto/smoke_positive.jsonl').read_text().splitlines()]
negative = [json.loads(x) for x in (ROOT / 'work/phase4_crypto/smoke_negative.jsonl').read_text().splitlines()]
assert len(positive) == 32 and len(negative) == 8
assert all(x['reencryption_consistency'] for x in positive + negative)
assert not any(x['exact_both_plaintexts'] for x in negative)
old = [x for x in positive if x['variant']=='old']
new = [x for x in positive if x['variant']=='source']
assert sum(x['exact_both_plaintexts'] for x in old) == 2
assert sum(x['exact_both_plaintexts'] for x in new) == 2
assert sum(x['exact_both_plaintexts'] for x in old if x['messages_scored']==1) == 1
assert sum(x['exact_both_plaintexts'] for x in old if x['messages_scored']==2) == 1
assert sum(x['exact_both_plaintexts'] for x in new if x['messages_scored']==1) == 0
assert sum(x['exact_both_plaintexts'] for x in new if x['messages_scored']==2) == 2

readme = '''Sentinel — nuevas pistas y prueba del método de búsqueda
1 de octubre de 2026

BLUME sigue sin descifrar. Este avance aporta un telegrama auténtico en claro de Victor Oswald, una vía concreta para buscar correspondencia empresarial y una comparación reproducible de dos versiones de la búsqueda de claves. Los paquetes anteriores conservan su contenido.

1. UN TELEGRAMA EN ALEMÁN DE 1938

El 9 de mayo de 1938 llegó a Berna un telegrama desde Hendaye, firmado Victor Oswald y dirigido a Dr. Frölicher, Bundeshaus. Pide ayuda para obtener permiso de tránsito por Francia ante un viaje urgente. Tiene saludo, petición y fórmulas de cortesía: no corresponde al modelo de telegrama que elimina sistemáticamente artículos y otras palabras funcionales.

BAR E2001E#1000/1571#787*, Unterlagen_0000004, imagen00000104:
https://image.recherche.bar.admin.ch/iiif/2/3ad2db78-393%2F8-5400-8984-%2F42d2b055e749%2FUnterlagen_0000004%2F00000104.jpg/full/full/0/default.jpg

La carta de Frölicher del 8 de abril de 1938, imagen00000106, va dirigida a Victor M. Oswald, Miraconcha13,3º, San Sebastián. Trata su expulsión de Francia y las gestiones pendientes ante las autoridades francesas. Aporta contexto a la petición de tránsito de1938; no permite determinar el motivo ni la fecha de expulsión y tampoco explicar la cita frustrada de1937.

Estos documentos no establecen que los cifrados de enero1937 estén en alemán. Tampoco ofrecen su clave o un fragmento conocido de su contenido. La discrepancia entre el año1912 del catálogo y el nacimiento1909 de la documentación policial permanece registrada.

2. DOCUMENTACIÓN EMPRESARIAL HUNZIKER EN OLTEN

El Stadtarchiv Olten conserva FA-013, PCO Portlandzementfabrik Olten (1921–1999),12metros lineales. La ficha explica que incluye documentos de empresas Hunziker por la relación entre ambas firmas. La carta dirigida a Oswald en abril1937 lleva el membrete AG Hunziker&Cie, Zürich, con fábricas de materiales de construcción en Brugg y Olten.

El interrogatorio del12mayo1937 identifica al industrial Hans Hunziker, nacido el3mayo1874 en Reinach, hijo de Johann y Elisabeth Galliker. Esos datos coinciden con la biografía empresarial del HLS; el vínculo se sostiene por varios datos, además del apellido. Todavía no se ha consultado el inventario detallado ni localizado correspondencia con Oswald dentro de FA-013.

Ficha del fondo:
https://ub-archeco24.ub.unibas.ch/index.php/pco-portlandzementfabrik-olten-1931
Resumen municipal del8junio2026, página11:
https://www.olten.ch/_docn/7067200/26-06-08_do_Bestands%C3%BCbersicht_Firmenarchive.pdf
Biografía de Hans Hunziker:
https://hls-dhs-dss.ch/de/articles/029551/2008-01-16/
Custodio:
https://www.olten.ch/aemter/974
Contacto público: stadtarchiv@olten.ch

El siguiente recurso concreto es el Dossierverzeichnis de FA-013. La pregunta de investigación es si conserva correspondencia de Hans Hunziker y de su empresa en enero-abril1937 con Werner/Victor Oswald, en particular sobre un viaje a París y Londres y el telegrama recibido desde Zürich antes del19abril1937. Esa petición permanece propuesta; no se ha enviado una consulta.

La búsqueda acotada en219textos OCR del BAR277 y siete consultas de catálogo no localizó el inventario del registro del despacho de Werner ni aquel telegrama de París. No se leyeron visualmente las219piezas. Los volúmenes vecinos BAR275/276 son candidatos de serie, sin digitalización pública encontrada; no sabemos si contienen esos documentos.

3. QUÉ NOS DICE LA PRUEBA CRIPTOGRÁFICA

El código común de transformaciones de CrypTool-2 define ciclos de tres segmentos y desplazamientos circulares que nuestra fase3 no recorría. Se ha portado ese vecindario conservando sus límites. La revisión del código y la comparación con una simulación independiente verificaron102163movimientos distintos de la identidad en23anchos (3–25).

Fuente fijada por commit:
https://github.com/CrypToolProject/CrypTool-2/blob/bbcc87bb77f9b3f83c4ded7cb563029b0fbb081c/CrypPlugins/ADFGVXAnalyzer/common/TranspositionTransformations.cs

El código procede del analizador ADFGVX actual y sirve para establecer la geometría de esos movimientos. No acredita que hayamos reproducido exactamente el programa histórico de Lasry de2014. La selección de familias sin inversiones, el orden de barrido aleatorio y las restantes variantes están descritos en source_ledger.json.

La comparación pequeña usa mensajes simulados de615y160letras, con claves compartidas conocidas sólo por el generador, anchos12×15y20×25, dos semillas nuevas por combinación de corpus/anchos y los mismos límites de cálculo. El solucionador no recibe texto ni claves verdaderas. Prosa española y un sustituto de estilo telegráfico son dos corpus de prueba; ninguna de esas elecciones está demostrada para BLUME.

Resultados de32búsquedas positivas (16por versión):
  Versión anterior:1/8 recuperaciones exactas al puntuar sólo el mensaje largo, y1/8 al puntuar ambos.
  Nuevo vecindario:0/8 al puntuar sólo el largo, y2/8 al puntuar ambos.
  Ambas versiones:2/16 recuperaciones exactas en total.
  Los éxitos conjuntos nuevos son los dos casos de prosa12×15. En el sustituto telegráfico no hubo recuperaciones conjuntas. La versión nueva agotó un presupuesto de etapa en las8búsquedas20×25.

Ocho controles negativos pequeños, con letras barajadas:0 recuperaciones exactas. Las semillas repetidas entre corpus comparten claves y las comparaciones single/joint y old/source son parejas; estas cifras no representan observaciones independientes ni una tasa general de éxito. Los diagnósticos de K2, cuando se incluyen, son pruebas focalizadas separadas y no forman parte de esos denominadores.

Un diagnóstico separado del par20×25 con sustituto telegráfico y semilla20261201 prueba sólo la búsqueda de K2: con5segundos termina dos de cinco búsquedas locales; con15segundos termina las cinco en9,22segundos, pero obtiene exactamente la misma clave incorrecta y la misma puntuación. En este caso el atasco persiste aunque haya tiempo para terminar. El siguiente mecanismo a probar es una forma controlada de escapar de esos máximos locales.

El cambio modifica qué casos se recuperan y aumenta el coste. Esta muestra no establece una mejora general ni prepara todavía un barrido fiable de las claves históricas largas. No se ha ejecutado en esta fase un ataque sobre los telegramas BLUME ni se ha excluido ninguna familia de claves, idioma o sistema histórico.

4. REPRODUCIR Y REVISAR

El paquete incluye originales, fuentes, consultas delimitadas, código y resultados, con rutas relativas que conservan los include. Desde su carpeta raíz:
  c++ -O3 -std=c++17 work/phase4_crypto/phase4.cpp -o /tmp/sentinel-blume-phase4
  /tmp/sentinel-blume-phase4 source work/crypto/model_es.bin work/crypto/holdout_es.txt 12 15 20261201 8 3 5

La salida contiene dos resultados: puntuando sólo el largo y puntuando ambos mensajes. Una recuperación sólo se declara exacta cuando coincide con los textos de prueba; poder volver a cifrar cualquier resultado con sus claves es una comprobación de consistencia, no una prueba de descifrado histórico.

La próxima prioridad histórica es el inventario empresarial de Olten y la localización del acta de registro. En criptografía, los controles para claves largas y otros estilos/idiomas deben mejorar antes de dedicar un barrido amplio al material histórico.
'''
# Improve spacing in research labels without altering filenames, URLs or code.
import re
readme_lines=[]
for line in readme.splitlines():
    if not line.startswith(('http', '  c++', '  /tmp')):
        line=re.sub(r'(?<=[a-záéíóúñ])(?=\d)', ' ', line)
        line=re.sub(r'(?<=\d)(?=[a-záéíóúñ])', ' ', line)
        line=line.replace('Hunziker&Cie', 'Hunziker & Cie').replace('),12', '), 12').replace('13,3º', '13, 3º')
        line=re.sub(r':(?=\d)', ': ', line).replace('102163 movimientos', '102.163 movimientos')
    readme_lines.append(line)
(OUT / 'LEEME.txt').write_text('\n'.join(readme_lines)+'\n')

files=[]
for path in sorted(OUT.rglob('*')):
    if path.is_file() and path.name not in {'manifest.json','SHA256SUMS','verification.json'}:
        files.append({'path':str(path.relative_to(OUT)), 'bytes':path.stat().st_size, 'sha256':digest(path)})
manifest={'project':'Sentinel — BLUME', 'date':'2026-10-01', 'historical_plaintext_found':False,'files':files}
(OUT / 'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
(OUT / 'SHA256SUMS').write_text(''.join(x['sha256']+'  '+x['path']+'\n' for x in files))
assert all(digest(OUT/x['path'])==x['sha256'] for x in files)
(OUT / 'verification.json').write_text(json.dumps({'file_hashes_verified':len(files),'positive_rows_verified':len(positive),'negative_rows_verified':len(negative),'all_reencryption_consistent':True,'history_originals_visually_verified_by_root':['00000104','00000106','00000513','00000499','Olten-FA013-p11']},indent=2)+'\n')
archive=OUT.with_suffix('.zip')
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
    for path in sorted(OUT.rglob('*')):
        if path.is_file(): z.write(path,str(Path(NAME)/path.relative_to(OUT)))
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    for x in files:
        assert hashlib.sha256(z.read(NAME+'/'+x['path'])).hexdigest()==x['sha256']
print(json.dumps({'folder':str(OUT),'zip':str(archive),'bytes':archive.stat().st_size,'sha256':digest(archive),'files':len(files)+3},ensure_ascii=False))

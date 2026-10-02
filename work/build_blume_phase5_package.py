from pathlib import Path
import hashlib, json, shutil, zipfile

ROOT = Path(__file__).resolve().parent.parent
NAME = 'Sentinel_BLUME_inventario_y_controles_2026-10-01'
OUT = ROOT / 'outputs' / NAME
assert not OUT.exists(), 'Preserve earlier delivery; choose a new name rather than overwrite.'
OUT.mkdir(parents=True)

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def put(rel):
    src = ROOT / rel; dst = OUT / rel
    dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(src, dst)

paths = [
    'work/crypto/double_search.cpp', 'work/crypto/model_es.bin',
    'work/crypto/model_provenance.json', 'work/crypto/prepare_model.py',
    'work/crypto/pg2000.txt', 'work/crypto/holdout_es.txt', 'work/crypto/holdout_proxy.txt',
    'work/phase3_crypto/phase3.cpp', 'work/phase3_crypto/ict_search.h', 'work/phase3_crypto/METHOD.txt',
    'work/phase4_crypto/source_moves.h', 'work/phase4_crypto/source/LICENSE',
    'work/phase4_crypto/source/TranspositionTransformations.cs', 'work/phase4_crypto/k2_budget_diagnostic.jsonl',
    'work/source/ct1.txt', 'work/source/ct2.txt',
    'work/final_language_comparison.json', 'work/phase5_root_verification.json'
]
for directory in ('work/phase5_language', 'work/phase5_crypto', 'work/history/phase5-archive'):
    for p in (ROOT / directory).rglob('*'):
        if p.is_file() and p.suffix in {'.py','.cpp','.h','.txt','.json','.jsonl','.pdf','.png','.html','.bin'}:
            paths.append(str(p.relative_to(ROOT)))
for rel in sorted(set(paths)): put(rel)

oracle = json.loads((ROOT / 'work/phase5_language/oracle_summary.json').read_text())
assert oracle['rows'] == 24
assert all(x['exact_775_letters'] == 8 and x['budget_expired'] == 0 for x in oracle['summary'])
crypto = json.loads((ROOT / 'work/phase5_crypto/summary.json').read_text())
assert len(crypto['policies']) == 4 and crypto['all_global_bests_unchanged']
verification = json.loads((ROOT / 'work/phase5_root_verification.json').read_text())
assert verification['passed'] and verification['protected_prior_files_unchanged'] == 133

report = '''SENTINEL — BLUME SALAMANCA
Avance del 1 de octubre de 2026, fase 5

Seguimos sin una lectura verificada de los telegramas de enero de 1937,
sin su clave y sin una identificación segura del destinatario BLUME.

EL AVANCE HISTÓRICO
Encontramos el inventario detallado de FA-013, público y de 26 páginas.
Corrige el informe anterior: el inventario se puede consultar sin pedirlo
al archivo. Los originales descritos en él aún no se han consultado.
https://firmenarchive.ch/uploads/1/4/2/1/142137325/fa-013_portlandzementfabrik_olten_pco_hunziker_ag.pdf

La búsqueda ya tiene dos destinos concretos en el Stadtarchiv Olten:
• Actas del consejo: FA-013-11.65.67; tramo 1934–1964 en FA-013-NF_0001.
  Interesan enero–abril de 1937 y posibles anexos (inventario, página 2).
• Informes anuales: FA-013-11.65.79; 1932–1950 en FA-013-NF_0008.
  Interesan los ejercicios 1936 y 1937 (página 2).

El fondo también contiene publicaciones sobre la historia de la empresa;
sus referencias se detallan en el ledger. El inventario indica que faltan
los informes de auditoría de 1937, una serie distinta. No demuestra ausencia
de informes anuales ni de correspondencia en los documentos conservados.

Por qué importa: la carta de Hunziker del 19 de abril de 1937, ya cotejada,
menciona un telegrama desde Zürich que anunciaba que Oswald no podía ir
a París. Encontrar ese telegrama o correspondencia asociada podría aportar
otros mensajes y, si se conservara, información sobre cómo se cifraban.
No tenemos prueba de que use el sistema de los telegramas de enero.

Hay un borrador de consulta en alemán y su traducción al español:
work/history/phase5-archive/Olten-FA013-draft-de.txt
work/history/phase5-archive/Olten-FA013-draft-es.txt
Pide acceso a documentos delimitados por fecha y orientación sobre otros
fondos de correspondencia. Está preparado localmente; no se ha enviado.

Otra vía: las fichas BAR E4320B#1974/47#275* y #276* indican acceso libre
y posibilidad de pedido; no enlazan digitalización en las respuestas
consultadas. La política actual del BAR permite solicitar digitalización
gratuita. No se ha cursado ningún pedido ni sabemos si contienen el acta
del registro del 28 de abril de 1937. Esa gratuidad no se presupone en Olten.
https://www.bar.admin.ch/de/online-zugang

EL AVANCE CRIPTOGRÁFICO
Preparamos modelos de alemán y francés con textos distintos de los usados
en sus controles: Die Verwandlung (Kafka) y Candide (Voltaire). En alemán
comparamos dos normalizaciones: quitar la diéresis o convertirla en ae/oe/ue.
El modelo español anterior permanece congelado.
https://www.gutenberg.org/ebooks/22367
https://www.gutenberg.org/ebooks/4650

Los 24 controles pequeños recuperan las 775 letras y la primera clave.
La segunda clave correcta se proporciona expresamente al programa.
Son 12 ejecuciones que evalúan un mensaje y el par, con dos semillas,
anchos 12×15 y 20×25, y tres modelos; hay comparaciones emparejadas.
Esto valida el uso inicial de esos modelos. No representa 24 ataques
completos independientes ni prueba que podamos descifrar BLUME.

La sensibilidad del idioma también importa. Con las frecuencias del corpus
moderno UD anterior salía primero el español; con los nuevos textos
literarios sale primero el francés. No son probabilidades de idioma.
La muestra depende de autor, época y tema, de modo que no fijamos el idioma
del mensaje a partir de esta comparación.

Para el atasco de la segunda clave comparamos cuatro políticas sobre UN
caso sintético ya observado: búsqueda local, reinicios, perturbaciones
desde el mejor resultado y un recorrido que acepta otros óptimos locales.
Las tres políticas de escape consumen 150.000 evaluaciones cada una;
ninguna mejora la clave incorrecta inicial. Se visitan otros estados,
pero la mejor IDP sigue en −2,47530343674 (la correcta da −2,195668215).
La clave correcta sólo se usa después para evaluar el resultado.

Este diagnóstico no es una nueva tasa de recuperación y no excluye
ninguna longitud de clave. No justifica ampliar ahora esa configuración.
No se ha lanzado un nuevo ataque histórico en esta fase.

CÓMO CONTINUAR
1. Consultar en Olten las actas y los informes identificados y preguntar
   dónde se conserva la correspondencia de Hans Hunziker con los Oswald.
2. Solicitar al BAR la digitalización de #275 y #276 para comprobar si
   añaden documentación policial al expediente #277 ya leído.
3. Cambiar el mecanismo de búsqueda de la segunda clave y demostrar
   recuperación con ambas claves desconocidas en controles nuevos antes
   de ampliar los ataques históricos, usando varios idiomas.

CONTENIDO Y COMPROBACIÓN
El paquete reúne inventario, páginas cotejadas, fichas, borradores, modelos,
código, procedencia y registros de las pruebas. Las instrucciones técnicas
están en REPRODUCIR.txt y work/phase5_crypto/README.txt.
La revisión independiente verificó hashes, presupuestos, probabilidades de
los modelos y claves/puntuaciones exactas de los controles sintéticos.
Los 133 archivos protegidos de las fases anteriores siguen intactos.
MANIFEST.json verifica los archivos de esta entrega.
'''
(OUT / 'LEEME.txt').write_text(report, encoding='utf-8')
(OUT / 'REPRODUCIR.txt').write_text('''Desde la raíz de la carpeta descomprimida, con Python 3 y C++17:

1. Compilar el núcleo que usa la prueba con K2 conocida:
c++ -O3 -std=c++17 work/phase3_crypto/phase3.cpp -o work/phase3_crypto/phase3

2. Un control alemán de muestra (produce dos registros JSON):
work/phase3_crypto/phase3 oracle work/phase5_language/de_fold/model.bin work/phase5_language/de_fold/holdout.txt 20 25 20261401 8 3 3

3. Reconstruir modelos de alemán/francés y comparación de frecuencias:
python3 work/phase5_language/prepare_languages.py

4. Repetir el pequeño conjunto de controles:
python3 work/phase5_language/run_oracle_controls.py

Para los diagnósticos de escape, véanse los comandos completos en
work/phase5_crypto/README.txt. Los resultados son condicionales a una K2
incorrecta seleccionada en fase 4; no son ataques históricos.

Las órdenes de regeneración actualizan archivos en la copia descomprimida;
trabajar sobre otra copia si se quiere conservar la entrega exacta.
Los binarios no se distribuyen. Los manifiestos originales registran sus
hashes y las rutas del Mac utilizado; recompilar puede cambiar esos hashes.
MANIFEST.json permite comprobar los archivos que sí se distribuyen.
Los tiempos varían según el equipo y los compiladores.

Los textos Gutenberg tienen entrenamiento (primer 80% del cuerpo) y
controles (último 20%) sin solapamiento; las muestras proceden de una obra
por idioma y no representan el lenguaje comercial de 1937. La procedencia
especifica los recortes y las normalizaciones. No hay nuevos controles
negativos de idioma ni un nuevo ataque con ambas claves desconocidas.

El port de los movimientos CrypTool2 conserva la licencia Apache 2.0 en
work/phase4_crypto/source/LICENSE. Se adjunta la fuente C# de referencia.
La motivación ILS es Lasry (2018), §§2.3.3 y 4.3.2, una propuesta de
investigación, no un ataque publicado a BLUME:
https://www.uni-kassel.de/upress/online/OpenAccess/978-3-7376-0458-1.OpenAccess.pdf
''',encoding='utf-8')

files = sorted(p for p in OUT.rglob('*') if p.is_file())
manifest = {'date':'2026-10-01','package':NAME,'historical_plaintext_verified':False,
            'files':[{'path':str(p.relative_to(OUT)),'bytes':p.stat().st_size,'sha256':digest(p)} for p in files]}
(OUT / 'MANIFEST.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n')
archive = OUT.with_suffix('.zip')
assert not archive.exists()
with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
    for p in sorted(OUT.rglob('*')):
        if p.is_file(): z.write(p, str(p.relative_to(OUT.parent)))
with zipfile.ZipFile(archive) as z: assert z.testzip() is None
result = {'package':str(archive),'files':len(manifest['files'])+1,'bytes':archive.stat().st_size,
          'sha256':digest(archive),'zip_crc_valid':True,'prior_packages_unchanged':True}
(ROOT / 'work/phase5_package_receipt.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result))

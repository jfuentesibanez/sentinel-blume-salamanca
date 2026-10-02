from pathlib import Path
import hashlib
import json
import shutil
import zipfile

base = Path(__file__).resolve().parent.parent
history = base / 'work/history'
out = base / 'outputs/Sentinel_BLUME_originales_BAR'
out.mkdir(parents=True, exist_ok=True)
(out / 'imagenes').mkdir(exist_ok=True)
(out / 'procedencia').mkdir(exist_ok=True)
(out / 'ocr').mkdir(exist_ok=True)

image_ledger = json.loads((history / 'bar-blume277-images-source-ledger.json').read_text())
portable = []
for item in image_ledger:
    source = base / item['local_path']
    destination = out / 'imagenes' / source.name
    shutil.copyfile(source, destination)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    assert digest == item['sha256'], source.name
    portable.append({'file': str(destination.relative_to(out)), 'sha256': digest,
                     'source_url': item['source_url'], 'canvas': item['canvas_label'],
                     'piece': item['document'], 'bytes': destination.stat().st_size})

for name in ['bar-blume277-entity.json', 'bar-blume277-manifest.json',
             'bar-blume277-sub66-manifest.json', 'bar-blume277-Dokument_0000069-manifest.json',
             'bar-blume277-Unterlagen_0000072-manifest.json', 'bar-blume277-images-source-ledger.json',
             'bar-blume277-evidence.json', 'legimi-book-note42.json',
             'bar-blume277-cipher-visual-audit.json']:
    source = history / name
    if source.exists():
        shutil.copyfile(source, out / 'procedencia' / name)

for name in ['Dokument_0000069_OCR.txt', 'Unterlagen_0000072_OCR.txt']:
    shutil.copyfile(history / 'bar-blume277-ocr' / name, out / 'ocr' / name)
shutil.copyfile(history / 'bar-blume277-ocr.zip', out / 'ocr/OCR-completo-del-expediente.zip')

ficha = '''SENTINEL · BLUME SALAMANCA · HALLAZGO DOCUMENTAL
Consulta: 1 de octubre de 2026.

La nota 42 del capítulo «Bilder für Hitler, Bomben für Franco» de Nylon und
Napalm, Regula Bochsler (Hier und Jetzt, 2022; ISBN electrónico
978-3-03919-992-1), identifica la remisión PTT → Fiscalía Federal del
15 de enero de 1937 en el expediente BAR E4320B#1974/47#277*.
El crédito de imágenes 48 o/u cita el mismo expediente. El enlace del
crédito vuelve a las dos fotografías de los telegramas: 48 es la página
de la edición impresa. Las páginas 64, 66 y 825 de Legimi son posiciones
del lector y no equivalen a páginas impresas.

Expediente: Spanische Revolution (Passvisas etc.), 1936–1938.
Acceso público y digitalizado. Es un expediente colectivo.
Catálogo:
https://www.recherche.bar.admin.ch/recherche/#/de/archiv/einheit/3578609
Visor:
https://viewer.recherche.bar.admin.ch/?manifest=https://www.recherche.bar.admin.ch/recherche/files/manifests/0000/0357/8609/3578609.json

DOCUMENTOS Y LOCALIZACIÓN
1. Carta PTT, 15.1.1937: imagen Unterlagen_0000072-00000519.jpg.
   Asunto: neutralidad ante España. Remite confidencialmente dos copias
   de telegramas cifrados enviados de Zúrich a Salamanca.
2. Interrogatorio de Werner Leodegar Oswald, 28.4.1937, 14:25:
   Dokument_0000069, imágenes 501, 503 y 505 (502, 504 y 506 son reversos).
   La policía pregunta por autor, contenido y clave de los dos telegramas.
   Werner atribuye envío y firma a su hermano Viktor, niega conocer el
   contenido y niega tener la clave. El negocio de lana es una conjetura
   que declara Werner, no un texto descifrado ni un hecho independiente.
   Hisma, Sevilla, y autoridades españolas en Burgos aparecen en el acta.
3. Telegrama largo T1: Unterlagen_0000072-00000527.jpg, canvas 9.
4. Telegrama corto T2: Unterlagen_0000072-00000531.jpg, canvas 13.
   Ambos están fechados el 8 de enero de 1937. El destinatario aparece
   como BLUME SALAMANCA. Las dos imágenes preservan sus anotaciones.
   La anotación roja de T1 atribuye el mensaje a Viktor Oswald y da la
   fecha de nacimiento 15.11.1909 y Burgos. Su mano y fecha no están
   identificadas; no demuestra por sí sola quién redactó el mensaje.

QUÉ CAMBIA PARA EL PROYECTO
Tenemos procedencia archivística y acceso a originales de mayor calidad,
la carta de remisión y el acta policial. La nota 44 del libro identifica
a Peter Heinzmann, Carlo Matteotti, Patrick Liniger y Kandiah Viveksanth
en relación con un intento fallido de descifrado de 2020. Esa afirmación
procede del libro; no hemos obtenido su informe técnico.

No se ha encontrado clave ni texto claro en la carta PTT o el acta.
No se ha revisado íntegramente el expediente para probar su ausencia.
La identidad de BLUME sigue sin demostrarse. El contexto de un proyecto
de bombas de hormigón no prueba que ese sea el contenido de los mensajes.
El acta es un interrogatorio presencial, no una escucha telefónica.

CONTENIDO DEL PAQUETE
20 JPEG originales sin recortar ni alterar, OCR de las dos piezas,
ZIP original de OCR completo (219 archivos), catálogos y manifests,
registros de evidencia y referencias del libro. manifest-paquete.json
asocia cada imagen con URL y SHA-256. El OCR contiene errores y debe
cotejarse con las imágenes para cualquier cita o transcripción.
Las capturas del libro y la cancelación de Legimi se conservan aparte
en outputs/Sentinel_BLUME_Legimi. La prueba se canceló el 1 de octubre.
'''
(out / 'LEEME-hallazgos.txt').write_text(ficha, encoding='utf-8')
(out / 'manifest-paquete.json').write_text(json.dumps(portable, ensure_ascii=False, indent=2) + '\n')

files = sorted(p for p in out.rglob('*') if p.is_file())
checksums = ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(out)) + '\n'
                    for p in files if p.name != 'SHA256SUMS.txt')
(out / 'SHA256SUMS.txt').write_text(checksums)
archive = base / 'outputs/Sentinel_BLUME_originales_BAR.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
    for p in sorted(out.rglob('*')):
        if p.is_file():
            z.write(p, str(p.relative_to(out.parent)))
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    for info in z.infolist():
        original = out.parent / info.filename
        assert hashlib.sha256(z.read(info)).digest() == hashlib.sha256(original.read_bytes()).digest()
print(json.dumps({'archive': str(archive), 'bytes': archive.stat().st_size,
                  'images': len(portable), 'files': len(files) + 1,
                  'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}, ensure_ascii=False))

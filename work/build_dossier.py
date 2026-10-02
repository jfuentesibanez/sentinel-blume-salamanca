from pathlib import Path
import json
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, KeepTogether

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'outputs'
DATA = OUT / 'blume_sentinel'
NAVY = colors.HexColor('#173149')
RUST = colors.HexColor('#a94d2e')
GREY = colors.HexColor('#53616c')
LIGHT = colors.HexColor('#edf2f5')
styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name='TitleCustom', fontName='Helvetica-Bold', fontSize=27, leading=30, textColor=NAVY, spaceAfter=12))
styles.add(ParagraphStyle(name='SectionCustom', fontName='Helvetica-Bold', fontSize=15, leading=19, textColor=NAVY, spaceBefore=7, spaceAfter=10))
styles.add(ParagraphStyle(name='BodyCustom', fontName='Helvetica', fontSize=10.1, leading=14.4, spaceAfter=8))
styles.add(ParagraphStyle(name='SmallCustom', fontName='Helvetica', fontSize=8.2, leading=11.2, textColor=GREY, spaceAfter=6))
styles.add(ParagraphStyle(name='MonoCustom', fontName='Courier', fontSize=7.6, leading=10.5, spaceAfter=7))
styles.add(ParagraphStyle(name='CellCustom', fontName='Helvetica', fontSize=8.5, leading=11.3))
styles.add(ParagraphStyle(name='CellHeaderCustom', fontName='Helvetica-Bold', fontSize=8.3, leading=11, textColor=colors.white))
story = []

def p(text, style='BodyCustom'):
    story.append(Paragraph(text, styles[style]))

def h(text):
    p(text, 'SectionCustom')

def table(rows, widths):
    widths = [x * (A4[0] - 36*mm) / sum(widths) for x in widths]
    cells = [[Paragraph(escape(str(x)), styles['CellHeaderCustom' if i == 0 else 'CellCustom']) for x in row] for i, row in enumerate(rows)]
    t = Table(cells, colWidths=widths, repeatRows=1, hAlign='LEFT')
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY), ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, LIGHT]),
        ('LEFTPADDING', (0,0), (-1,-1), 7), ('RIGHTPADDING', (0,0), (-1,-1), 7),
        ('TOPPADDING', (0,0), (-1,-1), 7), ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LINEBELOW', (0,-1), (-1,-1), .4, colors.HexColor('#ccd6dc')),
    ]))
    story.append(t)
    story.append(Spacer(1, 9))

def link(label, url):
    return '<a href="'+escape(url, {'"':'&quot;'})+'" color="#175a86">'+escape(label)+'</a>'

def photo(path, width, max_height=None):
    width = min(width, A4[0] - 36*mm)
    im = Image(str(path))
    factor = width / im.imageWidth
    if max_height: factor = min(factor, max_height / im.imageHeight)
    im.drawWidth = im.imageWidth * factor
    im.drawHeight = im.imageHeight * factor
    im.hAlign = 'LEFT'
    story.append(im)
    story.append(Spacer(1, 6))

manifest = json.loads((DATA / 'source_manifest.json').read_text())
summary = json.loads((ROOT / 'work/crypto/controls_summary.json').read_text())
language = json.loads((DATA / 'language_comparison.json').read_text())
lookup = {(r['w1'],r['w2'],r['corpus'],r['messages_scored']):r for r in summary}

p('SENTINEL / DOSSIER DE INVESTIGACIÓN', 'SmallCustom')
p('BLUME SALAMANCA', 'TitleCustom')
p('Verificación documental y primer laboratorio de descifrado', 'SectionCustom')
p('1 de octubre de 2026. Dos telegramas del 8 de enero de 1937. <b>Estado: sin plaintext histórico verificado.</b> Se han comprobado las transcripciones, localizado una nueva pista archivística y construido un buscador de doble transposición con controles medidos.')
p('El resultado de esta fase es una base auditable para continuar la investigación. El buscador todavía no recupera consistentemente claves largas en controles comparables. Una lectura incomprensible, aunque recifre perfectamente, no se presenta como solución.')
h('Resultados comprobados')
table([
    ['Línea', 'Resultado', 'Límite'],
    ['Documentos', '615 y 160 letras; los dos hashes coinciden. Tres L confirmadas visualmente.', 'RBEEP, grupo 113 de T1, queda con confianza media por tinta roja.'],
    ['Historia', 'Expediente oficial de Victor Oswald y carta de 18 enero 1939 cotejada.', 'No es el expediente policial de Werner que contiene BLUME.'],
    ['Descifrado', '60 búsquedas de control en cinco parejas de longitudes de clave; código y resultados registrados.', '0/3 recuperaciones en las parejas 12x15, 15x20 y 20x25.'],
    ['Idiomas', 'Comparación equilibrada de cinco muestras modernas de 39.069 letras cada una.', 'Español es una prioridad de prueba; idioma y género siguen abiertos.'],
], [70, 221, 220])
h('Criterio de solución')
p('Un candidato debe sostener un texto coherente, explicar las letras y posibles rellenos, fijar un procedimiento y dos permutaciones concretas, y reproducir exactamente el ciphertext al recifrar. Si se alegan claves compartidas, debe funcionar con cada longitud y matriz por separado. La coincidencia de palabras aisladas o una puntuación alta no alcanza ese criterio.')
p('Archivos y fuentes fijados en la revisión <b>'+manifest['revision'][:12]+'</b> de dbourdeau/cyphersolver. El paquete adjunto conserva la revisión completa, hashes de archivos, código, parámetros y resultados.', 'SmallCustom')
story.append(PageBreak())

h('1  Cotejo de los telegramas')
p('Se realizaron dos lecturas visuales independientes de las copias fotográficas del repositorio, incluida la ampliación de los grupos dudosos. Los 123 grupos de T1 y los 32 de T2 coinciden con los archivos descargados. BLUME SALAMANCA se conserva como dirección externa al cuerpo cifrado, una interpretación compatible con el formulario.')
table([
    ['Dato visible', 'Telegrama 1', 'Telegrama 2'],
    ['Fecha / serie', '8 enero 1937 / 1381', '8 enero 1937 / 1486'],
    ['Hora del formulario', '11:31; transmisión anotada 11:42', '17:34; transmisión anotada 17:40'],
    ['Cuerpo cifrado', '123 grupos / 615 letras', '32 grupos / 160 letras'],
    ['Recuento de palabras', '125: 123 grupos + dos palabras de dirección', 'Nota manuscrita compatible con 34 W; certeza menor'],
    ['Índice de coincidencia', '0,06948438865', '0,07099056604'],
], [130, 191, 190])
table([
    ['Grupo de T1', 'Lectura anterior', 'Lectura confirmada'],
    ['38', 'SOIRS', 'SOLRS'], ['48', 'ACCEI', 'ACCEL'], ['122', 'FTUIX', 'FTULX'],
], [130, 191, 190])
p('La L tiene pie derecho; la I presenta serif superior e inferior. En el grupo 113, RBEEP es la lectura preferida, con restos negros compatibles bajo el rojo. DRODL (114) e IPLAN (121) siguen legibles. No se identificó otra discrepancia; todas las letras de T2 resultan claras.')
photo(ROOT / 'work/visual_root/rows13_16.png', 511)
p('Detalle documental de T1. El aumento facilita la lectura, pero no añade resolución a la fotografía original.', 'SmallCustom')
p('SHA-256 de A-Z mayúsculas, sin espacios:', 'SmallCustom')
for name in ('ct1.txt', 'ct2.txt'):
    r = json.loads((DATA / 'verification.json').read_text())['messages'][0 if name=='ct1.txt' else 1]
    p(name+': '+r['sha256_normalized'], 'MonoCustom')
p('Los hashes acreditan igualdad de transcripciones, no autenticidad archivística ni solución. El IC es compatible con conservación de frecuencias; no demuestra por sí solo transposición ni español. Las fotos son copias del repositorio, no una nueva digitalización certificada del archivo. [1]', 'SmallCustom')
story.append(PageBreak())

h('2  La pista documental de Victor Oswald')
p('El Archivo Federal Suizo ofrece el expediente <b>Oswald, Victor, 1912, Madrid</b>, fechas 1937-1948, signatura <b>E2001E#1000/1571#787*</b>. El año 1912 forma parte del título del catálogo; no se adopta aquí como dato biográfico, porque otra pieza presenta una fecha distinta. [2]')
p('Una carta de <b>H. Pfyffer a Giuseppe Motta, 18 de enero de 1939</b>, afirma que Viktor Oswald desarrolla importación y exportación en el lado de Franco desde diciembre de 1936. Se cotejó la imagen, no solo su OCR: Dokument_0000003, canvas 4, imagen 00000076.jpg, hoja marcada -2-. Es un testimonio contemporáneo de 1939, no la lectura del telegrama de 1937. [3]')
photo(ROOT / 'work/history/victor-00000076.jpg', 511, 245)
p('Carta conservada en el expediente de Victor. Fuente: Archivo Federal Suizo, imagen identificada en [3].', 'SmallCustom')
p('No se encontró BLUME, SALAMANCA ni WERNER en los cuatro archivos OCR del expediente. Hay un telegrama alemán en claro de mayo de 1938 sobre tránsito por Francia; no se ha identificado como copia de BLUME. Una búsqueda negativa en OCR no demuestra ausencia documental.')
p('Otra pista concreta es <b>Oswald, Madrid</b>, 1936-1938, <b>E2001D#1000/1551#5627*</b>, sin digitalización localizada. La identidad de BLUME y la signatura exacta del expediente policial de Werner siguen pendientes. [4]')
p('El extracto público de <i>Nylon und Napalm</i>, de Regula Bochsler, sitúa la actividad española en el entorno de PATVAG, Werner, Rudolf y Victor, y menciona CEDRIC. Esto justifica buscar esa documentación. No autoriza atribuir el contenido cifrado a lana, armas, mercurio ni a una empresa concreta. [5]', 'SmallCustom')
p('La web de Bochsler atribuye los envíos a Victor o quizá Werner. Por separado, T2 muestra el remitente Dr. ing. W. E. Oswald. Se conserva esta diferencia entre atribución narrativa y dato del formulario; no se adjudica a Victor el texto de T2. [5b]', 'SmallCustom')
story.append(PageBreak())

h('3  Método y calibración')
p('Se implementó una base C++17 que busca permutaciones, sin limitarse a palabras clave. Primero puntúa candidatos de la segunda clave mediante una relajación de adyacencias IDP; después busca la primera clave con quadgramas y refina ambas alternativamente. En la pareja se comparten claves, pero las matrices y las ventanas lingüísticas de cada telegrama son independientes.')
p('<b>Convención calibrada:</b> escribir por filas y leer columnas en orden de clave, dos veces; sin añadir padding. El código maneja exactamente las columnas largas y cortas. Como gcd(615,160)=5, un ancho compartido superior a cinco obliga a que al menos una matriz de cada etapa sea incompleta.')
p('Modelo: 1.321.563 letras de la primera parte de Don Quijote, con bigramas, trigramas y quadgramas. El 20% final se reservó antes de normalizar para controles disjuntos. Se probó prosa y un proxy sintético que elimina palabras funcionales; este último no es español comercial auténtico de 1937. [7]')
rows = [['Claves', 'Prosa: solo 615', 'Prosa: pareja', 'Proxy: solo 615', 'Proxy: pareja']]
for w1,w2 in ((8,10),(10,12),(12,15),(15,20),(20,25)):
    rows.append([f'{w1} x {w2}'] + [f"{lookup[w1,w2,c,n]['exact_plaintext_both']}/3" for c,n in [('holdout_es.txt',1),('holdout_es.txt',2),('holdout_proxy.txt',1),('holdout_proxy.txt',2)]])
table(rows, [71,110,110,110,110])
p('Éxito exige recuperar exactamente 615+160 letras. En la modalidad solo 615, el corto se usa después para evaluar transferencia con esas claves, sin haber participado en el objetivo. Tres semillas por pareja y tipo de texto: 30 comparaciones, 60 búsquedas, cuatro reinicios y 10.000 propuestas IDP por reinicio, además de las etapas K1 y refinamiento. Se suministran las longitudes verdaderas: este piloto no mide su detección.')
p('<b>Conclusión experimental:</b> la pareja ayuda en algunos controles y perjudica en otros. El algoritmo aún no tiene potencia probada para las claves largas. No se descarta ninguna de esas regiones. Las pruebas mecánicas incluyen 700 recorridos de inversas y, en una revisión independiente, 1.566 comparaciones de cifrado/descifrado y 1.485 matrices IDP frente a implementaciones distintas.')
p('Los controles negativos también recifran exactamente. El recifrado comprueba consistencia de las inversas y se exige a un candidato, pero no distingue una solución de letras sin sentido.', 'SmallCustom')
story.append(PageBreak())

h('4  Auditoría del ataque previo')
p('Lasry, Kopal y Wacker publicaron en 2014 un ataque de divide y vencerás a la doble transposición. Nuestra base es una implementación parcial inspirada en él, no una reproducción completa. El fracaso del piloto no invalida el método publicado. [6]')
p('En Idp2.cs del repositorio, el modo habitual permite reutilizar el mejor vecino y el modo opcional usa asignación óptima. El artículo describe una selección greedy uno a uno. El repositorio también limita comienzos de columnas a un entorno de la expectativa, y sus movimientos y refinamiento no reproducen todas las fases publicadas.')
p('La auditoría geométrica de 10.000 claves aleatorias por ancho muestra que recortar a +/-2 deja fuera al menos un comienzo real en el 7,29% de claves de ancho 19; 17,67% de ancho 25; y 36,82% de ancho 35, para 615 letras. Eso demuestra una omisión de alineaciones; no prueba por sí solo que se pierda la clave. La base nueva usa por defecto todo el rango factible.')
p('La relajación IDP permite offsets óptimos distintos por pareja y puede producir ciclos; no reconstruye automáticamente una clave realizable. La suma conjunta tampoco impone todos los constraints geométricos comunes. Esta libertad puede elevar puntuaciones espurias y debe considerarse al diseñar la siguiente versión.')
h('Ensayo exploratorio sobre BLUME')
p('Tras los controles se ejecutó solamente la pareja de anchos 8 x 10, convención anterior, tres semillas y el mismo presupuesto. Se registran seis salidas al comparar solo T1 y la pareja. Ninguna sostiene texto coherente. Las puntuaciones de quadgramas están en el rango de los controles barajados; no se identifica un candidato a solución.')
p('Este ensayo no es una búsqueda exhaustiva, no examina las claves largas y no excluye ni siquiera todos los casos 8 x 10. No se lanzó una búsqueda masiva de las regiones donde el algoritmo fracasa en controles equivalentes.')
h('Siguiente versión del laboratorio')
p('Reproducir fielmente las fases publicadas, documentar sus variantes para matrices irregulares y ampliar controles independientes. La calibración debe cubrir varios textos, claves y lenguas, además de comparar claves compartidas frente a distintas. El nuevo modelo necesita correspondencia comercial y telegramas con procedencia ajena al objetivo. Solo después tendrá sentido ampliar el cómputo sobre BLUME.')
story.append(PageBreak())

h('5  Lengua y cribs')
p('Se compararon cinco treebanks oficiales de Universal Dependencies, tomando 39.069 letras normalizadas de cada uno. Los perfiles son muestras modernas de géneros diferentes. La tabla expresa log-verosimilitud natural por letra; un valor menos negativo favorece el perfil únicamente bajo este modelo marginal. [8]')
rows = [['Perfil', 'T1: log p / letra', 'T2: log p / letra']]
for r in sorted(language['results'], key=lambda r:r['messages']['ct1.txt']['log_likelihood_per_letter_natural_log'], reverse=True):
    rows.append([{'es':'Español','de':'Alemán','fr':'Francés','it':'Italiano','en':'Inglés'}[r['code']]] + [f"{r['messages'][ct]['log_likelihood_per_letter_natural_log']:.4f}" for ct in ('ct1.txt','ct2.txt')])
table(rows, [171,170,170])
p('T1 favorece español en este criterio, pero su chi-cuadrado supera el de todas las 1.000 ventanas de igual longitud muestreadas en cada corpus. No encaja con estos géneros de prosa. En T2 español e italiano quedan cerca; el chi-cuadrado incluso favorece inglés frente a español. Son diagnósticos dependientes del corpus, no pruebas de idioma; las ventanas del mismo corpus no son un test independiente de significación.')
table([
    ['Crib literal', 'T1', 'T2', 'Interpretación'],
    ['PATVAG / VICTOR / CEDRIC', 'Factible', 'Factible', 'Contexto histórico; no presencia demostrada.'],
    ['OSWALD / WERNEROSWALD', 'Imposible', 'Imposible', 'No hay W en ninguno.'],
    ['WALTHERCETTO', 'Imposible', 'Imposible', 'No hay W en ninguno.'],
    ['KILOS', 'Factible', 'Imposible', 'T2 no contiene K.'],
    ['EXPORTACION', 'Factible', 'Imposible', 'T2 no contiene X.'],
    ['PESETAS / LANA', 'Factible', 'Factible', 'La explicación comercial sigue siendo hipótesis.'],
], [166,67,67,211])
p('Los filtros comprueban multiplicidades, no solo presencia. Factible es una condición necesaria bajo transposición pura A-Z; no acredita aparición. Varios términos propuestos deben cotejarse conjuntamente. Cualquier cambio W->V u otra transliteración exige fundamento documental adicional.')
p('Prioridad histórica: fijar la signatura del expediente policial de Werner a través de las notas completas de Bochsler; inspeccionar folios contiguos, respuestas y documentación de claves. La nueva pista de Victor y el expediente Oswald, Madrid orientan esa búsqueda sin sustituirla.', 'SmallCustom')
story.append(PageBreak())

h('6  Fuentes y reproducción')
sources = [
    ('1', 'Fotografías y transcripciones; revisión '+manifest['revision'][:12]+' del repositorio.', 'https://github.com/dbourdeau/cyphersolver/tree/'+manifest['revision']+'/targets/blume'),
    ('1a', 'Issue 14: correcciones y segundo telegrama, septiembre de 2026.', 'https://github.com/dbourdeau/cyphersolver/issues/14'),
    ('2', 'Archivo Federal Suizo: Oswald, Victor, 1912, Madrid; E2001E#1000/1571#787*.', 'https://www.recherche.bar.admin.ch/recherche/#/de/archiv/einheit/Vz%20%20%20%20%20%203ad2db78-3938-5400-8984-42d2b055e749'),
    ('3', 'Carta Pfyffer a Motta, 18 enero 1939. Visor oficial; Dokument_0000003, canvas 4.', 'https://viewer.recherche.bar.admin.ch/?manifest=https://www.recherche.bar.admin.ch/recherche/files/manifests/3ad2db78-393/8-5400-8984-/42d2b055e749/3ad2db78-3938-5400-8984-42d2b055e749.json'),
    ('4', 'Archivo Federal Suizo: Oswald, Madrid, 1936-1938; E2001D#1000/1551#5627*.', 'https://www.recherche.bar.admin.ch/recherche/#/de/archiv/einheit/1689905'),
    ('5', 'Bochsler, Nylon und Napalm, HIER UND JETZT, 2022. Extracto público utilizado.', 'https://www.legimi.de/e-book-nylon-und-napalm-regula-bochsler,b3465546.html'),
    ('5a', 'Ficha editorial oficial: ISBN 978-3-03919-569-5, 592 páginas.', 'https://www.hierundjetzt.ch/fr/catalogue/nylon-und-napalm_2200022/'),
    ('5b', 'Bochsler, web del libro: entrada Facebook de 8 septiembre 2023; atribución expresamente incierta.', 'https://www.nylonundnapalm.ch/medien'),
    ('6', 'Lasry, Kopal y Wacker (2014), Cryptologia 38(3), 197-214. Solving the Double Transposition Challenge with a Divide-and-Conquer Approach.', 'https://doi.org/10.1080/01611194.2014.915269'),
    ('6a', 'Copia del artículo subida por uno de los autores.', 'https://www.researchgate.net/publication/263286752_Solving_the_Double_Transposition_Challenge_with_a_Divide-and-Conquer_Approach'),
    ('6b', 'Lasry (2018), A Methodology for the Cryptanalysis of Classical Ciphers with Search Metaheuristics, capítulo 9.', 'https://www.uni-kassel.de/upress/online/OpenAccess/978-3-7376-0458-1.OpenAccess.pdf'),
    ('7', 'Cervantes, Don Quijote de la Mancha. Fuente del modelo y de controles con separación 80/20.', 'https://www.gutenberg.org/ebooks/2000'),
    ('8', 'Universal Dependencies: Spanish AnCora, German GSD, French GSD, Italian ISDT y English EWT. URLs y hashes individuales en language_comparison.json.', 'https://universaldependencies.org/'),
]
for ident,label,url in sources:
    p('['+ident+'] '+link(label, url), 'SmallCustom')
h('Paquete de trabajo')
p('El archivo ZIP incluye los textos y fotos, manifiesto de procedencia, lectura por grupo, inventario de cribs, resultados lingüísticos, código C++ y Python, modelo, controles y candidatos exploratorios. LEEME.txt explica las rutas y comandos. Los textos emitidos como plaintexts en logs de búsqueda son <b>lecturas candidatas</b>, salvo controles comparados exactamente con su claro conocido.')
p('La reproducción de semillas depende también del compilador y de la biblioteca estándar usada por std::shuffle. Se registran el entorno y las claves resultantes. Los datos lingüísticos originales conservan sus licencias y referencias; las versiones exactas están identificadas por hashes.', 'SmallCustom')

def footer(canvas, doc):
    w,hh=A4
    canvas.setStrokeColor(RUST); canvas.setLineWidth(1.1)
    canvas.line(18*mm, hh-15*mm, w-18*mm, hh-15*mm)
    canvas.setFont('Helvetica',7.5); canvas.setFillColor(GREY)
    canvas.drawString(18*mm, 12*mm, 'SENTINEL | BLUME SALAMANCA | 1 octubre 2026 | Sin solución verificada')
    canvas.drawRightString(w-18*mm, 12*mm, str(doc.page))

pdf = OUT / 'Sentinel_BLUME_dossier.pdf'
doc = SimpleDocTemplate(str(pdf), pagesize=A4, rightMargin=18*mm,leftMargin=18*mm,
                        topMargin=22*mm,bottomMargin=20*mm,
                        title='BLUME SALAMANCA - Dossier de investigación para Sentinel',
                        author='Proyecto Sentinel')
doc.build(story,onFirstPage=footer,onLaterPages=footer)
print(pdf)

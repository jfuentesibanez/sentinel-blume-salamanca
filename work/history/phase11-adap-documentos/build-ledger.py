from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[3]
P = Path(__file__).resolve().parent
manifest = json.loads((P / 'iiif-manifest.json').read_text())
canvases = manifest['sequences'][0]['canvases']

def save(name, value):
    (P / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')

def spaced(s):
    s = re.sub(r'(?<=[A-Za-zÀ-ÿ])(?=[0-9])', ' ', s)
    return re.sub(r'(?<=[0-9])(?=[A-Za-zÀ-ÿ])', ' ', s)

docs = [
    dict(number=163, date='1936-12-23', pages=[153], scans=[253], reference='3176/682874–875', sender='Jefe del departamento de Política Comercial; firmado Ritter', recipient='Encargado de negocios en Salamanca', registration='Telegramm Nr.155; W II W.E.4914; Ref. V.L.R. Sabath', fact='Propone prorrogar tres meses el acuerdo de mercancías de 9 marzo1936, y negociar uno nuevo antes del 1 abril1937. Distingue el acuerdo de pagos de 21 diciembre1934, vigente sin término fijo.', limit='Propuesta diplomática; no prueba un negocio de los Oswald.'),
    dict(number=180, date='1937-01-01', pages=[170], scans=[270], reference='3176/682876; anexo3176/682877', sender='Representante alemán en Salamanca; I.V. Schwendemann', recipient='Auswärtiges Amt', registration='Sa.10–322; referencia a telegrama629 de31diciembre1936', fact='Remite protocolo de prórroga y solicita negociar en Salamanca o Burgos por dificultades para enviar técnicos españoles a Berlín.', attachment='Protocolo firmado Faupel y F.Serrat en Salamanca31diciembre1936: prórroga hasta31marzo1937 y negociación antes1abril.', limit='Se leyó el anexo impreso; el telegrama629 (3176/682878) se menciona como no impreso y no se leyó.'),
    dict(number=181, date='1937-01-02', pages=[171], scans=[271], reference='3253/E000652–655', sender='Representante alemán en Salamanca; I.V. Schwendemann', recipient='Auswärtiges Amt', registration='Sa.3–324; recibido6enero; Pol.III71', fact='Schwendemann registra lo que le dijo Sangroniz: el agregado comercial británico Pack visitaba frecuentemente Burgos y Salamanca para negociaciones económicas.', limit='Testimonio transmitido por Sangroniz, no observación directa de Schwendemann de todas las visitas; Pack no se identifica con Blume.'),
    dict(number=187, date='1937-01-07', pages=[175,176], scans=[275,276], reference='643/254221–222', sender='Faupel, encargado de negocios en Salamanca', recipient='Auswärtiges Amt', registration='Sa.3–360; Pol.III160; Lagebericht', fact='Faupel propone aprovechar la reacción al material alemán anunciado para cerrar acuerdos políticos y económicos. Para los acuerdos económicos señala las estrechas relaciones personales del jefe de Hisma, Bernhardt, con Franco y Nicolas Franco.', limit='Documento contemporáneo un día anterior a los BLUME; no menciona a Blume ni a los Oswald y no demuestra relación con los telegramas.'),
    dict(number=196, date='1937-01-12', pages=[186], scans=[286], reference='1534/374403–404', sender='Faupel, encargado de negocios en Salamanca', recipient='Auswärtiges Amt', registration='Telegramm Nr.21; enviado19:20; llegada13enero06:00', fact='Pide acelerar una delegación para cerrar cuestiones económicas y de indemnización, antes de que el aumento de la intervención italiana reduzca la influencia alemana.', attachment='Nota de la Cancillería del Reich fechada15enero1937, L[ammers], reproducida en nota editorial: orden de atender cuanto antes la petición final y comunicarla al ministro, Wienstein y Röhrcke.', limit='La nota adjunta sí está reproducida; no se leyó el expediente original ni el telegrama629 referido.'),
    dict(number=205, date='1937-01-15', pages=[192], scans=[292], reference='2938/569697–698', sender='Weizsäcker', recipient='Encargado de negocios en Salamanca', registration='Telegramm Nr.25; Berlin22:15; W II W.E.341 II; Ref. V.L.R. Dumont', fact='Solicita aclarar noticias del Wehrwirtschaftsstab y prensa británica sobre distribución de la producción de Rio Tinto y compensaciones a empresas británicas.', limit='La distribución40/60 y otros datos son noticias cuya confirmación se pide; no deben presentarse como un contrato verificado. La nota refiere telegrama Woermann21enero2938/569695–696, no reproducido completo ni leído.'),
    dict(number=206, date='1937-01-16', pages=[193], scans=[293], reference='3176/682895–896', sender='Ritter, jefe del departamento de Política Comercial', recipient='Encargado de negocios en Salamanca', registration='Telegramm Nr.26; W II W.E.355 I', fact='Anuncia negociación económica inmediata, sin acuerdo político previsto. La delegación sería encabezada por Wucher, con representantes ministeriales y Rowak, y estrecha participación de Bernhardt; pregunta por sede Salamanca o Burgos y prevé empezar25enero.', limit='Composición y calendario previstos, no acta de reuniones realizadas. El cuerpo nombra von Jackwitz o Bethge; la nota editorial corrige Bethge a Friedrich Bethke. No resolver por similitud Jackwitz/Jagwitz.'),
    dict(number=207, date='1937-01-18', pages=[193,194], scans=[293,294], reference='47/31868–869', sender='Faupel, encargado de negocios en Salamanca', recipient='Auswärtiges Amt', registration='Geheim; Sa.3–459; recibido22enero; Pol.I338g', fact='En su informe de situación, Faupel contrasta lo que Mancini dijo sobre gastos italianos y poca compensación con los retornos que Alemania obtenía por Hisma.', limit='La comparación está condicionada a la veracidad de los datos comunicados por Mancini. No es una cuenta de resultados verificada. Anexo47/31870–871 no impreso ni leído.'),
    dict(number=208, date='1937-01-20', pages=[194], scans=[294], reference='2938/569699', sender='Faupel, encargado de negocios en Salamanca', recipient='Auswärtiges Amt', registration='Telegramm Nr.34; enviado20:00; llegada21enero04:30; W II W.E.519a', fact='En respuesta al telegrama25, informa que la propuesta británica fue rechazada y que Hisma tenía una promesa escrita del Gobierno español de hasta60% de la producción de Rio Tinto. El texto indica un tipo de cambio de42pesetas por una libra esterlina (moneda, no unidad de peso). Espera contrato final próximo.', limit='Se leyó el informe de Faupel; no la promesa escrita ni el contrato final. No tratar expectativa de firma como contrato realizado.'),
    dict(number=213, date='1937-01-26', pages=[198,199], scans=[298,299], reference='47/31895–899', sender='Von Dörnberg, Legationssekretär de la Politische Abteilung', recipient='Nota presentada a Weizsäcker', registration='Berlin; Geheim; e.o.Pol.I731g', fact='Dörnberg registra reunión con Canaris y Augusto Miranda. Según Miranda, Bernhardt reclamaba que las divisas disponibles se pusieran a disposición suya/Hisma; Franco, Nicolas Franco y Faupel aparecen en el relato. Miranda defendía sus compras de armas fuera de Alemania y citaba tratos con Veltjens.', counterevidence='La nota reproduce la reserva de Weizsäcker27enero y Körner, y una nota de R[itter]28enero con la versión de Bernhardt: quería que las divisas pagadas por suministros extranjeros se destinaran a pagar los alemanes. Ritter aprobaba esta petición y sospechaba rivalidad comercial de Miranda.', limit='Acusación transmitida y versión contraria, no monopolio de divisas demostrado. El Erlass firmado Dumont47/31900–903 se resume editorialmente; no se leyó completo.'),
]
for d in docs:
    d['reading'] = 'Texto completo del documento numerado y notas de sus páginas, en imagen de la edición1951; no original archivístico.'
    d['image_urls'] = [canvases[n-1]['images'][0]['resource']['@id'] for n in d['scans']]
    d['reference_type'] = 'Referencia de película/fotograma impresa en ADAP; equivalencia a signatura actual PAAA no verificada.'
    for key in ('fact','attachment','counterevidence','limit','reading'):
        if key in d:
            d[key] = spaced(d[key])

nav = {
    5: ('sin numerar', 'Portada: ADAP serieD volumenIII, Alemania y Guerra Civil española1936–1939.'),
    253: ('153', 'Documento163 completo; final vecino162 visible sin seguimiento.'),
    254: ('154', 'Navegación sobrante: inicio164 de24diciembre; no se leyó completo ni se siguió155.'),
    270: ('170', 'Documento180 completo y protocolo anexo31diciembre.'),
    271: ('171', 'Documento181 completo, añadido por contacto comercial Pack; inicio182 visible sin seguimiento.'),
    275: ('175', 'Inicio187 leído; vecino186 visible sin selección temática ni seguimiento.'),
    276: ('176', 'Final187 leído, incluido párrafo relaciones Bernhardt/Franco/Nicolas.'),
    277: ('177', 'Navegación sobrante: inicio188 de7enero, sin lectura completa ni seguimiento.'),
    286: ('186', 'Documento196 completo y nota Lammers15enero; cola195 visible sin lectura completa.'),
    287: ('187', 'Navegación sobrante: vecinos197/198 visibles, no seleccionados ni seguidos.'),
    292: ('192', 'Documento205 completo; cola204 visible sin lectura completa.'),
    293: ('193', 'Documento206 completo e inicio207.'),
    294: ('194', 'Final207 y documento208 completo.'),
    295: ('195', 'Navegación sobrante: nota Ciano y vecinos209/210 visibles; no seleccionados ni seguidos.'),
    298: ('198', 'Inicio213: registro Dörnberg de declaraciones Miranda ante Canaris.'),
    299: ('199', 'Final213, reservas27enero y nota Ritter28enero; inicio214 visible sin seguimiento.'),
    851: ('751', 'Navegación para localizar apéndices; vecinos769–771 marzo1939, fuera de ventana, sin seguimiento.'),
    871: ('771', 'Navegación: documento788 de2mayo1939 menciona Bernhardt/Hisma; fuera de ventana, sin seguimiento.'),
    881: ('781', 'Navegación: continuación de un documento1939, sin encabezado en esta página; no se le asigna número/fecha ni se usa para enero1937.'),
    901: ('801', 'Navegación: plan de personal WII, Sabath España y Wingen Suiza. Año no visible: no se le atribuye vigencia1937.'),
    910: ('810', 'Personenverzeichnis: BLOMBERG, BLUM Léon, BOHLE; sin entrada Blume en ese tramo. Entrada Bernhardt identificada como nota de los editores.'),
    911: ('811', 'Continuación índiceCABALLERO–DIRKSEN; confirma límite del tramoB/C, sin entrada Blume.'),
    913: ('813', 'Cotejo visual del único resultado OCR Oswald: nombre de pila de Hoyningen-Huene, enviado alemán en Lisboa según índice; homónimo descartado.'),
    914: ('814', 'Personenverzeichnis LITWINOW–PLESSEN; tramo NEWTON–PERTH sin entrada de apellido Oswald.'),
    915: ('815', 'Navegación índice PLYMOUTH–SCHWENDEMANN.'),
    916: ('816', 'Navegación índice SELZAM–WUCHER.'),
}
romans = ['XXX','XXXI','XXXII','XXXIII','XXXIV','XXXV','XXXVI','XXXVII','XXXVIII']
doc_ranges = ['133–140','141–150','151–159','160–169','170–179','180–189','190–199','200–208','209–219']
for n, r, dr in zip(range(30,39),romans,doc_ranges):
    nav[n] = (r, f'Índice cronológico, resúmenes y referencias de documentos{dr}; selección temática del cuerpo, sin lectura íntegra de todos esos documentos.')
pages=[]
for f in sorted(P.glob('scan-*.jpg')):
    n=int(f.stem.split('-')[1])
    printed,scope=nav[n]
    c=canvases[n-1]
    pages.append(dict(scan=n,printed_page=printed,local_file=f.name,canvas_id=c['@id'],image_url=c['images'][0]['resource']['@id'],visual_read=True,scope=spaced(scope)))

save('ledger.json', {
    'phase':11,'date':'2026-10-02','source':'https://digitale-sammlungen.de/de/view/bsb00045915',
    'permalink':'https://mdz-nbn-resolving.de/urn:nbn:de:bvb:12-bsb00045915-4',
    'manifest':'https://api.digitale-sammlungen.de/iiif/presentation/v2/bsb00045915/manifest',
    'metadata_source':'iiif-manifest.json',
    'edition':{'publication_year':1951,'institution':'Bayerische Staatsbibliothek','shelfmark':'4 Z 50.281,D-3','catalogue_id':'BV001113577','volume_scans':len(canvases),'scope':'Selección documental editada, con notas y apéndices. Se leen facsímiles de la edición impresa, no los expedientes originales completos.'},
    'access':{'method':'API pública IIIF documentada en https://digitale-sammlungen.de/de/schnittstellen; imágenes limitadas derivadas del manifiesto. Lectura visual con view_image original.','viewer_queries_here':0,'root_viewer_queries':2,'root_query_ledger':'work/history/phase11-adap-buscador/ledger.json','queries':['Oswald','Hisma'],'query_limits':'Hasta8 consultas; root leyó100 fragmentos OCR Hisma de254 anunciados. Aquí no se descargó OCR ni se repitió búsqueda Blume.','local_browser':'No disponible en esta fase tras la única comprobación indicada por bootstrap. No es un negativo documental. No se crearon pestañas.','shell_access':'GET públicos autorizados; una revisión caducada del primer acceso se recuperó con el único reintento permitido. Sin eludir rechazo ni acceso privado.'},
    'budgets':{'max_queries':8,'new_queries_total':2,'max_visual_scans':50,'visual_scans_here':len(pages),'max_chronological_documents':20,'fully_read_numbered_documents':len(docs),'additional_primary_pieces_or_comments':4,'primary_units_conservative_total':len(docs)+4,'additional_pieces':['Protocolo31diciembre1936 adjunto180','NotaLammers15enero1937 reproducida bajo196','ComentarioWeizsäcker27enero1937 bajo213','NotaRitter28enero1937 bajo213'],'definition':'El límite documental cuenta lectura íntegra del cuerpo seleccionado y piezas primarias adjuntas. Los resúmenes del índice y vecinos sólo visibles no se presentan como documentos íntegros leídos.'},
    'pages':pages,'documents':docs,
    'bounded_negatives':[
        'El índice de personas no tiene entrada Blume en el tramoB leído visualmente; sí BLUM Léon. No prueba que Blume no existiera ni que no aparezca en originales fuera de la edición.',
        'El índice no tiene entrada de apellido Oswald en el tramoN–P leído visualmente. La única coincidencia OCR ejecutada por root se cotejó: Oswald es nombre de pila de Hoyningen-Huene.',
        'Los10 documentos completos seleccionados no establecen relación de Blume u Oswald con los nombres comerciales registrados. No se afirma ausencia en todos los81 documentos de diciembre1936–enero1937 ni en archivos originales.'
    ],
    'outside_scope':{
        'date_window':'1936-12-01–1937-01-31; anexo31diciembre1936 incluido.',
        'edition_documents_in_window':'Índice:136–216, 81documentos. Se seleccionaron163,180,181,187,196,205,206,207,208,213; los demás cuerpos no se estudiaron completos.',
        'unread_originals':'Contratos Hisma/RioTinto, promesa escrita referida por208, remisiones y anexos declarados no impresos, expediente completo de cada película/fotograma, y documentos excluidos por los editores.',
        'outside_date_navigation':'Escaneos851/871/881 contienen páginas1939; sólo navegación, sin usarlos como pruebas de enero1937. Resultados OCR Hisma desde307 no se siguieron aquí.'
    },
    'quotes_short_total_words':12,
    'short_extracts':[{'doc':187,'printed_page':176,'scan':276,'text':'die sehr engen persönlichen Beziehungen','purpose':'Traducción orientativa: las relaciones personales muy estrechas; atribución de Faupel.'},{'doc':213,'printed_page':198,'scan':298,'text':'alle ihm zur Verfügung stehenden Devisen','purpose':'Traducción orientativa: todas las divisas a su disposición; reclamación atribuida por Miranda, con versión contraria en nota.'}],
    'source_instructions_treated_as_data':True,'contacts':0,'accounts':0,'orders':0,'payments':0,'published':False,'tabs_created':0,'user_tabs_modified':0,
})

baseline=json.loads((P/'protected-baseline.json').read_text())
changed=[];missing=[];same=0
for filename, expected in baseline.items():
    f=ROOT/filename
    if not f.exists():missing.append(filename)
    elif hashlib.sha256(f.read_bytes()).hexdigest()!=expected:changed.append(filename)
    else:same+=1
save('protected-verification.json',{'baseline_count':len(baseline),'unchanged':same,'changed':changed,'missing':missing,'previous_history_preserved':not changed and not missing})
print(json.dumps({'scans':len(pages),'numbered_documents':len(docs),'primary_units_with_attachments':len(docs)+4,'protected':len(baseline),'unchanged':same,'changed':changed,'missing':missing},ensure_ascii=False))

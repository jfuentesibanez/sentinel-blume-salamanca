BLUME SALAMANCA — laboratorio de doble transposición, 1 octubre 2026

Estado: NO se ha obtenido un descifrado de BLUME. Se ejecutó un piloto exploratorio
8 × 10 con tres semillas, 4 reinicios y 10.000 propuestas por reinicio, separado
de los controles. Se construyó y calibró una base reproducible
con controles de exactamente 615 + 160 letras y claves compartidas.

Archivos que deben acompañar al código:
  double_search.cpp       implementación C++17 portátil, sin dependencias
  prepare_model.py        creación de modelo y controles lingüísticos
  run_controls.py        piloto acotado, 3 semillas por banda y tipo de texto
  model_es.bin           bigramas/trigramas/quadgramas, float32 log10
  model_provenance.json   URL, hash, normalización y división entrenamiento/test
  holdout_es.txt          cola del texto no usada en entrenamiento
  holdout_proxy.txt       proxy sintético: se eliminan palabras funcionales
  controls.jsonl         resultados completos, claves y textos de cada control
  controls_summary.json  recuperación exacta y tiempos agregados
  control_manifest.json  comandos, parámetros, finalización y presupuesto
  tolerance_audit.json   evaluación de recorte de alineaciones de upstream
  negative_controls.jsonl y negative_manifest.json: controles de ruido
  blume_8x10_pilot.jsonl: candidatos reales completos del piloto exploratorio
  blume_shuffled_8x10_pilot.jsonl: baseline con letras de cada telegrama barajadas
  real_pilot_manifest.json, blume_shuffled_manifest.json: comandos y hashes

Compilar y comprobar inversas, desde esta carpeta:
  c++ -std=c++17 -O3 -o double_search double_search.cpp
  ./double_search check

Se comprueban 700 casos de cifrar/descifrar, incluyendo longitudes incompletas
y las cuatro combinaciones de sentido. La operación individual escribe filas
y lee columnas permutadas (F); G es su inversa. Las convenciones son:
  0=F,F  1=G,G  2=G,F  3=F,G.
El tratamiento de columnas largas/cortas depende de cada longitud por separado.
No se añade padding. Los índices de las claves empiezan en cero y representan
columnas originales en orden de lectura del cifrado; no son palabras clave.

Reproducir piloto de 615 + 160, mismo presupuesto por modalidad:
  python3 run_controls.py --budget 390 --steps 10000 --restarts 4
Control individual (8×10, semilla 20261001):
  ./double_search control model_es.bin holdout_es.txt 8 10 20261001 4 10000 0 -1 1
El comando ejecuta dos búsquedas: puntuando 615 solas y puntuando 615 + 160 juntas.
Las longitudes de claves se proporcionan correctamente al solver: el piloto
no incluye todavía coste/ambigüedad de detectar esas longitudes.

Generación de la pareja y búsqueda usan flujos independientes. La semilla
de búsqueda es uint64(plant_seed) XOR 0x9e3779b97f4a7c15 y se registra.
El solver recibe solo los textos cifrados, longitudes y el modelo; nunca las
claves verdaderas ni los textos claros del control. Estos se usan al final
para contar letras y claves recuperadas. El corpus de formación se separa por
posición (primer 80% del cuerpo de Don Quijote, Gutenberg 2000) de la cola 20%
reservada a controles. Las dos partes de cada control proceden de segmentos
contiguos disjuntos de esa cola; no constituyen una muestra de telegramas reales.

Método y limitaciones:
  • IDP usa todos los comienzos de columna factibles por geometría. Parámetro
    tolerancia=-1 indica rango completo; ≥0 recorta alrededor de la expectativa.
  • En la pareja se suman matrices de adyacencia del mismo índice de columnas
    en los dos textos; una asignación común comparte el orden implícito de K1.
    Es una relajación: los comienzos óptimos de cada par no están obligados a
    ser compatibles globalmente ni entre ambos mensajes. No es una prueba de K1.
  • Selección greedy de vecinos uno a uno; puede contener ciclos. Un diagonal
    forzado al final recibe floor −7 por fila, decisión heurística explícita.
  • Búsqueda K2: annealing con swaps, slides, swaps de bloques de igual longitud,
    reversión y recombinación tripartita. Conserva3 candidatos de4 reinicios.
  • K1: annealing de claves compartidas sobre quadgramas y refinamiento alternado
    con vecindario de slides completo bajo presupuesto. No concatena mensajes:
    las ventanas de ngramas nunca cruzan la frontera 615/160.
  • Esta base NO reproduce íntegramente Lasry/Kopal/Wacker (2014). Falta replicar
    exactamente su selección de iniciales, vecindarios completos, fases y scorer
    adaptativo para K1. El fracaso aquí no invalida el método publicado.
  • Este piloto solamente calibra F,F en español literario y un proxy. Las
    pruebas de inversas en otros sentidos no calibran recuperación en ellos.
  • Re-cifrado exacto valida coherencia mecánica. Cualquier permutación propuesta
    produce una lectura que vuelve a cifrar exactamente; no acredita solución.
  • La métrica de éxito es texto completo775/775 y claves exactas, no un buen
    score ni palabras aisladas. Se registran todas las lecturas para auditoría.

Piloto:3 semillas 20261001/20261002/20261003 por banda y corpus,4 reinicios,
10.000 propuestas IDP por reinicio más etapas K1 y refinamiento;30 comparaciones,
60 búsquedas, todas finalizadas. Véanse JSON para tiempos y métricas precisas.

Recuperación exacta775/775 (solo 615 / pareja 615 + 160):
                prosa             proxy sin palabras funcionales
  8×10          1/3 / 3/3         2/3 / 1/3
  10×12         1/3 / 1/3         0/3 / 1/3
  12×15         0/3 / 0/3         0/3 / 0/3
  15×20         0/3 / 0/3         0/3 / 0/3
  20×25         0/3 / 0/3         0/3 / 0/3

Lectura: la pareja ayudó en algunos controles y perjudicó en otros. Tres
semillas no estiman una tasa de éxito poblacional; no autorizan exclusiones.
Claves 20–25 permanecen abiertas. El siguiente paso es mejorar y calibrar
el ataque, ampliar controles realistas y otros idiomas, e incorporar cribs
solo cuando tengan una procedencia histórica independiente.

El piloto real 8 × 10 usa tres semillas y conserva todos los candidatos. Sus
lecturas no forman un texto coherente y sus puntuaciones permanecen próximas
al ruido barajado. No es una exclusión: los controles del mismo método también
fallan en algunos casos, especialmente en el proxy. Se detuvo después del
piloto; no se hizo una búsqueda de claves largas sin calibración.

Para ampliar la investigación real tras calibración suficiente, la interfaz es:
  ./double_search solve model_es.bin CT1.txt CT2.txt W1 W2 SEED RESTARTS STEPS 0 -1 1

Fuentes técnicas primarias:
  Lasry, Kopal y Wacker (2014), Cryptologia 38(3), 197–214.
  https://doi.org/10.1080/01611194.2014.915269
  Versión subida por autor (contenido leído):
  https://www.researchgate.net/publication/263286752_Solving_the_Double_Transposition_Challenge_with_a_Divide-and-Conquer_Approach
  Lasry (2018), A Methodology for the Cryptanalysis of Classical Ciphers with Search Metaheuristics,
  capítulo 9, ISBN 978-3-7376-0458-1 (copia pública conservada internamente):
  https://www.uni-kassel.de/upress/online/OpenAccess/978-3-7376-0458-1.OpenAccess.pdf

Fuentes del objetivo (no afirmaciones independientes sobre contenido histórico):
  https://github.com/dbourdeau/cyphersolver/tree/main/targets/blume
  https://github.com/dbourdeau/cyphersolver/issues/14

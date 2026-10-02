Fase 3 BLUME/Sentinel — paquete reproducible de controles sintéticos

Archivos principales
ict_search.h   Mejora K1 ICT y búsqueda K2; incluye la fase1 en solo lectura.
phase3.cpp     Harness oracle/full/check final; final_ngram=3 en ambos modos.
phase3_full_validated.cpp  Snapshot exacto de la fuente de las tandas full;
              misma rama full que phase3.cpp, oracle antiguo q4 y sin campoNG.
run_controls.py  Tandas acotadas y manifiestos de comandos/hashes.
summary.json  Resultados finales agregados; no incluye desarrollo.
METHOD.txt    Fórmulas, fuentes primarias, decisiones y límites.
*_manifest.json  Comandos exactos y SHA256 de código/datos/logs de cada tanda.

Dependencias concretas
- Compilador C++17 con la biblioteca estándar (GCC/Clang).
- Python 3 con biblioteca estándar para ejecutar/agregar tandas.
- work/crypto/double_search.cpp, leído por include relativo.
- work/crypto/model_es.bin; modelo float32 IEEE little-endian a–z, n2/n3/n4.
- work/crypto/holdout_es.txt y holdout_proxy.txt.
- work/crypto/model_provenance.json para procedencia.
No requiere OpenAI, otra API, claves externas ni paquetes Python de terceros.
La codificación binaria del modelo presupone CPU little-endian/floatIEEE.
std::shuffle puede variar entre bibliotecas estándar: seeds solas no garantizan
las mismas permutaciones entre plataformas. Los JSONL registran claves
plantadas y recuperadas para comprobar equivalencia. El binario Mac no es
necesario en el paquete portable; recompilar desde source en destino.

Desde la raíz del workspace:
c++ -std=c++17 -O3 -DNDEBUG work/phase3_crypto/phase3.cpp -o work/phase3_crypto/phase3
work/phase3_crypto/phase3 check work/crypto/model_es.bin
work/phase3_crypto/phase3 oracle work/crypto/model_es.bin work/crypto/holdout_es.txt 20 25 20261101 8 3
work/phase3_crypto/phase3 full work/crypto/model_es.bin work/crypto/holdout_es.txt 20 25 20261011 8 3 5

Para reejecutar una tanda existente, ejecutar los commands de su manifiesto
y redirigir las salidas a un archivo nuevo; o copiar el workspace sin los
logs de esa tanda. run_controls.py se niega a sobrescribir resultados y fija
su salida junto al script. Usar otra seed es un experimento nuevo.
Ejemplo de tanda nueva:
python3 work/phase3_crypto/run_controls.py oracle 20261201 25 3 prose
python3 work/phase3_crypto/run_controls.py full 20261201 3 3 prose negative

La opción check valida 60 casos de representación/alineación y 6780 movimientos
de permutación. Esas pruebas prueban geometría, no descifrado histórico.
oracle revela K2 solo en un control: no equivale a resolver las dos claves.
Los anchos known-width se suministran al solver; no se estima su longitud.
Solo las bandas 12x15 y 20x25 fueron calibradas en esta fase, convenciónF,F.
La fuente de 2018/2014 inspiró una implementación parcial: ver desviaciones
en METHOD.txt. No se ejecutó un ataque BLUME durante esta fase.

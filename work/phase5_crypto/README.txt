BLUME / SENTINEL — FASE 5, 2026-10-01

Resultado: tres mecanismos de escape no mejoran la mejor K2 en un caso
sintético previamente observado como fallido. Esto es un diagnóstico
condicionado a una clave incorrecta, no una tasa de recuperación ni una
prueba contra una región de claves. No se ejecuta BLUME.

Datos y fuentes
Se conserva el modelo español de Don Quijote, el holdout proxy, la IDP y
source_moves.h auditados en fases anteriores. No se mezclan los modelos
alemanes/francés nuevos del directorio phase5_language.
La discusión metodológica procede de George Lasry2018, §§2.3.3 y4.3.2,
pp.19 y53–54: reinicios y pasos no mejorantes pueden ayudar a escapar, pero
pueden volver al mismo óptimo; ILS alterna búsqueda local y perturbaciones.
Lasry distingue ILS de su esquema anidado y plantea investigar ILS para
criptografía clásica. Esto no es un ataque publicado o validado a BLUME.
source_ledger.json registra fuentes, hashes, elecciones y límites.

Caso condicionado
Proxy español, longitudes615+160, anchos20x25, seed20261201 y ambos mensajes.
El inicio es la K2 incorrecta del diagnóstico phase4 con15s, donde se habían
completado los cinco climbs. known_wrong_k2.txt reproduce esa clave; jamás
contiene la clave correcta proporcionada al solver. La verdad sólo aparece
en plant() y en las métricas externas.

Se comparan cuatro políticas con un máximo global de150000 evaluaciones IDP
y15s como segundo límite. Las evaluaciones incluyen el score inicial,
todos los vecinos HC y el score después de cada perturbación. Aplicar swaps
sin puntuar no realiza evaluaciones IDP. La suma de eventos coincide con
el contador global. Los scores de verdad/verificación externos se identifican
en los manifiestos y no forman parte del solver o del presupuesto de búsqueda.

source: recorre todo el vecindario y termina al confirmar el óptimo local.
restart: tras comprobar el óptimo, genera una clave aleatoria y hace HC,
repitiendo hasta el límite; conserva el mejor resultado global.
kick: cambia2,3,4 pares disjuntos de posiciones (ciclo fijo) en el mejor
global, hace HC y conserva sólo las mejoras globales. No usa temperatura.
walk: perturba el último estado local con el mismo ciclo, incluso si empeoró;
mantiene por separado la mejor clave encontrada durante todo el recorrido.
Cada HC usa los slides circulares, swaps y ciclos de tres partes del source
auditado, con orden aleatorio de barrido y aceptación de mejora estricta.

Resultados
             IDP mejor       evaluaciones      segundos  terminación
source       -2.47530343674   16650               1.01     óptimo local
restart      -2.47530343674   150000              9.15     máximo evaluaciones
kick         -2.47530343674   150000              9.41     máximo evaluaciones
walk         -2.47530343674   150000              8.97     máximo evaluaciones

Las cuatro devuelven exactamente la misma K2 incorrecta. Los escapes sí
visitan otros óptimos, pero ninguno mejora el mejor global. La IDP de la
clave correcta es aproximadamente-2.195668215 y sólo se calcula después,
para diagnosticar; no se usa como umbral de búsqueda.
El tiempo es un recurso medido: restart/kick/walk consumen exactamente el
mismo número de evaluaciones y terminan antes de15s. El source puro termina
antes, porque no dispone de una política de escape.

Con este resultado no se inicia una calibración nueva o un ataque histórico.
No se repiten más semillas de este mismo caso buscando un resultado favorable.
Las configuraciones ensayadas no quedan refutadas universalmente: tampoco
permiten concluir idioma, longitud de claves o contenido de BLUME.

Verificación
check.cpp comprueba6900 perturbaciones: conservan permutación y cambian
exactamente2k posiciones disjuntas. También comprueba7 escenarios de presupuesto
con un evaluador independiente, límites de llamadas y causas de terminación.
verification.json verifica eventos, caps, conservación del mejor y hashes de
dependencias. Las fases anteriores y sus paquetes permanecen sin modificaciones.

Reproducción desde la raíz del proyecto
c++ -O3 -std=c++17 work/phase5_crypto/check.cpp -o work/phase5_crypto/check
work/phase5_crypto/check
c++ -O3 -std=c++17 work/phase5_crypto/diagnostic.cpp -o work/phase5_crypto/diagnostic
work/phase5_crypto/diagnostic work/crypto/model_es.bin work/crypto/holdout_proxy.txt 20 25 20261201 2 15 150000 work/phase5_crypto/known_wrong_k2.txt kick
c++ -O3 -std=c++17 work/phase5_crypto/walk_diagnostic.cpp -o work/phase5_crypto/walk_diagnostic
work/phase5_crypto/walk_diagnostic work/crypto/model_es.bin work/crypto/holdout_proxy.txt 20 25 20261201 2 15 150000 work/phase5_crypto/known_wrong_k2.txt
Sustituir kick por source o restart en el primer diagnóstico según la política.
Los binarios guardados corresponden al Mac actual; recompilar en otro host.
Los manifiestos conservan las órdenes completas y hashes exactos usados.

Licencia
Se importa el port de movimientos de CrypTool2 de phase4, sin editarlo,
con copyright CrypTool2 Team y Apache2.0; su licencia sigue en phase4/source/LICENSE.
Las políticas ILS experimentales y sus reservas están identificadas aparte.

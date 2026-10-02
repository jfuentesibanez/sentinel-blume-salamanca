#!/usr/bin/env python3
"""Build a separate source supplement, preserving the delivered packages."""
import collections
import hashlib
import json
import pathlib
import shutil
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PHASE = ROOT / 'work/phase3_crypto'
DEST = ROOT / 'outputs/Sentinel_BLUME_avance_2026-10-01'
ARCHIVE = DEST.with_suffix('.zip')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def loadrows(filename):
    return [json.loads(line) for line in (PHASE / filename).read_text().splitlines()]

def copy(rel):
    source = ROOT / rel
    target = DEST / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)

def main():
    if DEST.exists() or ARCHIVE.exists():
        raise SystemExit('Refusing to replace an existing supplement.')
    preserved = [ROOT / 'outputs/Sentinel_BLUME_dossier.pdf',
                 ROOT / 'outputs/Sentinel_BLUME_codigo_y_evidencias.zip',
                 ROOT / 'outputs/Sentinel_BLUME_originales_BAR.zip',
                 ROOT / 'work/crypto/double_search.cpp']
    before = {str(p.relative_to(ROOT)): sha(p) for p in preserved}
    assert before['work/crypto/double_search.cpp'] == '445afbaf9f85c17c0661515634ee16a58dced5da80e15e0b54ea8868a093fefe'
    assert before['outputs/Sentinel_BLUME_originales_BAR.zip'] == '21290e9ed369897a14d516d5f89b1b8ac0ef1ae0a973ddb8c60b2988498d68ae'
    summary = json.loads((PHASE / 'summary.json').read_text())
    for name, digest in summary['code_sha256'].items():
        assert sha(PHASE / name) == digest, f'Summary source hash mismatch: {name}'
    for rel, digest in summary['dependency_sha256'].items():
        assert sha(ROOT / rel) == digest, f'Summary dependency hash mismatch: {rel}'

    oraclefiles = ['oracle_prose_20261101_25.jsonl', 'oracle_proxy_20261101_25.jsonl']
    fullfiles = ['full_prose_20261011_5.jsonl', 'full_proxy_20261011_3.jsonl']
    oracle = sum((loadrows(f) for f in oraclefiles), [])
    full = sum((loadrows(f) for f in fullfiles), [])
    oj = [r for r in oracle if r['messages_scored'] == 2]
    os = [r for r in oracle if r['messages_scored'] == 1]
    fj = [r for r in full if r['messages_scored'] == 2]
    fs = [r for r in full if r['messages_scored'] == 1]
    assert len(oj) == len(os) == 100 and len(fj) == len(fs) == 16
    assert all(r['oracle_k2_disclosed'] and r['final_ngram'] == 3 for r in oracle)
    assert all(not r['oracle_k2_disclosed'] for r in full)
    assert sum(r['exact_both_plaintexts'] for r in oj) == 100
    assert sum(r['exact_both_plaintexts'] for r in os) == 96
    assert sum(r['exact_both_plaintexts'] for r in fj) == 0
    assert sum(r['exact_both_plaintexts'] for r in fs) == 1
    assert all(r['reencryption_consistency'] and not r['budget_expired'] for r in oracle + full)
    expected_totals = {('oracle', 2): (100, 100), ('oracle', 1): (100, 96),
                       ('full', 2): (16, 0), ('full', 1): (16, 1)}
    for total in summary['totals']:
        if not total['negative']:
            expected = expected_totals[(total['mode'], total['messages_scored'])]
            assert (total['searches'], total['exact_both_plaintexts_775']) == expected
    audit = json.loads((PHASE / 'independent_source_audit.json').read_text())
    for rel, digest in audit['reviewed_sha256'].items():
        assert sha(ROOT / rel) == digest, f'Audit source is stale: {rel}'
    checked_run_manifests = []
    for path in sorted(PHASE.glob('*_manifest.json')):
        run = json.loads(path.read_text())
        if 'mode' not in run:
            continue
        for rel, digest in run.get('sha256', {}).items():
            if rel == 'work/phase3_crypto/phase3':
                continue  # The original compiled binaries are not portable.
            source = ROOT / rel
            if rel == 'work/phase3_crypto/phase3.cpp' and run['mode'] == 'full':
                source = PHASE / 'phase3_full_validated.cpp'
            assert sha(source) == digest, f'Run provenance mismatch: {path.name}, {rel}'
        checked_run_manifests.append(path.name)

    newledger = json.loads((ROOT / 'work/history/bar-blume277-adjacent/images-source-ledger.json').read_text())
    # Verify every downloaded adjacent original, even though only seven are copied.
    records = newledger if isinstance(newledger, list) else newledger.get('images', newledger.get('entries', []))
    assert len(records) == 22
    for row in records:
        rel = row.get('local_path', row.get('local_file'))
        assert sha(ROOT / rel) == row['sha256'], rel

    DEST.mkdir(parents=True)
    block = (
        'La nueva búsqueda de la primera clave (K1) recupera exactamente la clave y las 775 letras '
        'en los 100 controles conjuntos cuando se proporciona la segunda clave (K2). '
        'Son 25 pares por corpus y combinación de anchos: prosa española y una aproximación '
        'de estilo telegráfico, con claves de 12×15 y 20×25 columnas. Los anchos se conocen de antemano. '
        'La prueba usa la misma puntuación por trigramas que la etapa K1 del ataque completo. '
        'Con el mensaje largo como único texto puntuado se recuperan 96 de los 100 pares.\n\n'
        'El piloto que debe descubrir ambas claves recupera 0 de los 16 pares al puntuar '
        'ambos mensajes, y 1 de 16 al puntuar únicamente el largo. La única recuperación es '
        'sintética. El piloto es exploratorio y no mide una tasa de éxito general. '
        'Los controles barajados, los límites de tiempo y las variantes del algoritmo '
        'se documentan en los resultados. Se comprobaron además 60 casos de geometría '
        'y 6.780 movimientos.\n\n'
        'Esto sitúa la búsqueda de K2 como el principal trabajo pendiente bajo estas condiciones. '
        'Esta versión no se ha ejecutado sobre BLUME y no proporciona un texto histórico descifrado.'
    )
    report = (ROOT / 'work/sentinel-avance-2026-10-01.txt').read_text()
    assert report.count('CRYPTO_RESULT_BLOCK') == 1
    (DEST / 'LEEME.txt').write_text(report.replace('CRYPTO_RESULT_BLOCK', block), encoding='utf-8')

    histories = [
        'bar-blume277-adjacent-evidence.json',
        'blume-registered-address-lead.json',
        'blume-user-search-screenshot-audit.json',
        'blume2020-public-report-search.json',
        'gaceta1934-direcciones-abreviadas.pdf',
        'gaceta1934-direcciones-abreviadas-p1437.png',
        'telegraph-regulations-madrid1932-lnts151.pdf',
        'telegraph-regulations-madrid1932-p63.png',
        'correos-catalogue-direcciones.txt',
        'correos-catalogue-abreviadas.txt',
        'correos-catalogue-salamanca.txt',
        'correos-catalogue-salamanca1930-1940.txt',
        'correos-catalogue-blume.txt',
    ]
    for name in histories:
        copy('work/history/' + name)
    adjacent = 'work/history/bar-blume277-adjacent/'
    for path in sorted((ROOT / adjacent).glob('*.json')):
        copy(str(path.relative_to(ROOT)))
    selected = [
        'Umschlag_0000067-00000491.jpg',
        'Unterlagen_0000068-00000499.jpg',
        'Unterlagen_0000068-00000500.jpg',
        'Unterlagen_0000070-00000507.jpg',
        'Unterlagen_0000070-00000511.jpg',
        'Dokument_0000071-00000513.jpg',
        'Dokument_0000071-00000517.jpg',
    ]
    for name in selected:
        copy(adjacent + 'images/' + name)
    for path in sorted(PHASE.iterdir()):
        if path.is_file() and path.suffix in ('.json', '.jsonl', '.h', '.cpp', '.py', '.txt') and not path.name.startswith('progress_'):
            copy(str(path.relative_to(ROOT)))
    for name in ['double_search.cpp', 'model_es.bin', 'holdout_es.txt', 'holdout_proxy.txt',
                 'model_provenance.json', 'prepare_model.py', 'pg2000.txt']:
        copy('work/crypto/' + name)
    copy('work/build_blume_supplement.py')

    verification = {
        'date': '2026-10-01',
        'independent_log_aggregation': {
            'oracle_positive_files': oraclefiles,
            'oracle_q3_k2_revealed_joint': {'exact': 100, 'total': 100},
            'oracle_q3_k2_revealed_single': {'exact': 96, 'total': 100},
            'full_positive_files': fullfiles,
            'full_joint': {'exact': 0, 'total': 16},
            'full_single': {'exact': 1, 'total': 16},
            'all_these_runs_completed_without_reported_budget_expiry': True,
            'reencryption_is_only_consistency_not_solution_evidence': True,
        },
        'adjacent_bar_originals_all_22_sha_verified': True,
        'adjacent_bar_originals_selected_for_package': selected,
        'adjacent_bar_originals_downloaded_but_excluded_from_package': 15,
        'historical_solution_found': False,
        'phase3_historical_attack_run': False,
        'binary_not_packaged_recompile_source': True,
        'prior_deliverable_and_baseline_hashes_before_build': before,
        'reviewed_current_source_hashes_match_independent_audit': True,
        'run_manifests_source_data_and_log_hashes_verified': checked_run_manifests,
        'full_run_main_source_hashes_resolve_to': 'work/phase3_crypto/phase3_full_validated.cpp',
        'limitations': [
            'Prior book screenshots, private account evidence and the user screenshot are not included.',
            'Referenced work/phase2_crypto thesis text is not copied; primary technical source is linked in METHOD.txt.',
            'Historical ledgers describe all downloaded originals; fifteen adjacent images remain outside this selected supplement.',
            'Absolute CLI paths in run manifests identify the original environment; re-run from package root with the README commands.',
        ],
    }
    (DEST / 'verificacion-suplemento.json').write_text(json.dumps(verification, ensure_ascii=False, indent=2) + '\n')
    entries = [{'path': str(p.relative_to(DEST)), 'bytes': p.stat().st_size, 'sha256': sha(p)}
               for p in sorted(DEST.rglob('*')) if p.is_file()]
    manifest = {'date': '2026-10-01', 'scope': 'Separate selected-source supplement; historical ciphertext remains unsolved.', 'files': entries}
    (DEST / 'manifest-paquete.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    hashes = [(str(p.relative_to(DEST)), sha(p)) for p in sorted(DEST.rglob('*')) if p.is_file()]
    (DEST / 'SHA256SUMS.txt').write_text(''.join(digest + '  ' + path + '\n' for path, digest in hashes))
    files = [p for p in sorted(DEST.rglob('*')) if p.is_file()]
    with zipfile.ZipFile(ARCHIVE, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for path in files:
            z.write(path, DEST.name + '/' + str(path.relative_to(DEST)))
    with zipfile.ZipFile(ARCHIVE) as z:
        assert z.testzip() is None
        for path in files:
            name = DEST.name + '/' + str(path.relative_to(DEST))
            assert hashlib.sha256(z.read(name)).hexdigest() == sha(path)
    after = {str(p.relative_to(ROOT)): sha(p) for p in preserved}
    assert before == after
    print(json.dumps({'archive': str(ARCHIVE), 'files': len(files), 'bytes': ARCHIVE.stat().st_size,
                      'sha256': sha(ARCHIVE), 'prior_files_preserved': before == after}, ensure_ascii=False))

if __name__ == '__main__':
    main()

"""Read-only replay of the completed phase 17 public export.

Recomputes saved-log descriptors only, via the approved compute(root) routine.
Never evaluates IDP, runs a solver, regenerates RNG, opens the network, reads
truth/model inputs or writes files. The full original local baseline is not required.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
PLAN_SHA256 = 'c3c81e29da5e0d54dbd42706e4feeb4414324d091d2d9cd3a759fe114f42036f'
SOURCE_SHA256 = '28bebca8650461b807612f2b2aef9c2c54a0b9edd89eac8782e689e569b02232'
RECORDS = 'work/phase17_records/'
REVIEW = 'work/phase17_review/'
SOURCE_PATH = RECORDS + 'analyze_saved_paths.py'
SAFE_IMPORTS = {'csv', 'hashlib', 'io', 'json', 'pathlib', 'typing'}
ZERO_FIELDS = ('new_IDP_calls', 'new_truth_score_evaluations',
               'new_solver_trajectories', 'new_searches')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def within(root, relative):
    require(isinstance(relative, str) and not Path(relative).is_absolute(),
            f'Expected relative export path: {relative!r}')
    path = (root / relative).resolve()
    require(path.is_relative_to(root), f'Path outside export: {relative}')
    return path


def check_ref(root, relative, digest, size=None):
    path = within(root, relative)
    require(path.is_file() and sha(path) == digest, f'Recorded file hash differs: {relative}')
    if size is not None:
        require(type(size) is int and path.stat().st_size == size,
                f'Recorded file size differs: {relative}')
    return path


def check_inventory(root):
    """Check selected contents, never require the complete original workspace."""
    path = root / 'provenance/phase17_source_inventory.jsonl'
    require(path.is_file(), 'Requires the completed phase 17 export inventory')
    entries = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    sources = {entry['source_path']: entry for entry in entries}
    require(len(sources) == len(entries), 'Duplicate phase 17 source inventory entry')
    included = 0
    for entry in entries:
        disposition = entry['disposition']
        require(disposition in ('included', 'referenced_only'), 'Unknown inventory disposition')
        if disposition == 'included':
            check_ref(root, entry['repository_path'], entry['sha256'], entry['bytes'])
            included += 1
        else:
            require(bool(entry.get('reason')), 'Referenced-only resource lacks its publication reason')
    update = load(root / 'provenance/phase17_update.json')
    require(update['research_through_phase'] == 17
            and update['new_inventory_entries'] == len(entries)
            and update['new_included_files'] == included
            and update['new_referenced_files'] == len(entries) - included,
            'Publication update/inventory counts differ')
    return sources, {'entries': len(entries), 'included': included,
                     'referenced_only': len(entries) - included}


def read_approved_compute(source_path):
    """Load definitions as source text; no import cache and no main invocation."""
    source = source_path.read_text(encoding='utf-8')
    tree = ast.parse(source, filename=str(source_path))
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    require('compute' in functions, 'Approved source has no compute(root) function')
    # Only definitions reachable through direct local calls from compute are
    # loaded. The executable writer/receipt wrapper and main are excluded.
    required = {'compute'}
    pending = ['compute']
    while pending:
        name = pending.pop()
        for node in ast.walk(functions[name]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                called = node.func.id
                if called in functions and called not in required:
                    require(called not in {'main', 'write_new'},
                            'compute reaches the executable writer wrapper')
                    required.add(called)
                    pending.append(called)
    for name in required:
        for node in ast.walk(functions[name]):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    require(node.func.id not in {'eval', 'exec', 'compile', '__import__'},
                            'Descriptor compute uses dynamic execution')
                elif isinstance(node.func, ast.Attribute):
                    require(node.func.attr not in {'write', 'write_text', 'write_bytes', 'mkdir',
                        'unlink', 'rename', 'replace', 'run', 'Popen', 'system', 'check_output'},
                        'Descriptor compute reaches a writer or external process')
    selected = [functions[name] for name in required]
    used_names = {node.id for definition in selected for node in ast.walk(definition)
                  if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
    required_classes = set(classes).intersection(used_names)
    require(required_classes == {'Row'}, 'Approved descriptor class set differs')
    selected.extend(classes[name] for name in required_classes)
    used_names.update(node.id for name in required_classes for node in ast.walk(classes[name])
                      if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load))
    definitions = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            aliases = [alias for alias in node.names
                       if (alias.asname or alias.name.split('.')[0]) in used_names]
            if aliases:
                require(all(alias.name.split('.')[0] in SAFE_IMPORTS for alias in aliases),
                        'Descriptor compute imports outside its recorded-data scope')
                definitions.append(ast.Import(names=aliases))
        elif isinstance(node, ast.ImportFrom):
            aliases = [alias for alias in node.names if (alias.asname or alias.name) in used_names]
            if aliases:
                require(node.level == 0 and node.module.split('.')[0] in SAFE_IMPORTS,
                        'Descriptor compute imports outside its recorded-data scope')
                definitions.append(ast.ImportFrom(module=node.module, names=aliases, level=0))
        elif isinstance(node, ast.FunctionDef) and node.name in required:
            definitions.append(node)
        elif isinstance(node, ast.ClassDef) and node.name in required_classes:
            definitions.append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            # Top-level assignments in this approved source are literal constants.
            ast.literal_eval(node.value)
            definitions.append(node)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            definitions.append(node)
    module = ast.Module(body=definitions, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = {'__name__': 'phase17_public_record_descriptors', '__file__': str(source_path)}
    exec(compile(module, str(source_path), 'exec'), namespace)
    return namespace['compute']


def final_metadata(root, plan, approval, source_hash, output):
    """Bind saved approvals, both audits and each attempt/launcher receipt."""
    require(source_hash == SOURCE_SHA256, 'Analysis source differs from the reviewed source')
    for label in ('root_review', 'independent_review', 'preaudit_root'):
        check_ref(root, approval[label + '_path'], approval[label + '_sha256'])
    require(approval['CSV_aggregations_before_approval'] == 0
            and approval['new_IDP_calls_before_approval'] == 0,
            'Approval records pre-approval aggregation or scoring')
    preaudit = load(root / approval['preaudit_root_path'])
    require(preaudit['status'] == 'passed' and not preaudit['errors']
            and preaudit['plan_sha256'] == PLAN_SHA256
            and preaudit['source_sha256'] == source_hash
            and preaudit['input_hashes_checked'] == 10
            and preaudit['CSV_aggregations_before_approval'] == 0
            and preaudit['new_IDP_calls'] == 0 and preaudit['new_solver_trajectories'] == 0,
            'Root preaudit is incomplete or bound to different inputs')
    preapproval = load(root / (REVIEW + 'independent_preapproval.json'))
    require(preapproval['status'] == 'approved_before_csv_processing'
            and preapproval['independent_approved'] is True
            and preapproval['plan_sha256'] == PLAN_SHA256
            and preapproval['source_sha256'] == source_hash
            and preapproval['report_path'] == approval['independent_review_path']
            and preapproval['AST_passed'] is True and not preapproval['remaining_objections']
            and all(preapproval[field] is False for field in
                    ('CSV_processing_performed', 'compute_executed', 'truth_read'))
            and preapproval['new_IDP_calls'] == 0 and preapproval['new_truth_score_evaluations'] == 0,
            'Independent preapproval does not bind the approved source/plan')
    receipt_path = root / (RECORDS + 'run_receipt.json')
    receipt = load(receipt_path)
    require(receipt['phase'] == 17 and receipt['status'] == 'completed'
            and receipt['plan_sha256'] == PLAN_SHA256 and receipt['source_sha256'] == source_hash
            and receipt['approval_sha256'] == sha(root / (RECORDS + 'audit_approval.json'))
            and all(receipt[field] == 0 for field in ZERO_FIELDS)
            and receipt['maximum_analysis_seconds'] == plan['costs']['maximum_analysis_seconds'] == 60
            and 0 <= receipt['seconds'] < 60 and receipt['end_unix'] >= receipt['start_unix'],
            'Analysis execution receipt differs from the fixed zero-scoring scope')
    require(type(receipt['attempt']) is int
            and 1 <= receipt['attempt'] <= 1 + plan['costs']['maximum_repair_attempts'],
            'Analysis attempt exceeds its fixed bound')
    require(set(receipt['outputs']) == {'analysis.json', 'comparison.csv'}, 'Unexpected analysis outputs')
    for relative, digest in receipt['outputs'].items():
        check_ref(root, RECORDS + relative, digest)
    attempt_path = RECORDS + f"attempts/attempt{receipt['attempt']:02d}/"
    check_ref(root, attempt_path + 'source.py', source_hash)
    check_ref(root, attempt_path + 'receipt.json', sha(receipt_path))
    started = load(root / (attempt_path + 'started.json'))
    require(started['status'] == 'started' and started['attempt'] == receipt['attempt']
            and started['plan_sha256'] == PLAN_SHA256 and started['source_sha256'] == source_hash
            and started['approval_sha256'] == receipt['approval_sha256']
            and started['start_unix'] == receipt['start_unix']
            and started['maximum_analysis_seconds'] == 60
            and all(started[field] == 0 for field in ZERO_FIELDS),
            'Saved analysis attempt start differs from its receipt')
    launcher = load(root / (REVIEW + f"launch_receipt{receipt['attempt']}.json"))
    require(launcher['status'] == 'completed' and launcher['attempt'] == receipt['attempt']
            and launcher['returncode'] == 0 and launcher['timed_out'] is False
            and launcher['hard_seconds'] == 60 and 0 <= launcher['seconds'] < 60
            and launcher['plan_sha256'] == PLAN_SHA256 and launcher['source_sha256'] == source_hash
            and launcher['new_IDP_calls'] == 0 and launcher['new_solver_trajectories'] == 0,
            'Launcher did not finish the approved analysis within its bound')
    launch_started = load(root / (REVIEW + f"launch_started{receipt['attempt']}.json"))
    require(launch_started['plan_sha256'] == PLAN_SHA256
            and launch_started['source_sha256'] == source_hash
            and launch_started['hard_seconds'] == 60 and launch_started['new_IDP_calls'] == 0,
            'Launcher start differs from the bound analysis source/plan')
    for stream in ('stdout', 'stderr'):
        check_ref(root, REVIEW + f"launch_{stream}{receipt['attempt']}.txt", launcher[stream + '_sha256'])
    launch_stdout = load(root / (REVIEW + f"launch_stdout{receipt['attempt']}.txt"))
    require(launch_stdout['status'] == 'completed'
            and launch_stdout['outputs'] == receipt['outputs']
            and launch_stdout['CSV_rows_checked'] == receipt['CSV_rows_checked']
            and launch_stdout['new_IDP_calls'] == 0, 'Launcher stdout differs from analysis receipt')
    analysis = output['analysis'] if output is not None else load(root / (RECORDS + 'analysis.json'))
    require(analysis['phase'] == 17 and analysis['status'] == 'completed_descriptive_replay'
            and analysis['plan_sha256'] == PLAN_SHA256 and analysis['inputs'] == plan['inputs']
            and analysis['posthoc_outcome_selection'] is True
            and all(analysis[field] == 0 for field in ZERO_FIELDS)
            and analysis['CSV_rows_checked'] == receipt['CSV_rows_checked'] == 183143,
            'Descriptor metadata/costs differ from the receipt and fixed plan')
    independent_path = REVIEW + 'post_ejecucion_independiente.json'
    independent = load(root / independent_path)
    require(independent['phase'] == 17 and independent['status'] == 'passed'
            and independent['plan_sha256'] == PLAN_SHA256
            and independent['analyst_source_sha256'] == source_hash
            and independent['analysis_receipt_sha256'] == sha(receipt_path)
            and independent['analysis_sha256'] == receipt['outputs']['analysis.json']
            and independent['comparison_sha256'] == receipt['outputs']['comparison.csv']
            and independent['analyst_imported'] is False and independent['truth_read'] is False
            and independent['new_IDP_calls'] == 0 and independent['new_truth_score_evaluations'] == 0
            and independent['rows_replayed'] == analysis['CSV_rows_checked'],
            'Independent post-run audit is incomplete or bound to different results')
    audit_receipt = load(root / (REVIEW + 'attempts/attempt01/receipt.json'))
    require(audit_receipt['status'] == 'passed' and audit_receipt['attempt'] == 1
            and audit_receipt['plan_sha256'] == PLAN_SHA256
            and audit_receipt['result_sha256'] == sha(root / independent_path)
            and audit_receipt['rows_replayed'] == analysis['CSV_rows_checked']
            and audit_receipt['truth_read'] is False and audit_receipt['new_IDP_calls'] == 0
            and audit_receipt['new_truth_score_evaluations'] == 0
            and audit_receipt['maximum_seconds'] == plan['costs']['maximum_independent_audit_seconds'] == 60
            and 0 <= audit_receipt['seconds'] < 60,
            'Independent attempt receipt differs from the saved result')
    check_ref(root, REVIEW + 'audit_saved_descriptors.py', audit_receipt['source_sha256'])
    check_ref(root, REVIEW + 'attempts/attempt01/source.py', audit_receipt['source_sha256'])
    audit_started = load(root / (REVIEW + 'attempts/attempt01/started.json'))
    require(audit_started['status'] == 'started' and audit_started['attempt'] == 1
            and audit_started['plan_sha256'] == PLAN_SHA256
            and audit_started['source_sha256'] == audit_receipt['source_sha256']
            and audit_started['started_unix'] == audit_receipt['started_unix']
            and audit_started['maximum_seconds'] == 60 and audit_started['truth_read'] is False
            and audit_started['new_IDP_calls'] == 0 and audit_started['new_truth_score_evaluations'] == 0,
            'Independent audit start differs from its saved receipt')
    root_audit = load(root / (REVIEW + 'postaudit_root.json'))
    require(root_audit['status'] == 'passed' and not root_audit['protected_errors']
            and root_audit['analysis_sha256'] == receipt['outputs']['analysis.json']
            and root_audit['comparison_sha256'] == receipt['outputs']['comparison.csv']
            and root_audit['run_receipt_sha256'] == sha(receipt_path)
            and root_audit['stable_rows_independently_counted_by_root'] == 33298
            and root_audit['new_IDP_calls'] == 0 and root_audit['new_solver_trajectories'] == 0,
            'Root post-run saved-neighbourhood audit is incomplete')
    # protected_files_checked is a saved historical guard, not a public-clone requirement.


def main(root):
    require(__debug__, 'Run without Python -O: approved compute assertions must remain enabled')
    root = root.resolve()
    inventory, counts = check_inventory(root)
    plan_path = check_ref(root, RECORDS + 'plan.json', PLAN_SHA256)
    plan = load(plan_path)
    require(plan['phase'] == 17 and plan['status'] == 'fixed_descriptive_plan_before_aggregation',
            'Unexpected phase 17 plan')
    require(len(plan['pairs']) == 2 and len(plan['inputs']) == 10, 'Unexpected descriptive reading set')
    require(all(plan['costs'][field] == 0 for field in ('new_IDP_calls',
        'new_truth_score_evaluations', 'new_solver_trajectories', 'new_searches')),
        'Descriptive plan permits new scoring or trajectories')
    allowed_inputs = {'work/phase16_crypto/moves.json', 'work/phase16_crypto/evaluation.json'}
    for pair in plan['pairs']:
        require(set(pair['profiles']) == {'A', 'B'}, 'Expected paired saved paths')
        for item in pair['profiles'].values():
            allowed_inputs.update((item['csv_path'], item['summary_path']))
    require(set(plan['inputs']) == allowed_inputs, 'Input list differs from selected saved records')
    for relative, item in plan['inputs'].items():
        require(relative.startswith('work/phase16_crypto/') and Path(relative).suffix in ('.csv', '.json')
                and 'truth' not in Path(relative).name and 'model' not in Path(relative).name,
                'Input outside saved-record scope')
        check_ref(root, relative, item['sha256'], item['bytes'])
    # The baseline manifest may be published as a preservation record. Only
    # that record is hashed here, never every original 3,151 local resource.
    baseline = within(root, plan['frozen_baseline_path'])
    if baseline.exists():
        check_ref(root, plan['frozen_baseline_path'], plan['frozen_baseline_sha256'])
    approval = load(root / (RECORDS + 'audit_approval.json'))
    require(approval['root_approved'] is True and approval['independent_approved'] is True
            and approval['plan_sha256'] == PLAN_SHA256, 'Double plan/source approval missing')
    source_hash = approval['source_sha256']
    source_path = check_ref(root, SOURCE_PATH, source_hash)
    required_selection = {SOURCE_PATH, RECORDS + 'plan.json', RECORDS + 'audit_approval.json',
        RECORDS + 'run_receipt.json', RECORDS + 'analysis.json', RECORDS + 'comparison.csv',
        RECORDS + 'attempts/attempt01/source.py', RECORDS + 'attempts/attempt01/started.json',
        RECORDS + 'attempts/attempt01/receipt.json',
        REVIEW + 'independent_preapproval.json', REVIEW + 'post_ejecucion_independiente.json',
        REVIEW + 'post_ejecucion_independiente.txt', REVIEW + 'postaudit_root.json',
        REVIEW + 'audit_saved_descriptors.py', REVIEW + 'attempts/attempt01/source.py',
        REVIEW + 'attempts/attempt01/started.json', REVIEW + 'attempts/attempt01/receipt.json',
        REVIEW + 'launch_started1.json', REVIEW + 'launch_receipt1.json',
        REVIEW + 'launch_stdout1.txt', REVIEW + 'launch_stderr1.txt',
        *(approval[label + '_path'] for label in ('root_review', 'independent_review', 'preaudit_root'))}
    require(all(relative in inventory and inventory[relative]['disposition'] == 'included'
                and inventory[relative]['repository_path'] == relative for relative in required_selection),
            'Approved analysis/review/receipt resource omitted from the selected export')
    # Validate the complete saved approval/audit chain before computing descriptors.
    final_metadata(root, plan, approval, source_hash, None)
    computed = read_approved_compute(source_path)(root)
    require(isinstance(computed, dict) and set(computed) == {'analysis', 'comparison_csv'},
            'compute(root) does not match the approved deterministic contract')
    require(computed['analysis'] == load(root / (RECORDS + 'analysis.json')),
            'Saved descriptor analysis differs from deterministic recomputation')
    require(isinstance(computed['comparison_csv'], str)
            and computed['comparison_csv'] == (root / (RECORDS + 'comparison.csv')).read_text(encoding='utf-8'),
            'Saved comparison CSV differs from deterministic recomputation')
    final_metadata(root, plan, approval, source_hash, computed)
    print(json.dumps({'status': 'passed', 'phase': 17, 'published_selection': counts,
        'input_hashes_checked': len(plan['inputs']), 'selected_saved_paths': 4,
        'deterministic_analysis_matches': True, 'deterministic_comparison_csv_matches': True,
        'required_complete_local_baseline': False,
        'new_IDP_calls': 0, 'new_truth_score_evaluations': 0, 'new_solver_trajectories': 0,
        'scope': 'Post hoc saved-log descriptors only; no confirmatory experiment or recovery-rate test.',
        'limits': 'Finite recorded witnesses do not establish a shortest/minimum-loss route or global barrier.'}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT,
                        help='Root of the completed public export')
    arguments = parser.parse_args()
    try:
        main(arguments.root)
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as error:
        raise SystemExit(json.dumps({'status': 'failed', 'error_type': type(error).__name__,
            'error': str(error), 'new_IDP_calls': 0, 'new_solver_trajectories': 0}, indent=2))

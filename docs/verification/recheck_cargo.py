#!/usr/bin/env python3
"""Compare two Hooray JSON reports with a pinned RustSec index and zip maintainer records."""

import argparse
import csv
import hashlib
import json
import operator
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import urllib.request
from collections import Counter, defaultdict

REVISIONS = [
    ('0361fda09da6d49d477b127a64624e52aef3969e', '86858a28cec66553a6f38dff33b5c31685e8d85c35ecb2cc21ba5a9db502de47'),
    ('e7c066700df3c8910cbba0e0f913165fe7345c2d', 'c2241ee29aa5654abbe986c78970f0879563fceb379a1032f307386734781596'),
]
RUSTSEC = 'f291af9b1cc0d21dfcea1709d6b037963cef262b'
ZIP_API = 'https://api.github.com/repos/zip-rs/zip2/security-advisories?per_page=100'


def git(*args):
    return subprocess.check_output(['git', *args])


def audit(lock, db, work):
    path = work / 'Cargo.lock'
    path.write_bytes(lock)
    proc = subprocess.run(['cargo', 'audit', '--json', '--no-yanked', '--no-fetch', '--stale', '--db', str(db), '--file', str(path)], cwd=work, stdout=subprocess.PIPE, check=False)
    result = json.loads(proc.stdout)
    # cargo-audit exits 1 when vulnerabilities are found. Reject other failures.
    if proc.returncode != int(result['vulnerabilities']['found']):
        raise SystemExit(f'Unexpected cargo-audit status: {proc.returncode}')
    if any(result['settings'][key] for key in ('ignore', 'target_os', 'target_arch', 'severity')):
        raise SystemExit('Use a clean cargo-audit configuration without ignores or filters')
    records = [('vulnerability', result['vulnerabilities']['list']), *result['warnings'].items()]
    return {(r['package']['name'], r['package']['version'], r['advisory']['id']): (level, r) for level, batch in records for r in batch}


def hooray_matches(report, reference):
    inventory = report['inventory']['components']
    found, labels = defaultdict(list), defaultdict(set)
    for item in report['findings'].values():
        if item['kind'] != 'vulnerability':
            continue
        component = inventory[item['component_id']]
        coordinate = component['name'], component['version']
        id_ = item['rule_id'].removeprefix('osv:')
        aliases = {id_, *item['aliases']}
        labels[coordinate].update(aliases)
        matches = [key for key, (_, row) in reference.items() if key[:2] == coordinate and aliases.intersection({key[2], *row['advisory']['aliases']})]
        if len(matches) == 1:
            found[matches[0]].append(id_)
        else:
            print('No unambiguous RustSec match:', coordinate, id_, matches)
    print('RustSec package/version/advisory rows:', len(reference), '; matched:', len(found), '; matched raw Hooray findings:', sum(map(len, found.values())))
    return found, labels


def version(text):
    # Only the numeric releases and numbered prereleases used by this capture.
    m = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:-pre(\d+))?', text)
    if not m:
        raise ValueError(f'Unsupported maintainer version: {text!r}')
    return int(m[1]), int(m[2]), int(m[3]), 0 if m[4] else 1, int(m[4] or '0')


def in_affected_range(locked, expr, fixed):
    # The publisher sometimes supplies only a lower bound in the affected field.
    # Limit it by the explicit first-patched version, then intersect all bounds.
    candidate = version(locked)
    tests = {'=': operator.eq, '<': operator.lt, '>': operator.gt, '<=': operator.le, '>=': operator.ge}
    bounds = []
    for part in expr.split(','):
        m = re.fullmatch(r'\s*(>=|<=|<|>|=)?\s*(\S+)\s*', part)
        if not m:
            raise ValueError(f'Unsupported maintainer range: {expr!r}')
        bounds.append(tests[m[1] or '='](candidate, version(m[2])))
    return candidate < version(fixed) and all(bounds)


def get_publisher_rows():
    url = ZIP_API
    while url:
        request = urllib.request.Request(url, headers={'User-Agent': 'hooray-public-advisory-check', 'Accept': 'application/vnd.github+json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            yield from json.load(response)
            match = re.search(r'<(https://api\.github\.com/[^>]+)>; rel="next"', response.headers.get('Link', ''))
            url = match[1] if match else None


def write_rows(path, fields, rows):
    with path.open('w', encoding='utf-8', newline='') as output:
        writer = csv.writer(output, delimiter='\t', lineterminator='\n')
        writer.writerow(fields.split())
        writer.writerows(rows)


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--db', required=True, type=Path, help='clean RustSec advisory-db checkout at the recorded commit')
    args.add_argument('--base-report', required=True, type=Path)
    args.add_argument('--foundation-report', required=True, type=Path)
    args.add_argument('--out', required=True, type=Path, help='new or empty receipt directory')
    opts = args.parse_args()
    db = opts.db.resolve()
    if git('-C', str(db), 'rev-parse', 'HEAD').decode().strip() != RUSTSEC or git('-C', str(db), 'status', '--porcelain', '--untracked-files=all'):
        raise SystemExit('Use a clean RustSec checkout at '+RUSTSEC)
    if opts.out.exists() and any(opts.out.iterdir()):
        raise SystemExit('Use an empty output directory')
    opts.out.mkdir(parents=True, exist_ok=True)
    references, checks, ids, locks = [], [], [], []
    with tempfile.TemporaryDirectory() as tmp:
        for (rev, sha), source in zip(REVISIONS, (opts.base_report, opts.foundation_report), strict=True):
            lock = git('show', rev+':Cargo.lock')
            if hashlib.sha256(lock).hexdigest() != sha:
                raise SystemExit('Unexpected lockfile: '+rev)
            refs = audit(lock, db, Path(tmp)); references.append(refs)
            found, labels = hooray_matches(json.loads(source.read_text())['report'], refs)
            checks.append(found); ids.append(labels)
            packages = defaultdict(list)
            for p in tomllib.loads(lock.decode())['package']:
                packages[p['name']].append(p['version'])
            locks.append(packages)
    cargo_rows = []
    for (name, ver, aid), (kind, record) in sorted(references[0].items()):
        adv = record['advisory']; aliases = adv['aliases']; gh = ','.join(x for x in aliases if x.startswith('GHSA-'))
        next_versions = locks[1][name]
        newer = sorted(id_ for v in next_versions for id_ in checks[1].get((name, v, aid), []))
        source_url = f'https://github.com/RustSec/advisory-db/blob/{RUSTSEC}/crates/{name}/{aid}.md'
        upstream = adv['url'] or (f'https://github.com/zip-rs/zip2/security/advisories/{gh}' if name=='zip' and gh else '')
        cargo_rows.append([name, ver, aid, kind, ','.join(x for x in aliases if x.startswith('CVE-')), gh, ' || '.join(record['versions']['patched']), ','.join(sorted(checks[0][name, ver, aid])), ','.join(next_versions), ','.join(newer), source_url, upstream])
    write_rows(opts.out/'cargo-rustsec-coordinates.tsv', 'package base_version rustsec_id rustsec_class cve_alias ghsa_alias rustsec_patched_range base_hooray_ids foundation_locked_versions foundation_hooray_ids rustsec_source upstream_reference', cargo_rows)
    rows, stats = [], Counter()
    for row in sorted(get_publisher_rows(), key=lambda r:r['ghsa_id']):
        if row['withdrawn_at']:
            continue
        for vuln in row['vulnerabilities']:
            if vuln['package'] != {'ecosystem':'rust', 'name':'zip'}:
                continue
            fx, expr = vuln['patched_versions'], vuln['vulnerable_version_range']
            publisher_ids = {row['ghsa_id'], *(x['value'] for x in row['identifiers'])}
            result = []
            for index, locked in enumerate(('8.6.0', '9.8.1')):
                inside = in_affected_range(locked, expr, fx)
                seen = bool(publisher_ids.intersection(ids[index].get(('zip', locked), set())))
                stats[(locked, inside, seen)] += 1
                result.extend('yes' if v else 'no' for v in (inside, seen))
            rows.append([row['ghsa_id'], row['cve_id'] or '', row['published_at'], row['updated_at'], expr, fx, *result, row['html_url']])
    write_rows(opts.out/'zip-maintainer-coordinates.tsv', 'ghsa_id publisher_cve published_at updated_at publisher_range publisher_first_patched base_8.6.0_in_range base_reported_by_hooray foundation_9.8.1_in_range foundation_reported_by_hooray publisher_url', rows)
    for (locked, inside, seen), count in sorted(stats.items()):
        print(f'zip@{locked}: in maintainer range={inside}, Hooray finding={seen}: {count}')


if __name__ == '__main__':
    main()

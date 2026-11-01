"""Write a findings list (from surface.find) as JSON and as a Markdown table.

write(findings, name, out_dir) creates
  <out_dir>/<name>-report.json   the findings list as JSON
  <out_dir>/<name>-report.md     a table: Component, Type, Issue, CWE, Confidence
and returns the two paths.
"""
import json
import os

COLUMNS = (('Component', 'component'), ('Type', 'component_type'), ('Issue', 'issue'),
           ('CWE', 'cwe'), ('Confidence', 'confidence'))


def _cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ')


def to_markdown(findings, name):
    lines = ['# %s report' % name, '']
    if not findings:
        lines.append('No findings.')
        return '\n'.join(lines) + '\n'
    lines.append('| ' + ' | '.join(h for h, _ in COLUMNS) + ' |')
    lines.append('|' + '|'.join('---' for _ in COLUMNS) + '|')
    for f in findings:
        lines.append('| ' + ' | '.join(_cell(f.get(k, '')) for _, k in COLUMNS) + ' |')
    return '\n'.join(lines) + '\n'


def write(findings, name, out_dir='.'):
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, '%s-report.json' % name)
    md_path = os.path.join(out_dir, '%s-report.md' % name)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2)
        f.write('\n')
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(to_markdown(findings, name))
    return json_path, md_path

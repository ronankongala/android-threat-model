"""Write a findings list (from surface.find) as JSON and as a Markdown table.

write(findings, name, out_dir, dynamic=None) creates
  <out_dir>/<name>-report.json   the findings list as JSON (static, then dynamic)
  <out_dir>/<name>-report.md     a table: Component, Type, Issue, CWE, Confidence, Evidence
and returns the two paths. Evidence is the line of code that triggered a code
finding (blank for manifest findings).

dynamic is the list of dynamic_analyzer findings, or None when dynamic analysis
was not run. The Markdown report has a "Dynamic Analysis Findings" section with
those findings, or a one-line note that the step was skipped.
"""
import json
import os

COLUMNS = (('Component', 'component'), ('Type', 'component_type'), ('Issue', 'issue'),
           ('CWE', 'cwe'), ('Confidence', 'confidence'), ('Evidence', 'evidence'))


def _cell(value):
    if value is None:
        return ''
    return str(value).replace('|', '\\|').replace('\n', ' ')


SKIPPED_NOTE = ('Dynamic analysis was skipped. To enable it, start the ghera27 emulator '
                '(check `adb devices`) and run `python src/ate.py --apk APK --dynamic`.')


def _table(findings):
    if not findings:
        return ['No findings.']
    lines = ['| ' + ' | '.join(h for h, _ in COLUMNS) + ' |',
             '|' + '|'.join('---' for _ in COLUMNS) + '|']
    for f in findings:
        cells = [_cell(f.get(k, '')) for _, k in COLUMNS]
        if cells[-1]:
            cells[-1] = '`%s`' % cells[-1].replace('`', "'")
        lines.append('| ' + ' | '.join(cells) + ' |')
    return lines


def to_markdown(findings, name, dynamic=None):
    lines = ['# %s report' % name, ''] + _table(findings)
    lines += ['', '## Dynamic Analysis Findings', '']
    lines += [SKIPPED_NOTE] if dynamic is None else _table(dynamic)
    return '\n'.join(lines) + '\n'


def write(findings, name, out_dir='.', dynamic=None):
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, '%s-report.json' % name)
    md_path = os.path.join(out_dir, '%s-report.md' % name)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(findings + (dynamic or []), f, indent=2)
        f.write('\n')
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(to_markdown(findings, name, dynamic))
    return json_path, md_path

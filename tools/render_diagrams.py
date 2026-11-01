#!/usr/bin/env python3
"""Render every Mermaid block in docs/threat-models/ to SVG.

Block n (counting from 1) of docs/threat-models/<name>.md is written to
docs/diagrams/<name>-<n>.svg with the local mermaid-cli in tools/node_modules.

Setup (once, no admin rights):
  portable Node.js in C:\\Android\\node, then in tools/:
    npm install
    node node_modules/puppeteer/lib/puppeteer/node/cli.js browsers install chrome-headless-shell
  with PUPPETEER_CACHE_DIR=tools/.cache/puppeteer (this script sets it too).

Usage: python tools/render_diagrams.py [file.md ...]
Exit code 0 when every block rendered; failures are listed at the end.
"""
import glob
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'docs', 'threat-models')
OUT = os.path.join(ROOT, 'docs', 'diagrams')
TOOLS = os.path.join(ROOT, 'tools')
NODE_DIR = r'C:\Android\node'
MMDC = os.path.join(TOOLS, 'node_modules', '@mermaid-js', 'mermaid-cli', 'src', 'cli.js')


def blocks(path):
    cur, found = None, []
    with open(path, encoding='utf-8') as f:
        for line in f:
            s = line.strip()
            if cur is None and s == '```mermaid':
                cur = []
            elif cur is not None and s == '```':
                found.append(''.join(cur))
                cur = None
            elif cur is not None:
                cur.append(line)
    return found


def main(argv):
    files = argv or sorted(glob.glob(os.path.join(SRC, '*.md')))
    env = dict(os.environ)
    env['PATH'] = NODE_DIR + os.pathsep + env.get('PATH', '')
    env['PUPPETEER_CACHE_DIR'] = os.path.join(TOOLS, '.cache', 'puppeteer')
    node = os.path.join(NODE_DIR, 'node.exe') if os.name == 'nt' else 'node'
    os.makedirs(OUT, exist_ok=True)
    ok, failed = 0, []
    with tempfile.TemporaryDirectory() as tmp:
        for path in files:
            name = os.path.splitext(os.path.basename(path))[0]
            for n, body in enumerate(blocks(path), 1):
                src = os.path.join(tmp, '%s-%d.mmd' % (name, n))
                dst = os.path.join(OUT, '%s-%d.svg' % (name, n))
                with open(src, 'w', encoding='utf-8') as f:
                    f.write(body)
                r = subprocess.run([node, MMDC, '-q', '-i', src, '-o', dst],
                                   env=env, capture_output=True, text=True)
                if r.returncode == 0 and os.path.exists(dst):
                    ok += 1
                    print('ok     %s-%d.svg' % (name, n))
                else:
                    msg = (r.stderr or r.stdout).strip().splitlines()
                    failed.append(('%s-%d' % (name, n), msg[:6]))
                    print('FAILED %s-%d.svg' % (name, n))
    print('\nRendered %d, failed %d' % (ok, len(failed)))
    for name, msg in failed:
        print('\n== %s' % name)
        for m in msg:
            print('   ' + m)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

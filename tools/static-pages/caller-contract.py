"""Bootstrap admission, embedded verbatim in the immutable reusable workflow.
No code from a tools_ref checkout runs before this verifies the caller pin.
"""
import os
from pathlib import Path
import re
import subprocess

COMPANION = 't-scheiber/maintenance-workflows'
TARGETS = {'t-scheiber/AK_WeatherApp':'755321462','t-scheiber/ScheiberVueAppAbgabe':'755319788'}

def caller(repository, revision):
    if repository not in TARGETS or not re.fullmatch('[a-f0-9]{40}', revision):
        raise RuntimeError('Invalid fixed caller identity')
    return f'''name: Publish validated static Pages
on:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
concurrency:
  group: static-pages
  cancel-in-progress: false
jobs:
  pages:
    if: github.repository == '{repository}' && github.ref == 'refs/heads/main' && vars.STATIC_PAGES_ENABLED == 'true'
    permissions:
      contents: read
      pages: write
      id-token: write
    uses: {COMPANION}/.github/workflows/static-pages.yml@{revision}
    with:
      tools_ref: '{revision}'
'''

def admit(env, content, actual_head):
    repo, revision = env.get('GITHUB_REPOSITORY'), env.get('TOOLS_REF')
    if repo not in TARGETS or env.get('GITHUB_REPOSITORY_ID') != TARGETS[repo] or env.get('GITHUB_REPOSITORY_OWNER_ID') != '66697291' or env.get('REPOSITORY_PRIVATE') != 'false':
        raise RuntimeError('Only fixed public personal repositories are admitted')
    if not isinstance(revision,str) or not re.fullmatch('[a-f0-9]{40}',revision) or revision == '0'*40:
        raise RuntimeError('A real immutable shared release is required')
    sha=env.get('GITHUB_SHA')
    if not isinstance(sha,str) or not re.fullmatch('[a-f0-9]{40}',sha) or actual_head != sha or env.get('CALLER_WORKFLOW_SHA') != sha or env.get('CALLER_WORKFLOW_REF') != repo+'/.github/workflows/pages.yml@refs/heads/main':
        raise RuntimeError('Caller source and workflow revisions differ')
    if env.get('DEFAULT_BRANCH') != 'main' or env.get('GITHUB_REF') != 'refs/heads/main' or env.get('STATIC_PAGES_ENABLED') != 'true':
        raise RuntimeError('Pages is disabled or the branch is not main')
    if env.get('GITHUB_EVENT_NAME') != 'push' and not (env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and env.get('GITHUB_ACTOR') == 't-scheiber' and env.get('GITHUB_TRIGGERING_ACTOR') == 't-scheiber'):
        raise RuntimeError('Unapproved Pages event')
    if not isinstance(content,str) or content != caller(repo, revision):
        raise RuntimeError('Caller permissions, source or paired immutable pin differ')
    return {'tools_ref':revision,'repository_name':repo.split('/')[1]}

if __name__ == '__main__':
    source=Path(os.environ['GITHUB_WORKSPACE'])/'source'
    filename=source/'.github/workflows/pages.yml'
    if any(p.is_symlink() for p in [source,source/'.github',filename.parent,filename]) or not filename.is_file() or filename.stat().st_size>4096:
        raise RuntimeError('Caller must be a bounded regular file')
    head=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True,timeout=10).strip()
    result=admit(os.environ,filename.read_text(),head)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:
        out.write(''.join(key+'='+value+'\n' for key,value in result.items()))

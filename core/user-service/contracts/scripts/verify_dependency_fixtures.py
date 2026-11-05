"""Verify published dependency wheels against project pins and the frozen lock."""
import email.parser
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
import zipfile


def verify(root):
    root = Path(root)
    directory = root / 'tests_artifacts/dependencies'
    records = json.loads((directory / 'manifest.json').read_text())['dependencies']
    project = tomllib.loads((root / 'pyproject.toml').read_text())
    lock = tomllib.loads((root / 'uv.lock').read_text())
    declared = {}
    for requirement in project['project']['dependencies'] + project.get('dependency-groups', {}).get('dev', []):
        if 'git+' in requirement:
            match = re.fullmatch(r'(controlplane-[a-z]+) @ git\+https://github.com/hyperme-sh/\1\.git@([0-9a-f]{40})', requirement)
            if not match or match[1] in declared:
                raise ValueError('Unsupported or duplicate dependency pin')
            declared[match[1]] = match[2]
    if not declared or len(records) != len(declared) or {r['distribution'] for r in records} != set(declared):
        raise ValueError('Fixture inventory differs from declared dependencies')
    wheels = []
    for record in records:
        name = record['distribution']
        revision = record['dependency_revision']
        if declared[name] != revision or record['artifact_revision'] != revision:
            raise ValueError('Fixture does not match dependency revision')
        entries = [p for p in lock['package'] if p['name'] == name]
        git = f'https://github.com/hyperme-sh/{name}.git?rev={revision}#{revision}'
        if len(entries) != 1 or entries[0]['version'] != record['version'] or entries[0]['source'] != {'git': git}:
            raise ValueError('Fixture does not match locked dependency')
        filename = record['wheel']
        if Path(filename).name != filename or not filename.endswith('.whl'):
            raise ValueError('Fixture must stay in its directory')
        wheel = directory / filename
        if not wheel.resolve().is_relative_to(directory.resolve()):
            raise ValueError('Fixture escapes directory')
        if hashlib.sha256(wheel.read_bytes()).hexdigest() != record['sha256']:
            raise ValueError('Fixture digest mismatch')
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            metadata = [n for n in names if n.endswith('.dist-info/METADATA')]
            if len(names) != len(set(names)) or len(metadata) != 1:
                raise ValueError('Ambiguous wheel metadata')
            info = email.parser.BytesParser().parsebytes(archive.read(metadata[0]))
            if info.get_all('Name') != [name] or info.get_all('Version') != [record['version']]:
                raise ValueError('Fixture metadata differs from dependency')
        wheels.append(wheel.resolve())
    return wheels


if __name__ == '__main__':
    print('\n'.join(str(p) for p in verify(sys.argv[1])))

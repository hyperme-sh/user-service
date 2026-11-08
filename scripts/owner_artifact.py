"""Bind both owner distributions in a deterministic, inspectable release archive."""
import argparse
import email.parser
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

PACKAGES = {'user-service': 'user_service', 'operator-ban-store': 'operator_ban_store'}


def wheel_snapshot(raw, distribution):
    package = PACKAGES[distribution]
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or any('..' in PurePosixPath(n).parts or n.startswith('/') for n in names):
            raise ValueError('Unsafe or duplicate wheel member')
        metadata = [n for n in names if re.fullmatch(re.escape(package) + r'-[^/]+\.dist-info/METADATA', n)]
        if len(metadata) != 1:
            raise ValueError('Expected owner distribution metadata')
        info = email.parser.BytesParser().parsebytes(archive.read(metadata[0]))
        versions = info.get_all('Version', [])
        if info.get_all('Name') != [distribution] or len(versions) != 1:
            raise ValueError('Ambiguous owner identity')
        version = versions[0]
        prefix = f'{package}-{version}.dist-info/'
        if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version) or metadata[0] != prefix+'METADATA':
            raise ValueError('Invalid owner version')
        runtime = [n for n in names if not n.startswith(prefix)]
        if package+'/__init__.py' not in runtime or any(not n.startswith(package+'/') for n in runtime):
            raise ValueError('Incomplete or unexpected owner runtime')
        return version, {n: hashlib.sha256(archive.read(n)).hexdigest() for n in sorted(runtime)}


def inspect(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or len(names) != len(PACKAGES):
            raise ValueError('Owner archive requires exactly two wheels')
        contracts, versions = {}, set()
        for distribution, package in PACKAGES.items():
            matches = [n for n in names if re.fullmatch(re.escape(package)+r'-[^/]+-py3-none-any\.whl', n)]
            if len(matches) != 1:
                raise ValueError('Missing or ambiguous owner wheel')
            version, contract = wheel_snapshot(archive.read(matches[0]), distribution)
            if matches[0] != f'{package}-{version}-py3-none-any.whl':
                raise ValueError('Wheel filename differs from metadata')
            versions.add(version)
            contracts[distribution] = contract
        if len(versions) != 1:
            raise ValueError('Mixed owner package versions')
    contract = (json.dumps({'schema_version': 1, 'coverage': 'complete packaged runtime of both owner distributions; installer metadata compatibility is separate', 'packaged_file_sha256': contracts}, sort_keys=True, indent=2)+'\n').encode()
    return contract, {'schema_version': 1, 'version': versions.pop(), 'artifact_sha256': hashlib.sha256(raw).hexdigest(), 'contract_sha256': hashlib.sha256(contract).hexdigest()}


def build(directory):
    directory = Path(directory)
    wheels = sorted(directory.glob('*.whl'))
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for wheel in wheels:
            member = zipfile.ZipInfo(wheel.name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = 0o100644 << 16
            archive.writestr(member, wheel.read_bytes())
    raw = output.getvalue()
    _, evidence = inspect(raw)
    path = directory / f"user_service-{evidence['version']}.owner.zip"
    path.write_bytes(raw)
    return path


def export(path, directory):
    contract, evidence = inspect(Path(path).read_bytes())
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    (directory/'contract.json').write_bytes(contract)
    (directory/'evidence.json').write_text(json.dumps(evidence, sort_keys=True, indent=2)+'\n')


def qualify(path, directory, source_sha):
    """Record this build without rewriting any historical release selection."""
    if not re.fullmatch('[a-f0-9]{40}', source_sha):
        raise ValueError('Exact source revision required')
    directory = Path(directory)
    export(path, directory)
    evidence = json.loads((directory / 'evidence.json').read_text())
    digest = evidence['artifact_sha256']
    candidate = dict(schema_version=1, line=evidence['version'].rsplit('.', 1)[0],
        purpose='artifact-qualification', stable_release=False, source_sha=source_sha,
        components={'user-service': dict(version=evidence['version'], contract='contract.json',
            contract_sha256=evidence['contract_sha256'],
            artifact=dict(kind='package', uri='urn:sha256:' + digest, sha256=digest))})
    with (directory / 'release.json').open('x') as stream:
        stream.write(json.dumps(candidate, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('build'); create.add_argument('directory')
    read = sub.add_parser('export'); read.add_argument('archive'); read.add_argument('directory')
    qualification = sub.add_parser('qualify'); qualification.add_argument('archive'); qualification.add_argument('directory'); qualification.add_argument('source_sha')
    args = parser.parse_args()
    if args.command == 'build':
        print(build(args.directory))
    elif args.command == 'export':
        export(args.archive, args.directory)
    else:
        qualify(args.archive, args.directory, args.source_sha)

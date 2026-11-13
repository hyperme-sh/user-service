"""Exercise only shell cleanup, without installing or running owner suites."""
import os
from pathlib import Path
import subprocess
import pytest

ROOT=Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('status', [0,1,5])
def test_cleanup_preserves_available_native_xml_and_original_status(tmp_path,status):
    script=(ROOT/'scripts/check-package.sh').read_text()
    cleanup=script.split('cleanup() {',1)[1].split('trap cleanup EXIT',1)[0]
    scratch=tmp_path/'private';scratch.mkdir()
    output=tmp_path/'results'
    (scratch/'source.xml').write_text('<testsuite failures="1"/>')
    (scratch/'private.txt').write_text('must not be copied')
    body='cleanup() {'+cleanup+'\ntrap cleanup EXIT\nexit '+str(status)
    result=subprocess.run(['bash','-c',body],env={**os.environ,'scratch':str(scratch),'TEST_EVIDENCE_DIR':str(output)})
    assert result.returncode==status
    assert (output/'source.xml').read_text()=='<testsuite failures="1"/>'
    assert sorted(p.name for p in output.iterdir())==['source.xml']
    assert not scratch.exists()



@pytest.mark.parametrize('command', ['mkdir','cp','rm'])
@pytest.mark.parametrize('original', [0,1,5])
def test_collection_or_cleanup_failure_preserves_prior_test_failure(tmp_path,command,original):
    script=(ROOT/'scripts/check-package.sh').read_text()
    cleanup=script.split('cleanup() {',1)[1].split('trap cleanup EXIT',1)[0]
    scratch=tmp_path/'private';scratch.mkdir()
    (scratch/'source.xml').write_text('<testsuite/>')
    fake=tmp_path/'bin';fake.mkdir()
    program=fake/command;program.write_text('#!/bin/sh\nexit 9\n');program.chmod(0o700)
    output=tmp_path/'results'
    body='cleanup() {'+cleanup+'\ntrap cleanup EXIT\nexit '+str(original)
    result=subprocess.run(['bash','-c',body],env={**os.environ,'PATH':str(fake)+':'+os.environ['PATH'],
        'scratch':str(scratch),'TEST_EVIDENCE_DIR':str(output)},capture_output=True)
    assert result.returncode==(original or 1)

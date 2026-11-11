"""Publication retry policy with fake executables; no registry or container calls."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT=Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('failures,message,expected,calls',[(0,'',0,1),(1,'unknown blob',0,2),(2,'unknown blob',0,3),(3,'unknown blob',44,3),(1,'denied: permission denied',44,1),(1,'other unknown blob failure',44,1)])
def test_push_retries_only_bounded_exact_unknown_blob(tmp_path,failures,message,expected,calls):
    docker=tmp_path/'docker'
    docker.write_text('#!'+sys.executable+'\n'+'''import json,os,pathlib,sys
p=pathlib.Path(os.environ['UNIT_PUSH_STATE'])
rows=json.loads(p.read_text()) if p.exists() else []
rows.append(sys.argv[1:]);p.write_text(json.dumps(rows))
if len(rows)<=int(os.environ['UNIT_PUSH_FAILURES']):
 print(os.environ['UNIT_PUSH_ERROR'],file=sys.stderr);sys.exit(44)
print('Pushed')
''')
    docker.chmod(0o700)
    sleep=tmp_path/'sleep';sleep.write_text('#!/bin/sh\nexit 0\n');sleep.chmod(0o700)
    state=tmp_path/'calls.json'
    env={**os.environ,'PATH':str(tmp_path)+os.pathsep+os.environ['PATH'],'UNIT_PUSH_STATE':str(state),'UNIT_PUSH_FAILURES':str(failures),'UNIT_PUSH_ERROR':message}
    result=subprocess.run(['bash',str(ROOT/'scripts/push-qualified-image.sh'),'ghcr.io/unit/runtime:test-qualified'],env=env,capture_output=True,text=True,timeout=5)
    assert result.returncode==expected,result.stderr
    assert json.loads(state.read_text())==[['push','ghcr.io/unit/runtime:test-qualified']]*calls

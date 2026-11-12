import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from user_service._startup_contract import fingerprint
from user_service.startup_identity import person_plan, external_key, StartupConflict

ROOT = Path(__file__).resolve().parents[1]


class StartupIdentityTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((Path(__file__).parent/'startup-identity.json').read_text())
        self.person = {'id':'00000000-0000-4000-8000-000000000110', 'email':self.config['email'],
            'sso_provider_id':external_key(self.config), 'is_active':True, 'deleted_at':None}

    def test_new_person_and_identical_replay(self):
        self.assertIsNone(person_plan(self.config, None, []))
        binding = {'mapping_sha256':fingerprint(self.config),'user_id':self.person['id']}
        self.assertEqual(person_plan(self.config,binding,[self.person]),self.person)

    def test_email_never_selects_or_rebinds_person(self):
        for key,value in [('sso_provider_id','other'), ('is_active',False), ('deleted_at','retired')]:
            person=dict(self.person, **{key:value})
            with self.subTest(key=key),self.assertRaises(StartupConflict): person_plan(self.config,None,[person])
            self.assertEqual(person[key],value)

    def test_duplicate_or_missing_person_and_mapping_conflicts(self):
        with self.assertRaises(StartupConflict): person_plan(self.config,None,[self.person,self.person])
        binding={'mapping_sha256':fingerprint(self.config),'user_id':self.person['id']}
        with self.assertRaises(StartupConflict): person_plan(self.config,binding,[])
        binding['mapping_sha256']='0'*64
        with self.assertRaises(StartupConflict): person_plan(self.config,binding,[self.person])

    def test_wrong_config_is_rejected_before_person_plan(self):
        for field in ('entra_tenant_id','entra_account_id','sea_public_key'):
            config=dict(self.config);config[field]=''
            with self.subTest(field=field),self.assertRaises(ValueError): person_plan(config,None,[])

    def test_vendored_contract_matches_recorded_source_bytes(self):
        source=ROOT/'src/user_service'
        record=json.loads((source/'startup_contract_source.json').read_text())
        self.assertEqual(record['revision'],'11695cd3211685c5aca3f716d0edbaa78ae306c2')
        self.assertEqual(hashlib.sha256((source/'_startup_contract.py').read_bytes()).hexdigest(),record['sha256'])

    def test_startup_endpoint_refuses_ordinary_and_disabled_callers(self):
        from user_service.startup_routes import authorize
        from fastapi import HTTPException
        from types import SimpleNamespace
        request=SimpleNamespace(headers={'authorization':'Bearer ordinary'})
        with patch.dict('os.environ',{'STARTUP_IDENTITY_ENABLED':'1','USER_STARTUP_TOKEN':'scoped'},clear=True):
            with self.assertRaises(HTTPException) as error: authorize(request,'USER_STARTUP_TOKEN')
            self.assertEqual(error.exception.status_code,401)
            request.headers['authorization']='Bearer scoped'
            authorize(request,'USER_STARTUP_TOKEN')
        with patch.dict('os.environ',{},clear=True):
            with self.assertRaises(HTTPException) as error: authorize(request,'USER_STARTUP_TOKEN')
            self.assertEqual(error.exception.status_code,503)

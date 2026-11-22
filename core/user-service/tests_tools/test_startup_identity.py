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
        self.person = {'id':'00000000-0000-4000-8000-000000000110', 'email':self.config['owner']['profile']['email'],
            'sso_provider_id':external_key(self.config), 'is_active':True, 'deleted_at':None}

    def test_new_person_and_identical_replay(self):
        self.assertIsNone(person_plan(self.config, None, []))
        binding = {'mapping_sha256':fingerprint(self.config),'user_id':self.person['id']}
        self.assertEqual(person_plan(self.config,binding,[self.person]),self.person)

    def test_email_never_selects_or_rebinds_person(self):
        for key,value in [('sso_provider_id','other'), ('is_active',False), ('deleted_at','retired'), ('keycloak_sub','s'*251)]:
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
        self.assertEqual(record['revision'],'158ef3d50092706c31fd92062588f122b3046b97')
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


class ScopeConfigurationTests(unittest.IsolatedAsyncioTestCase):
    async def test_mixed_tenant_mapping_refused_before_database_access(self):
        from user_service.startup_identity import prepare_scope
        from user_service._startup_contract import binding_fingerprint
        config=json.loads((Path(__file__).parent/'startup-identity.json').read_text())
        config['binding']['organizations']['fyberlabs']['tenant_id']='00000000-0000-4000-8000-000000009999'
        config['binding_sha256']=binding_fingerprint(config['binding'])
        with self.assertRaises(StartupConflict):await prepare_scope(None,config)

    async def test_first_fyberlabs_owner_gets_only_its_matching_host_binding(self):
        from unittest.mock import AsyncMock, MagicMock
        from uuid import UUID

        from user_service._startup_contract import binding_fingerprint
        from user_service.startup_identity import reconcile

        config = json.loads((Path(__file__).parent / 'startup-identity.json').read_text())
        binding = config['binding']
        owner = binding['organizations']['fyberlabs']
        binding['organizations'] = {'fyberlabs': {**owner, 'roles': ['owner']}}
        binding['platform_admin'] = {'spanopticon': False, 'hyperme.sh': False}
        binding['keycloak_admin'] = {'realm': 'controlplane', 'enabled': False}
        config['owner']['broker'] = {'issuer': 'https://auth.hyperme.sh/realms/controlplane',
                                     'audience': 'controlplane-frontend'}
        config['owner']['network_id'] = 'hyperme.sh'
        config['binding_sha256'] = binding_fingerprint(binding)
        tenant = UUID(config['owner']['tenant_id'])
        db = MagicMock()
        db.execute = AsyncMock()
        db.execute.return_value = MagicMock()
        db.execute.return_value.mappings.return_value.all.return_value = []
        db.scalar = AsyncMock(return_value=None)
        with patch('user_service.startup_identity.prepare_scope', return_value=tenant), \
                patch('user_service.startup_identity.one', side_effect=[None, None, None]):
            result = await reconcile(db, config)
        inserts = [call.args for call in db.execute.await_args_list
                   if 'INSERT INTO authority_host_owners' in str(call.args[0])]
        self.assertEqual(len(inserts), 1)
        self.assertEqual(str(inserts[0][1]['org']), owner['organization_id'])
        self.assertEqual(str(inserts[0][1]['user']), result['person_id'])
        self.assertEqual([org['slug'] for org in result['organizations']], ['fyberlabs'])

"""Synthetic execution reviews, route loss and session-context boundaries."""
import copy
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from atlas.execution import ExecutionContexts, ExecutionChanged, linux_route
from atlas.importers import ImportProblem
from atlas.store import Store
from atlas.web_tools import WebTools
from atlas.web_transport import Scope, fetch
from atlas.host_operations import command


class Routes:
    def __init__(self):
        self.interface='tun0';self.source='10.10.14.2';self.up=True
    def __call__(self,args):
        if args[:2]==['route','get']:
            return [{'dev':self.interface,'prefsrc':self.source}]
        return [{'ifname':self.interface,'flags':['UP'] if self.up else []}]


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.store=Store(Path(self.temp.name)/'atlas.sqlite3')
        self.workspace=self.store.create('Synthetic execution','Documentation addresses only')['id']
        self.routes=Routes();self.clock=[100.0]
        self.manager=ExecutionContexts(self.store,clock=lambda:self.clock[0],platform_name='linux',route_runner=self.routes)
        self.config={'url':'http://192.0.2.20/','authorized':True,'path_prefix':'/',
                     'execution_kind':'request','execution_context':{'host_id':self.manager.host['id'],'interface':'tun0'}}

    def reviewed(self,changes=None):
        config={**self.config,**(changes or {})}
        proof=self.manager.preview(self.workspace,config)
        return {**config,'context_token':proof['token']},proof

    def test_installation_identity_is_stable_opaque_and_protected(self):
        following=ExecutionContexts(self.store,platform_name='linux',route_runner=self.routes)
        self.assertEqual(self.manager.host['id'],following.host['id'])
        saved=json.loads((Path(self.temp.name)/'execution-host.json').read_text())
        self.assertEqual(set(saved),{'schema','id'})
        self.assertNotIn('name',saved)
        self.assertEqual(self.manager.describe()['default_interface'],'tun0')
        other=Store(Path(self.temp.name)/'different'/'atlas.sqlite3')
        self.assertNotEqual(self.manager.host['id'],ExecutionContexts(other).host['id'])

    def test_review_is_dns_only_and_token_is_consumed_once(self):
        with patch('socket.create_connection',side_effect=AssertionError('Preview contacted target')):
            config,proof=self.reviewed()
        self.assertEqual(proof['routes'],[{'target':'192.0.2.20','interface':'tun0','source':'10.10.14.2'}])
        self.manager.bind(self.workspace,Scope(config),config)
        with self.assertRaises(ExecutionChanged):self.manager.bind(self.workspace,Scope(config),config)
        self.assertEqual(self.store.web_runs(self.workspace),[])

    def test_host_route_source_and_interface_up_fail_closed(self):
        for attribute,value in (('interface','eth0'),('source','not-an-address'),('up',False)):
            original=getattr(self.routes,attribute);setattr(self.routes,attribute,value)
            with self.subTest(attribute=attribute),self.assertRaises(ExecutionChanged):self.reviewed()
            setattr(self.routes,attribute,original)
        with self.assertRaises(ExecutionChanged):
            self.manager.preview(self.workspace,{**self.config,'execution_context':{'host_id':'0'*32,'interface':'tun0'}})
        self.assertEqual(self.store.web_runs(self.workspace),[])

    def test_review_expiry_workspace_owner_and_configuration_binding(self):
        config,_=self.reviewed();self.clock[0]+=61
        with self.assertRaises(ExecutionChanged):self.manager.bind(self.workspace,Scope(config),config)
        other=self.store.create('Other synthetic scope','No shared authority')['id']
        for changes,workspace in (({},other),({'_execution_owner':'different-operator'},self.workspace),
                                  ({'max_requests':2},self.workspace),({'method':'POST','body':'synthetic-body'},self.workspace),
                                  ({'investigation_revision':2},self.workspace),({'execution_kind':'scanner'},self.workspace)):
            config,_=self.reviewed()
            altered={**config,**changes}
            with self.subTest(changes=changes,workspace=workspace),self.assertRaises(ExecutionChanged):
                self.manager.bind(workspace,Scope(altered),altered)

    def test_source_change_after_review_blocks_socket_without_target_request(self):
        config,_=self.reviewed();scope=Scope(config)
        self.manager.bind(self.workspace,scope,config)
        self.routes.source='10.10.14.3'
        with patch('socket.create_connection') as connect,self.assertRaises(ExecutionChanged):fetch(scope,self.config['url'])
        connect.assert_not_called()

    def test_gateway_and_recreated_interface_changes_invalidate_context(self):
        state={'gateway':'10.10.14.1','ifindex':7}
        def runner(args):
            if args[:2]==['route','get']:
                return [{'dev':'tun0','prefsrc':'10.10.14.2','gateway':state['gateway'],'table':'main'}]
            return [{'ifname':'tun0','flags':['UP'],'ifindex':state['ifindex']}]
        self.manager.route_runner=runner
        for field,new in (('gateway','10.10.14.9'),('ifindex',8)):
            config,_=self.reviewed();scope=Scope(config)
            self.manager.bind(self.workspace,scope,config)
            previous=state[field];state[field]=new
            with self.subTest(field=field),self.assertRaises(ExecutionChanged):scope.check_execution()
            state[field]=previous

    def test_native_socket_requires_device_and_measured_source_binding(self):
        config,_=self.reviewed();scope=Scope(config)
        self.manager.bind(self.workspace,scope,config)
        sock=Mock()
        with patch('socket.socket',return_value=sock):scope.connect('192.0.2.20',80,2)
        sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET,getattr(socket,'SO_BINDTODEVICE',25),b'tun0\0')
        sock.bind.assert_called_once_with(('10.10.14.2',0))
        sock.connect.assert_called_once_with(('192.0.2.20',80))
        refused=Mock();refused.setsockopt.side_effect=PermissionError('synthetic permission failure')
        with patch('socket.socket',return_value=refused),patch('socket.create_connection') as fallback,self.assertRaises(ExecutionChanged):
            scope.connect('192.0.2.20',80,2)
        refused.connect.assert_not_called();refused.close.assert_called_once();fallback.assert_not_called()

    def test_system_policy_on_non_linux_does_not_claim_vpn(self):
        manager=ExecutionContexts(self.store,platform_name='win32')
        config={**self.config,'execution_context':{'host_id':manager.host['id'],'interface':'system'}}
        result=manager.preview(self.workspace,config)
        self.assertEqual(result['routes'][0]['source'],None)
        self.assertIn('no VPN',result['policy'])
        with self.assertRaises(ExecutionChanged):manager.preview(self.workspace,self.config)

    def test_owner_logout_revokes_reviews_and_running_guards(self):
        config,_=self.reviewed({'_execution_owner':'synthetic-owner'})
        scope=Scope(config);self.manager.bind(self.workspace,scope,config)
        pending,_=self.reviewed({'_execution_owner':'synthetic-owner'})
        self.manager.forget_owner('synthetic-owner')
        with self.assertRaises(ExecutionChanged):scope.check_execution()
        with self.assertRaises(ExecutionChanged):self.manager.bind(self.workspace,Scope(pending),pending)

    def test_preview_secrets_and_token_never_enter_persistent_records(self):
        config,proof=self.reviewed({'headers':'Authorization: Bearer SYNTHETIC-SECRET','body':'SYNTHETIC-BODY'})
        scope=Scope(config);retained=self.manager.bind(self.workspace,scope,config)
        self.store.start_web_run(self.workspace,'request',{'execution_context':retained})
        persisted=json.dumps(self.store.get(self.workspace))
        for private in ('SYNTHETIC-SECRET','SYNTHETIC-BODY',proof['token']):self.assertNotIn(private,persisted)
        self.assertNotIn('headers',scope.execution_guard.config)
        self.assertNotIn('body',scope.execution_guard.config)

    def test_authenticated_session_is_bound_to_scope_role_host_and_operator(self):
        tools=WebTools(self.store,8765)
        config={**self.config,'_execution_owner':'operator-a','access_role':'ordinary user','access_reference':'ref:user-a',
                'auth':{'check_url':'http://192.0.2.20/guard','success_text':'SYNTHETIC_SIGNED_IN','headers':'Cookie: session=SYNTHETIC_COOKIE'}}
        key=tools.save_session(self.workspace,config)['id']
        selected={**config,'session_id':key};selected.pop('auth')
        self.assertIn('auth',tools.session_config(self.workspace,selected))
        changes=({'url':'http://192.0.2.21/'},{'path_prefix':'/other','url':'http://192.0.2.20/other'},
                 {'access_role':'administrator'},{'access_reference':'ref:user-b'},{'_execution_owner':'operator-b'},
                 {'execution_context':{'host_id':self.manager.host['id'],'interface':'system'}})
        for change in changes:
            with self.subTest(change=change),self.assertRaises(ImportProblem):tools.session_config(self.workspace,{**selected,**change})
        self.assertEqual(tools.session_list(self.workspace,'operator-b'),[])
        with self.assertRaises(ImportProblem):tools.forget_session(self.workspace,key,'operator-b')
        tools.forget_owner('operator-a')
        with self.assertRaises(ImportProblem):tools.session_config(self.workspace,selected)
        self.assertNotIn('SYNTHETIC_COOKIE',json.dumps(self.store.get(self.workspace)))

    def test_session_expiry_blocks_reviewed_request_before_connection(self):
        tools=WebTools(self.store,8765)
        config={**self.config,'auth':{'check_url':'http://192.0.2.20/guard','success_text':'SIGNED_IN','headers':'Cookie: session=SYNTHETIC'}}
        key=tools.save_session(self.workspace,config)['id']
        tools.execution=self.manager;self.manager.session_validator=tools.session_config
        config={**self.config,'session_id':key}
        review=self.manager.preview(self.workspace,config);config['context_token']=review['token']
        scope=Scope(config);self.manager.bind(self.workspace,scope,config)
        tools.sessions[key]['expires']=0
        with patch('socket.create_connection') as connect,self.assertRaises(ExecutionChanged):fetch(scope,config['url'])
        connect.assert_not_called()

    def test_route_loss_retains_first_capture_as_partial_not_negative(self):
        tools=WebTools(self.store,8765);tools.execution=self.manager
        self.manager.session_validator=tools.session_config
        config={**self.config,'execution_kind':'crawl','paths':['/second'],'delay_ms':250,'max_requests':3,'max_seconds':5,'max_depth':0}
        review=self.manager.preview(self.workspace,config);config['context_token']=review['token']
        def response(scope,url,*args,**kwargs):
            scope.check_execution()
            event={'id':'synthetic-execution-response','url':url,'captured_at':'2026-01-01T00:00:00+00:00','request':{'method':'GET','headers':[],'body':''},'response':{'status':200,'headers':[],'body':'','bytes':0},'links':[],'parameters':[]}
            self.routes.interface='eth0'
            return event
        with patch('atlas.web_tools.fetch',side_effect=response):
            run=tools.start(self.workspace,'crawl',config)
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                retained=self.store.web_runs(self.workspace)[0]
                if retained['state'] not in ('queued','running'):break
                time.sleep(.02)
        self.assertEqual(retained['id'],run['id']);self.assertEqual(retained['state'],'partial')
        self.assertEqual(retained['requests'],1);self.assertEqual(len(retained['import_ids']),1)
        self.assertEqual(self.store.get(self.workspace)['findings'],[])
        self.assertIn('route',retained['reason'])

    def test_typed_operations_request_measured_source_and_explicit_curl_interface(self):
        nmap={'profile':'tcp-discovery','target':'192.0.2.20','timeout':30,'interface':'tun0'}
        argv=command(nmap,'fixture.xml','10.10.14.2')
        self.assertEqual(argv[argv.index('-S')+1],'10.10.14.2')
        self.assertEqual(argv[argv.index('-e')+1],'tun0')
        curl=command({**nmap,'profile':'http-headers','url':'https://192.0.2.20/'},'fixture.txt','10.10.14.2')
        self.assertEqual(curl[curl.index('--interface')+1],'if!tun0')

    def test_websocket_send_context_loss_immediately_closes_partial_and_preserves_evidence(self):
        from atlas.web_socket import WebSocketSession
        tools=WebTools(self.store,8765)
        artifact=self.store.import_file(self.workspace,json.dumps({'format':'atlas-evidence/1',
            'entities':[{'key':'fixture','label':'Synthetic socket peer'}],
            'observations':[{'subject':'fixture','kind':'Prior socket evidence','status':'observed','basis':'manual','value':'Synthetic retained observation'}]}),
            'synthetic-socket-evidence.json','atlas',{})['import']['id']
        run=self.store.start_web_run(self.workspace,'websocket',{})
        self.store.update_web_run(self.workspace,run['id'],state='running',import_ids=[artifact],requests=1)
        session=WebSocketSession.__new__(WebSocketSession)
        session.tools=tools;session.workspace=self.workspace;session.run=run;session.lock=threading.RLock()
        session.closed=False;session.count=1;session.limit=10;session.message_count=1;session.auth=None;session.config={}
        session.messages=[];session.saved_messages={};session.error=None;session.client=Mock()
        session.client.send.side_effect=ExecutionChanged('Synthetic execution host changed; no fallback.')
        with self.assertRaises(ExecutionChanged):session.send('Synthetic frame')
        retained=next(row for row in self.store.web_runs(self.workspace) if row['id']==run['id'])
        self.assertTrue(session.closed);session.client.close.assert_called_once()
        self.assertEqual(retained['state'],'partial');self.assertEqual(retained['import_ids'],[artifact])
        self.assertIn('incomplete',retained['reason']);self.assertEqual(len(self.store.get(self.workspace)['observations']),1)


if __name__=='__main__':unittest.main()

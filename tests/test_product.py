import copy
import hashlib
from http.client import HTTPConnection
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest.mock import patch

from atlas.importers import ImportProblem, parse, MAX_BYTES
from atlas.store import Store, html_report
from atlas.server import AtlasServer

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
TEST_TEMP = FIXTURES.parent / "work" / "test-temp"
TEST_TEMP.mkdir(parents=True, exist_ok=True)


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


class ImportTests(unittest.TestCase):
    def test_all_supported_fixture_semantics(self):
        expected = {"nmap.xml": ("nmap", 2, "service association", 3), "scan.nessus": ("nessus", 1, "scanner report", 1),
                    "nuclei.jsonl": ("nuclei", 1, "template match", 1), "httpx.jsonl": ("httpx", 1, "web response", 1),
                    "device.json": ("linux-ip", 2, "interface", 2), "manual.json": ("atlas", 2, "configured route", 1)}
        for filename, (source, _, kind, count) in expected.items():
            with self.subTest(source=source):
                b = parse(fixture(filename))
                self.assertEqual(b.source, source)
                self.assertEqual(sum(o["kind"] == kind for o in b.observations), count)
                self.assertTrue(all(o["location"] and o["vantage"] == "unknown" for o in b.observations))
        b = parse(fixture("nmap.xml"))
        self.assertEqual(sum(e["kind"] == "device" for e in b.entities), 2)
        self.assertEqual(next(o for o in b.observations if o["kind"] == "OS fingerprint")["status"], "inferred")
        self.assertEqual([o["value"]["state"] for o in b.observations if o["kind"] == "service association"], ["open", "filtered", "open"])
        self.assertEqual(sum(o["kind"] == "routed path sequence" for o in b.observations), 1)
        b = parse(fixture("device.json"))
        self.assertEqual(sum(o["kind"] == "operational route" for o in b.observations), 2)
        self.assertEqual(sum(o["kind"] == "local neighbor" for o in b.observations), 1)
        self.assertTrue(all(o["basis"] == "operational" for o in b.observations))
    def test_nmap_forced_up_is_not_observed_discovery(self):
        text='<nmaprun><host><status state="up" reason="user-set"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>'
        b=parse(text,"nmap")
        host=next(o for o in b.observations if o['kind']=='host state')
        port=next(o for o in b.observations if o['kind']=='service association')
        self.assertEqual(host['status'],'unknown');self.assertEqual(host['basis'],'configured');self.assertEqual(host['value']['state'],'up')
        self.assertEqual(port['status'],'observed');self.assertEqual(port['value']['state'],'open')
        self.assertTrue(any('forced' in w for w in b.warnings))
    def test_missing_nmap_discovery_status_stays_unknown(self):
        b=parse('<nmaprun><host/></nmaprun>','nmap')
        self.assertEqual(b.observations[0]['status'],'unknown')
    def test_forced_up_with_only_filtered_ports_is_not_confirmed_reachable(self):
        text='<nmaprun><host><status state="up" reason="user-set"/><ports><port protocol="tcp" portid="22"><state state="filtered" reason="no-response"/></port></ports></host></nmaprun>'
        b=parse(text,'nmap')
        self.assertEqual(next(o for o in b.observations if o['kind']=='host state')['status'],'unknown')
        self.assertEqual(next(o for o in b.observations if o['kind']=='service association')['value']['state'],'filtered')
        self.assertFalse(any(o['kind']=='tested reachability' for o in b.observations))

    def test_no_network_or_command_execution(self):
        with patch("socket.create_connection", side_effect=AssertionError("Import contacted network")), patch("subprocess.run", side_effect=AssertionError("Import executed command")):
            for name in ("nmap.xml", "scan.nessus", "nuclei.jsonl", "httpx.jsonl", "device.json", "manual.json"):
                parse(fixture(name))
            parse('<?xml-stylesheet href="https://example.test/run"?><nmaprun><host><status state="up"/></host></nmaprun>', "nmap")

    def test_entity_and_external_dtd_rejected(self):
        for declaration in ('<!DOCTYPE nmaprun SYSTEM "https://example.test/x">', '<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///secrets">]>', '<!ENTITY x "payload">'):
            with self.subTest(declaration=declaration), self.assertRaises(ImportProblem):
                parse(declaration + '<nmaprun><host/></nmaprun>', "nmap")

    def test_hostile_and_malformed_json_xml(self):
        cases = [("<nmaprun><host>", "nmap"), ('{"format":"atlas-evidence/1","format":"linux-ip/1"}', "atlas"),
                 ('{"format":"atlas-evidence/1","entities":NaN}', "atlas"), ('[1,2,3]', "nuclei"),
                 ('{"url":null}', "httpx"), ('{"info":{},"host":"x"}', "nuclei"), ('{}', "auto"),
                 ('<NessusClientData><Report/></NessusClientData>', "nessus"), ('{"format":"atlas-evidence/1","entities":{}}', "atlas")]
        for text, source in cases:
            with self.subTest(text=text), self.assertRaises(ImportProblem):
                parse(text, source)

    def test_resource_bounds(self):
        with self.assertRaises(ImportProblem):
            parse("x" * (MAX_BYTES + 1), "nmap")
        with self.assertRaises(ImportProblem):
            parse("<nmaprun>" + "<x>"*40 + "</x>"*40 + "</nmaprun>", "nmap")
        with self.assertRaises(ImportProblem):
            parse("["*40 + "0" + "]"*40, "nuclei")

    def test_nuclei_json_array_and_single_object(self):
        event=json.loads(fixture("nuclei.jsonl"))
        self.assertEqual(len(parse(json.dumps([event,event]), "nuclei").findings),2)
        self.assertEqual(parse(json.dumps(event), "nuclei").findings[0]["validation"],"scanner-reported")
    def test_current_httpx_fields_and_legacy_aliases(self):
        current=json.loads(fixture("httpx.jsonl"));b=parse(json.dumps(current),"httpx")
        self.assertEqual(next(o for o in b.observations if o["kind"]=="web response")["value"]["status_code"],200)
        self.assertEqual(b.entities[0]["addresses"],["192.0.2.20"])
        current["status-code"]=current.pop("status_code");current["content-length"]=current.pop("content_length")
        self.assertEqual(next(o for o in parse(json.dumps(current),"httpx").observations if o["kind"]=="web response")["value"]["content_length"],1024)
    def test_utf8_bom_import_retains_original_digest(self):
        text='\ufeff'+fixture("manual.json")
        self.assertEqual(parse(text,"atlas").source,"atlas")
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as folder:
            store=Store(Path(folder)/'bom.sqlite3');w=store.create('BOM synthetic','synthetic')
            imported=store.import_file(w['id'],text,'bom.json','atlas',{})['import']
            self.assertEqual(imported['sha256'],hashlib.sha256(text.encode('utf-8')).hexdigest())

    def test_metadata_unknown_and_override(self):
        b=parse(fixture("httpx.jsonl"),context={"vantage":"Desk", "collected_at":"2020-01-01T10:00:00Z"})
        self.assertEqual(b.observations[0]["vantage"],"Desk")
        self.assertTrue(b.observations[0]["collected_at"].startswith("2026-10-12"))
        event=json.loads(fixture("httpx.jsonl"));del event["timestamp"]
        self.assertIsNone(parse(json.dumps(event),"httpx").observations[0]["collected_at"])

    def test_secret_fields_scrubbed(self):
        data=json.loads(fixture("manual.json"));data["observations"][0]["value"]={"password":"synthetic-secret", "banner":"token=synthetic-token"}
        b=parse(json.dumps(data),"atlas",{"vantage":"password=synthetic-vantage"})
        saved=json.dumps(b.observations)
        self.assertNotIn("synthetic-secret",saved);self.assertNotIn("synthetic-token",saved);self.assertNotIn("synthetic-vantage",saved)

    def test_manual_references_and_duplicate_keys(self):
        for mutate in (lambda d:d["observations"][0].update(subject="missing"),lambda d:d["entities"].append(d["entities"][0]),lambda d:d["observations"][0].update(status="confirmed")):
            data=json.loads(fixture("manual.json"));mutate(data)
            with self.assertRaises(ImportProblem):parse(json.dumps(data),"atlas")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=TEST_TEMP);self.path=Path(self.temp.name)/"atlas.sqlite3";self.store=Store(self.path)
        self.workspace=self.store.create("Synthetic engagement","Authorized synthetic scope")
    def tearDown(self):self.temp.cleanup()
    def add(self,name="nmap.xml",context=None):
        return self.store.import_file(self.workspace["id"],fixture(name),name,"auto",context or {"vantage":"Synthetic assessor"})
    def test_repeat_import_is_noop_but_metadata_changes_retained(self):
        first=self.add();second=self.add();self.assertFalse(first["duplicate"]);self.assertTrue(second["duplicate"])
        self.assertEqual(len(first["workspace"]["observations"]),len(second["workspace"]["observations"]))
        self.add(context={"vantage":"Other position"});self.assertEqual(len(self.store.get(self.workspace["id"])["imports"]),2)
    def test_changed_file_appends_history(self):
        self.add();before=self.store.get(self.workspace["id"])
        self.store.import_file(self.workspace["id"],fixture("nmap.xml").replace('state="up"','state="down"'),"changed.xml","nmap",{})
        self.assertEqual(len(self.store.get(self.workspace["id"])["imports"]),2)
        self.assertEqual(before["observations"],self.store.get(self.workspace["id"])["observations"][:len(before["observations"])])
    def test_old_adapter_reimport_retains_history_and_corrects_derivation(self):
        text='<nmaprun><host><status state="up" reason="user-set"/><ports><port protocol="tcp" portid="22"><state state="filtered" reason="no-response"/></port></ports></host></nmaprun>'
        context={"vantage":"Synthetic assessor"}
        legacy=parse(text,"nmap",context)
        host=next(o for o in legacy.observations if o["kind"]=="host state")
        # Persist the v1 contract: it treated the scanner-forced host tag as observed.
        host.update(status="observed",basis="active test",value={"state":"up","reason":"user-set"})
        legacy.warnings=[]
        with patch("atlas.store.VERSION","1"),patch("atlas.store.parse",return_value=legacy):
            old=self.store.import_file(self.workspace["id"],text,"old.xml","nmap",context)
        self.store.record(self.workspace["id"],{"kind":"note","title":"Historical interpretation","details":"Retain source evidence","evidence_refs":old["workspace"]["observations"][0]["id"],"status":"open"})
        before=self.store.get(self.workspace["id"])
        upgraded=Store(self.path)
        new=upgraded.import_file(self.workspace["id"],text,"old.xml","nmap",context)
        self.assertFalse(new["duplicate"])
        self.assertEqual([i["adapter_version"] for i in new["workspace"]["imports"]],["1","2"])
        self.assertEqual(old["import"]["sha256"],new["import"]["sha256"])
        self.assertNotEqual(old["import"]["fingerprint"],new["import"]["fingerprint"])
        after=upgraded.get(self.workspace["id"])
        self.assertEqual(after["observations"][:len(before["observations"])],before["observations"])
        self.assertEqual(after["history"][:-1],before["history"])
        self.assertEqual(after["records"],before["records"])
        corrected=next(o for o in after["observations"] if o["import_id"]==new["import"]["id"] and o["kind"]=="host state")
        self.assertEqual((corrected["status"],corrected["basis"]),("unknown","configured"))
        self.assertEqual(corrected["value"]["reason"],"user-set")
        self.assertTrue(upgraded.import_file(self.workspace["id"],text,"old.xml","nmap",context)["duplicate"])
    def test_failed_import_leaves_workspace_unchanged(self):
        self.add();before=self.store.get(self.workspace["id"])
        with self.assertRaises(ImportProblem):self.store.import_file(self.workspace["id"],"<bad", "bad.xml","nmap",{})
        self.assertEqual(self.store.get(self.workspace["id"]),before)
    def test_persistence_after_reopening(self):
        self.add();self.assertEqual(Store(self.path).get(self.workspace["id"]),self.store.get(self.workspace["id"]))
    def test_no_automatic_name_ip_merge_and_reversible_link(self):
        self.add();w=self.add("manual.json")["workspace"]
        self.assertEqual(len(w["entities"]),len(w["nodes"]));self.assertTrue(w["candidates"])
        routers={e["id"] for e in w["entities"] if e["label"]=="Synthetic router"}
        pair=next(c for c in w["candidates"] if c["left"] in routers and c["right"] in routers)
        linked=self.store.reconcile(w["id"],pair["left"],pair["right"],"Synthetic sources describe same router; retain older state.")
        self.assertEqual(len(linked["nodes"]),len(w["nodes"])-1);self.assertTrue(linked["conflicts"])
        undone=self.store.undo(w["id"],linked["decisions"][-1]["id"])
        self.assertEqual(len(undone["nodes"]),len(w["nodes"]));self.assertEqual(undone["observations"],w["observations"])
    def test_overlapping_namespaces_and_ip_reuse(self):
        self.add(context={"namespace":"A"});self.add(context={"namespace":"B"})
        w=Store.view(self.store.get(self.workspace["id"]));self.assertEqual(len(w["nodes"]),len(w["entities"]))
        self.assertFalse(any(next(e for e in w["entities"] if e["id"]==c["left"])["namespace"] != next(e for e in w["entities"] if e["id"]==c["right"])["namespace"] for c in w["candidates"]))
    def test_records_review_and_history(self):
        self.add();w=self.store.record(self.workspace["id"],{"kind":"access","title":"Synthetic authenticated access","details":"Role verified, no credentials retained","evidence_refs":"synthetic observation","status":"open"})
        w=self.store.update_record(w["id"],{"id":w["records"][0]["id"],"status":"complete","note":"Synthetic validation and cleanup recorded"})
        self.assertEqual(w["records"][0]["status"],"complete");self.assertEqual(w["history"][-1]["action"],"record review")
    def test_finding_review_does_not_promote_source_assertion(self):
        w=self.add("scan.nessus")["workspace"]
        w=self.store.update_record(w["id"],{"id":w["findings"][0]["id"],"collection":"findings","status":"complete","note":"Requires separate impact evidence"})
        self.assertEqual(w["findings"][0]["validation"],"scanner-reported")
    def test_scoped_exports_and_default_redactions(self):
        self.add(context={"vantage":"Synthetic assessor","source_version":"Private synthetic inventory label"});self.add("device.json")
        w=self.store.export(self.workspace["id"]);text=json.dumps(w)
        self.assertNotIn("192.0.2.20",text);self.assertNotIn("portal.example.test",text);self.assertNotIn("Synthetic assessor",text)
        self.assertNotIn("Private synthetic inventory label",text)
        self.assertTrue(w["export"]["redactions"]);self.assertTrue(w["imports"][0]["sha256"])
        full=self.store.export(self.workspace["id"],True,kind="local neighbor")
        self.assertEqual(len(full["observations"]),1);self.assertEqual(full["observations"][0]["kind"],"local neighbor")
        self.assertIn("192.0.2.20",json.dumps(full));self.assertIn("Evidence and typed relationships",html_report(full))
    def test_html_escapes_hostile_text(self):
        w=self.add()["workspace"];w["name"]='<script>alert(1)</script>'
        report=html_report({**w,"export":{"at":"now","limitations":"source claim","selection":{},"redactions":[]}})
        self.assertNotIn('<script>',report);self.assertIn('&lt;script&gt;',report)
    def test_deletion_and_confirmation(self):
        self.add()
        with self.assertRaises(ImportProblem):self.store.delete(self.workspace["id"],"wrong")
        self.store.delete(self.workspace["id"],self.workspace["name"]);self.assertEqual(self.store.list(),[])
    def test_invalid_decisions_and_records(self):
        for fn in (lambda:self.store.reconcile(self.workspace["id"],"a","b","why"),lambda:self.store.record(self.workspace["id"],{"kind":"exec","title":"bad"})):
            with self.assertRaises(ImportProblem):fn()
    def test_incompatible_types_cannot_merge(self):
        w=self.add()["workspace"]
        device=next(e for e in w["entities"] if e["kind"]=="device");service=next(e for e in w["entities"] if e["kind"]=="service")
        with self.assertRaises(ImportProblem):self.store.reconcile(w["id"],device["id"],service["id"],"Incorrect cross-type merge")
    def test_newer_schema_is_preserved_and_rejected(self):
        con=sqlite3.connect(self.path);con.execute("PRAGMA user_version=99");con.close()
        with self.assertRaises(ImportProblem):Store(self.path)
        con=sqlite3.connect(self.path);self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0],99);con.close()
    def test_parallel_repeat_import_has_one_effect(self):
        results=[]
        threads=[threading.Thread(target=lambda:results.append(self.add())) for _ in range(6)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual(len(results),6);self.assertEqual(sum(not r["duplicate"] for r in results),1)
    def test_suggestion_work_is_bounded_for_repeated_identifiers(self):
        data={"format":"atlas-evidence/1","entities":[{"key":str(i),"label":"Shared synthetic name","addresses":["192.0.2.1"]} for i in range(100)],"observations":[]}
        result=self.store.import_file(self.workspace["id"],json.dumps(data),"repeated.json","atlas",{})["workspace"]
        self.assertEqual(len(result["candidates"]),200);self.assertTrue(result["candidates_limited"]);self.assertEqual(len(result["nodes"]),100)


class CaptureContractTests(unittest.TestCase):
    def test_explicit_helper_fixed_readonly_commands_and_no_overwrite(self):
        from tools import capture_linux
        bundle=json.loads(fixture("device.json"))
        outputs=["iproute2 synthetic",json.dumps(bundle["addresses"]),json.dumps(bundle["routes"]),json.dumps(bundle["neighbors"])]
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as folder:
            destination=Path(folder)/"new.json"
            with patch("sys.argv",["capture_linux.py",str(destination)]),patch("subprocess.run",side_effect=[SimpleNamespace(stdout=x) for x in outputs]) as run:
                capture_linux.main()
            self.assertEqual([call.args[0] for call in run.call_args_list],[["ip","-V"],["ip","-j","address","show"],["ip","-j","route","show","table","all"],["ip","-j","neigh","show"]])
            self.assertTrue(all(call.kwargs["timeout"]==10 for call in run.call_args_list))
            self.assertEqual(parse(destination.read_text(),"linux-ip").source,"linux-ip")
            with patch("sys.argv",["capture_linux.py",str(destination)]),patch("subprocess.run",side_effect=[SimpleNamespace(stdout=x) for x in outputs]),self.assertRaises(FileExistsError):capture_linux.main()


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=TEST_TEMP);self.store=Store(Path(self.temp.name)/"data.sqlite3")
        self.server=AtlasServer(("127.0.0.1",0),self.store);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.port=self.server.server_address[1]
        status,headers,_=self.request("GET","/");self.cookie=headers["set-cookie"].split(";")[0]
        _,_,session=self.request("GET","/api/session",cookie=True);self.nonce=session["nonce"]
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join();self.temp.cleanup()
    def request(self,method,path,data=None,cookie=False,auth=False,extra=None):
        c=HTTPConnection("127.0.0.1",self.port,timeout=5);headers={"Content-Type":"application/json"}
        if cookie:headers["Cookie"]=self.cookie
        if auth:headers.update({"X-Atlas-Nonce":self.nonce,"Origin":f"http://127.0.0.1:{self.port}"})
        headers.update(extra or {});c.request(method,path,json.dumps(data) if data is not None else None,headers);r=c.getresponse();body=r.read();status=r.status;head={k.lower():v for k,v in r.getheaders()};c.close()
        return status,head,json.loads(body) if head.get("content-type","").startswith("application/json") else body.decode()
    def test_session_origin_host_and_path_boundaries(self):
        self.assertEqual(self.request("GET","/api/workspaces")[0],403)
        self.assertEqual(self.request("POST","/api/create",{"name":"x"},cookie=True)[0],403)
        self.assertEqual(self.request("POST","/api/create",{"name":"x"},cookie=True,auth=True,extra={"Origin":"https://evil.test"})[0],403)
        self.assertEqual(self.request("GET","/",extra={"Host":f"evil.test:{self.port}"})[0],403)
        self.assertEqual(self.request("GET","/../../SECURITY.md",cookie=True)[0],404)
    def test_complete_api_workflow(self):
        status,_,w=self.request("POST","/api/create",{"name":"API synthetic","scope":"synthetic"},cookie=True,auth=True);self.assertEqual(status,200)
        payload={"workspace":w["id"],"content":fixture("nmap.xml"),"filename":"nmap.xml","source":"nmap","context":{"vantage":"API synthetic"}}
        self.assertEqual(self.request("POST","/api/preview",payload,cookie=True,auth=True)[0],200)
        status,_,result=self.request("POST","/api/import",payload,cookie=True,auth=True);self.assertEqual(status,200);self.assertTrue(result["workspace"]["edges"])
        status,_,report=self.request("POST","/api/export",{"workspace":w["id"],"format":"html"},cookie=True,auth=True);self.assertEqual(status,200);self.assertIn("Sources and provenance",report)
        status,_,_=self.request("POST","/api/delete",{"workspace":w["id"],"confirmation":"API synthetic"},cookie=True,auth=True);self.assertEqual(status,200)
    def test_headers_and_invalid_input(self):
        _,headers,_=self.request("GET","/");self.assertIn("frame-ancestors 'none'",headers["content-security-policy"]);self.assertIn("HttpOnly",headers["set-cookie"])
        status,_,_=self.request("POST","/api/preview",{"content":"<broken","source":"nmap"},cookie=True,auth=True);self.assertEqual(status,400)
    def test_native_request_auth_scope_and_workspace_boundaries(self):
        from test_web_tools import fixture_server
        target=fixture_server();url=f'http://127.0.0.1:{target.server_address[1]}/'
        try:
            w=self.store.create('Native API synthetic','Owned local fixture')
            payload={'workspace':w['id'],'config':{'url':url,'authorized':True}}
            self.assertEqual(self.request('POST','/api/web/request',payload,cookie=True)[0],403)
            self.assertEqual(self.request('POST','/api/web/request',payload,cookie=True,auth=True,extra={'Origin':'https://evil.test'})[0],403)
            self.assertEqual(target.seen,[])
            rejected={**payload,'config':{**payload['config'],'request_url':'http://127.0.0.1:1/escape'}}
            self.assertEqual(self.request('POST','/api/web/request',rejected,cookie=True,auth=True)[0],400);self.assertEqual(target.seen,[])
            status,_,capture=self.request('POST','/api/web/request',payload,cookie=True,auth=True);self.assertEqual(status,200);self.assertEqual(target.seen,['/'])
            other=self.store.create('Other native','Owned fixture')
            self.assertEqual(self.request('POST','/api/web/compare',{'workspace':other['id'],'left':capture['capture_id'],'right':capture['capture_id']},cookie=True,auth=True)[0],400)
            self.assertEqual(self.request('GET','/api/web/status?workspace='+w['id'])[0],403)
        finally:target.shutdown();target.server_close()


if __name__=="__main__":unittest.main()

"""Atomic local SQLite persistence and reversible identity decisions."""
import copy
from contextlib import contextmanager
import datetime as dt
import hashlib
import html
import json
from pathlib import Path
import sqlite3
import threading
import uuid

from .importers import ImportProblem, clean, parse, VERSION


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def uid():
    return uuid.uuid4().hex


def required_text(value, field, limit=1000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ImportProblem(f"{field} must contain 1–{limit} characters.")
    return clean(value.strip())


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        with self.connect() as con:
            version=con.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2):
                raise ImportProblem("Unsupported database schema version. Preserve this data folder and use its compatible application version.")
            if version==1:
                backup=self.path.with_name(self.path.stem+'-before-schema2-'+uid()+'.sqlite3')
                with backup.open('xb'):pass
                destination=sqlite3.connect(backup)
                try:con.backup(destination)
                finally:destination.close()
            con.execute("CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, body TEXT NOT NULL)")
            con.execute("PRAGMA user_version=2")
            # Interrupted live jobs are not silently resumed after a server restart.
            for key,body in con.execute('SELECT id,body FROM workspaces').fetchall():
                w=json.loads(body);changed=False
                for run in w.get('web_runs',[]):
                    if run['state'] in ('queued','running'):
                        run.update(state='interrupted',ended_at=now(),reason='Application restarted; retained partial evidence.');changed=True
                if changed:con.execute('UPDATE workspaces SET body=? WHERE id=?',(json.dumps(w,ensure_ascii=False),key))

    @contextmanager
    def connect(self):
        con = sqlite3.connect(self.path, timeout=10)
        con.execute("PRAGMA secure_delete=ON")
        try:
            with con:
                yield con
        finally:
            con.close()

    def list(self):
        with self.lock, self.connect() as con:
            data = [json.loads(r[0]) for r in con.execute("SELECT body FROM workspaces ORDER BY rowid DESC")]
        return [{"id": w["id"], "name": w["name"], "created_at": w["created_at"], "entities": len(w["entities"])} for w in data]

    def get(self, workspace):
        with self.lock, self.connect() as con:
            row = con.execute("SELECT body FROM workspaces WHERE id=?", (workspace,)).fetchone()
        if not row:
            raise ImportProblem("Workspace not found.")
        return json.loads(row[0])

    def _save(self, data):
        if len(data["entities"]) > 10000 or len(data["observations"]) > 50000:
            raise ImportProblem("Workspace capacity reached (10,000 entities / 50,000 observations). Start a separate workspace.")
        with self.connect() as con:
            con.execute("INSERT OR REPLACE INTO workspaces(id,body) VALUES (?,?)", (data["id"], json.dumps(data, ensure_ascii=False)))

    def create(self, name, scope):
        with self.lock:
            w = {"id": uid(), "name": required_text(name, "Name", 120), "scope": clean(scope)[:4000],
                 "created_at": now(), "schema": "atlas-workspace/1", "imports": [], "entities": [],
                 "observations": [], "findings": [], "records": [], "decisions": [], "history": []}
            self._save(w)
            return w

    def delete(self, workspace, confirmation):
        with self.lock:
            w = self.get(workspace)
            if confirmation != w["name"]:
                raise ImportProblem("Type the workspace name to confirm deletion.")
            with self.connect() as con:
                con.execute("DELETE FROM workspaces WHERE id=?", (workspace,))
                con.commit()
                con.execute("VACUUM")

    def import_file(self, workspace, content, filename, source, context, intake='offline'):
        if intake not in ('offline','native live'):raise ImportProblem('Unknown evidence intake mode.')
        bundle = parse(content, source, copy.deepcopy(context))
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        adapter_version=getattr(bundle,'adapter_version',VERSION)
        # Metadata changes intentionally create a distinct import; identical repeat is a no-op.
        fingerprint = hashlib.sha256(json.dumps([digest, bundle.source, adapter_version, context], sort_keys=True).encode()).hexdigest()
        with self.lock:
            w = self.get(workspace)
            existing = next((x for x in w["imports"] if x["fingerprint"] == fingerprint), None)
            event_id=getattr(bundle,'event_id',None)
            if event_id:
                previous=next((x for x in w['imports'] if x.get('event_id')==event_id and x['source']==bundle.source),None)
                if previous and previous['sha256']!=digest:raise ImportProblem('Event ID already identifies different source content; history was preserved.')
                existing=previous if previous and previous['fingerprint']==fingerprint else existing
            if existing:
                return {"duplicate": True, "import": existing, "workspace": self.view(w)}
            artifact = {"id": uid(), "filename": clean(Path(str(filename).replace('\\', '/')).name)[:200],
                        "intake_mode":intake,
                        "sha256": digest, "fingerprint": fingerprint, "source": bundle.source,
                        "source_version": clean(context.get("source_version")) or bundle.source_version,
                        "adapter_version": adapter_version, "imported_at": now(), "namespace": clean(context.get("namespace")) or "default",
                        "vantage": clean(context.get("vantage")) or "unknown", "warnings": bundle.warnings,
                        "raw_reference": "Original file held by operator; raw bytes are not persisted. Digest identifies original input."}
            if event_id:artifact['event_id']=event_id
            if bundle.source.startswith('web-'):artifact['raw_reference']='Bounded live capture or web envelope; raw messages are transient and not persisted. Retained excerpts may be redacted/truncated; protect source originals separately when available.'
            mapping = {entity["key"]: uid() for entity in bundle.entities}
            for entity in bundle.entities:
                w["entities"].append({**entity, "id": mapping[entity["key"]], "import_id": artifact["id"], "namespace": artifact["namespace"]})
            for observation in bundle.observations:
                w["observations"].append({**observation, "id": uid(), "subject": mapping[observation["subject"]],
                                          "target": mapping.get(observation["target"]), "import_id": artifact["id"]})
            for finding in bundle.findings:
                w["findings"].append({**finding, "id": uid(), "subject": mapping[finding["subject"]],
                                      "import_id": artifact["id"], "review_notes": ""})
            w["imports"].append(artifact)
            w["history"].append({"at": now(), "action": "import", "detail": f"{artifact['filename']}: {len(bundle.entities)} entities, {len(bundle.observations)} observations", "import_id": artifact["id"]})
            self._save(w)
            return {"duplicate": False, "import": artifact, "workspace": self.view(w)}

    def start_web_run(self,workspace,kind,plan):
        with self.lock:
            w=self.get(workspace);runs=w.setdefault('web_runs',[])
            if len(runs)>=200:raise ImportProblem('This workspace has 200 retained web runs; use a new workspace for more runs.')
            run={'id':uid(),'kind':kind,'state':'queued','started_at':now(),'plan':copy.deepcopy(plan),'requests':0,'import_ids':[],'errors':[],'skipped':0,'reason':''}
            runs.append(run);w['history'].append({'at':now(),'action':'web run scheduled','detail':kind,'run_id':run['id']});self._save(w)
            return copy.deepcopy(run)

    def update_web_run(self,workspace,run_id,**changes):
        with self.lock:
            w=self.get(workspace);run=next((r for r in w.get('web_runs',[]) if r['id']==run_id),None)
            if not run:raise ImportProblem('Web run not found.')
            run.update(copy.deepcopy(changes));self._save(w);return copy.deepcopy(run)

    def web_runs(self,workspace):return copy.deepcopy(self.get(workspace).get('web_runs',[]))

    def reconcile(self, workspace, left, right, reason):
        with self.lock:
            w = self.get(workspace)
            ids = {e["id"] for e in w["entities"]}
            if left not in ids or right not in ids or left == right:
                raise ImportProblem("Select two different existing identities.")
            kinds = {e["kind"] for e in w["entities"] if e["id"] in (left, right)}
            if len(kinds) > 1 and not kinds.issubset({"device", "hop"}):
                raise ImportProblem("Only compatible entity types can share an identity. Device and hop candidates can be reconciled together.")
            reason = required_text(reason, "Evidence and rationale", 3000)
            view = self.view(w)
            if view["canonical"][left] == view["canonical"][right]:
                raise ImportProblem("These identities are already linked.")
            decision = {"id": uid(), "left": left, "right": right, "reason": reason, "at": now(), "active": True, "actor": "local operator"}
            w["decisions"].append(decision)
            w["history"].append({"at": now(), "action": "identity link", "detail": reason, "decision_id": decision["id"]})
            self._save(w)
            return self.view(w)

    def undo(self, workspace, decision_id):
        with self.lock:
            w = self.get(workspace)
            decision = next((d for d in w["decisions"] if d["id"] == decision_id and d["active"]), None)
            if not decision:
                raise ImportProblem("Active identity decision not found.")
            decision["active"] = False
            decision["undone_at"] = now()
            w["history"].append({"at": now(), "action": "undo identity link", "detail": decision["reason"], "decision_id": decision_id})
            self._save(w)
            return self.view(w)

    def record(self, workspace, data):
        with self.lock:
            w = self.get(workspace)
            if data.get("kind") not in ("question", "test", "access", "note", "finding"):
                raise ImportProblem("Choose a supported assessment record type.")
            subject = data.get("subject") or None
            if subject and subject not in {e["id"] for e in w["entities"]}:
                raise ImportProblem("Record subject not found.")
            status = data.get("status", "open")
            if status not in ("open", "in progress", "complete", "needs retest"):
                raise ImportProblem("Unknown record status.")
            record = {"id": uid(), "kind": data["kind"], "subject": subject,
                      "title": required_text(data.get("title"), "Title", 240), "details": clean(data.get("details")),
                      "status": status, "at": now(), "evidence_refs": clean(data.get("evidence_refs")), "actor": "local operator"}
            w["records"].append(record)
            w["history"].append({"at": now(), "action": "assessment record", "detail": record["title"], "record_id": record["id"]})
            self._save(w)
            return self.view(w)

    def update_record(self, workspace, data):
        with self.lock:
            w = self.get(workspace)
            records = w["findings"] if data.get("collection") == "findings" else w["records"]
            record = next((r for r in records if r["id"] == data.get("id")), None)
            if not record:
                raise ImportProblem("Record not found.")
            if data.get("status") not in ("open", "in progress", "complete", "needs retest", "accepted risk", "false positive"):
                raise ImportProblem("Unknown status.")
            note = required_text(data.get("note"), "Review note", 3000)
            record["status"] = data["status"]
            record["review_notes"] = note
            record["updated_at"] = now()
            w["history"].append({"at": now(), "action": "record review", "detail": note, "record_id": record["id"], "status": data["status"]})
            self._save(w)
            return self.view(w)

    @staticmethod
    def view(w):
        result = copy.deepcopy(w)
        parents = {e["id"]: e["id"] for e in w["entities"]}
        def find(e):
            while parents[e] != e:
                e = parents[e]
            return e
        for decision in w["decisions"]:
            if decision["active"]:
                parents[find(decision["right"])] = find(decision["left"])
        result["canonical"] = {eid: find(eid) for eid in parents}
        groups = {}
        for entity in w["entities"]:
            groups.setdefault(find(entity["id"]), []).append(entity)
        result["nodes"] = [{**members[0], "id": root, "members": [m["id"] for m in members],
                            "labels": list(dict.fromkeys(m["label"] for m in members)),
                            "addresses": list(dict.fromkeys(a for m in members for a in m["addresses"]))} for root, members in groups.items()]
        result["edges"] = [{**o, "source": find(o["subject"]), "target": find(o["target"])} for o in w["observations"] if o["target"]]
        candidates = []
        indexed = {}
        seen_pairs = set()
        limited = False
        for node in result["nodes"]:
            if node["kind"] not in ("device", "hop"):
                continue
            for marker in dict.fromkeys(node["labels"] + node["addresses"]):
                token = (node["namespace"], marker)
                for peer in indexed.get(token, []):
                    if peer != node["id"]:
                        pair = tuple(sorted((peer, node["id"])))
                        if pair not in seen_pairs:
                            if len(candidates) >= 200:
                                limited = True
                                break
                            candidates.append({"left": peer, "right": node["id"], "reason": f"Shared label/address {marker}; identity remains uncertain."})
                            seen_pairs.add(pair)
                peers = indexed.setdefault(token, [])
                if len(peers) < 20:
                    peers.append(node["id"])
                else:
                    limited = True
        result["candidates"] = candidates
        result["candidates_limited"] = limited
        divergent = {}
        for o in w["observations"]:
            if o["target"] or o["kind"] in ("address", "name", "address assignment", "script output", "scanner report", "scanner references", "scanner endpoint"):
                continue
            divergent.setdefault((find(o["subject"]), o["kind"]), []).append(o)
        result["conflicts"] = [{"subject": key[0], "kind": key[1], "observations": [o["id"] for o in obs],
                                "reason": "Values differ across retained observations; inspect collection times, sources and validity."}
                               for key, obs in divergent.items() if len({json.dumps(o["value"], sort_keys=True) for o in obs}) > 1]
        return result

    def export(self, workspace, identifiers=False, kind="", claim="", import_id=""):
        w = self.view(self.get(workspace))
        all_observations = w["observations"]
        w["observations"] = [o for o in w["observations"] if (not kind or o["kind"] == kind) and (not claim or o["status"] == claim) and (not import_id or o["import_id"] == import_id)]
        keep = {o["subject"] for o in w["observations"]} | {o["target"] for o in w["observations"] if o["target"]}
        if not (kind or claim or import_id):
            keep |= {e["id"] for e in w["entities"]}
        w["entities"] = [e for e in w["entities"] if e["id"] in keep]
        w["edges"] = [o for o in w["edges"] if o["id"] in {x["id"] for x in w["observations"]}]
        w["nodes"] = [n for n in w["nodes"] if any(m in keep for m in n["members"])]
        w["findings"] = [f for f in w["findings"] if f["subject"] in keep]
        w["records"] = [r for r in w["records"] if not r["subject"] or r["subject"] in keep]
        selected_ids = {o["id"] for o in w["observations"]}
        conflict_ids = {oid for c in w["conflicts"] for oid in c["observations"]}
        w["context_observations"] = [o for o in all_observations if o["id"] in conflict_ids and o["id"] not in selected_ids]
        w["export"] = {"format": "atlas-results/1", "at": now(), "identifiers_included": identifiers,
                       "selection": {"kind": kind or "all", "status": claim or "all", "import_id": import_id or "all"},
                       "limitations": "Source assertions, not independently validated impact. Graph paths are not tested reachability. Imported originals held by operator; native raw messages are transient with bounded/redacted excerpts. Collection gaps and history remain in observations.",
                       "redactions": [] if identifiers else ["entity labels and addresses", "source filenames, supplied versions and testing position", "evidence values and free text", "workspace name and scope"]}
        if not identifiers:
            for run in w.get('web_runs',[]):
                run['plan']='[withheld]';run['errors']=['[withheld]' for _ in run.get('errors',[])];run['reason']='[withheld]'
            for i, e in enumerate(w["entities"]):
                e["label"] = "Entity " + str(i + 1)
                e["addresses"] = []
                e["key"] = "[withheld]"
            for i, n in enumerate(w["nodes"]):
                n["label"] = "Node " + str(i + 1)
                n["labels"] = [n["label"]]
                n["addresses"] = []
                n["key"] = "[withheld]"
            for o in w["observations"] + w["edges"] + w["context_observations"]:
                o["value"] = "[withheld in redacted export]"
                o["vantage"] = "[withheld]" if o["vantage"] != "unknown" else "unknown"
                o["location"] = "[withheld]"
            for artifact in w["imports"]:
                artifact["filename"] = "[withheld]"
                artifact["source_version"] = "[withheld]"
                artifact["vantage"] = "[withheld]" if artifact["vantage"] != "unknown" else "unknown"
                artifact["namespace"] = "[withheld]"
            for item in w["findings"] + w["records"] + w["history"] + w["decisions"]:
                for field in ("title", "description", "details", "detail", "reason", "review_notes", "evidence_refs", "external_id", "location"):
                    if field in item:
                        item[field] = "[withheld]"
            w["candidates"] = []
            w["name"] = "Redacted assessment"
            w["scope"] = "[withheld]"
            for e in w["entities"] + w["nodes"]:
                e["namespace"] = "[withheld]"
        return w


def html_report(w):
    esc = lambda v: html.escape(str(v), quote=True)
    rows = lambda data, fields: "".join("<tr>" + "".join("<td>" + esc(row.get(f, "")) + "</td>" for f in fields) + "</tr>" for row in data)
    table = lambda title, data, fields: f"<h2>{esc(title)}</h2><table><thead><tr>" + "".join(f"<th>{esc(f.replace('_', ' '))}</th>" for f in fields) + "</tr></thead><tbody>" + rows(data, fields) + "</tbody></table>"
    body = table("Inventory", w["nodes"], ["id", "label", "kind", "addresses"])
    body += table("Findings (source assertions)", w["findings"], ["subject", "title", "severity", "validation", "status", "description", "import_id", "location"])
    body += table("Assessment activity", w["records"], ["kind", "title", "status", "subject", "details", "evidence_refs", "at"])
    body += table("Native web runs and collection limits", w.get('web_runs',[]), ['id','kind','state','started_at','ended_at','requests','message_count','websocket_messages','interactions','findings','oob_interactions','oob_import_ids','skipped','plan','errors','reason','import_ids'])
    body += table("Evidence and typed relationships", w["observations"], ["id", "subject", "target", "kind", "status", "basis", "value", "collected_at", "vantage", "import_id", "location"])
    body += table("Sources and provenance", w["imports"], ["id", "filename", "source", "source_version", "intake_mode", "adapter_version", "sha256", "imported_at", "raw_reference", "warnings"])
    body += table("Divergent observations", w["conflicts"], ["subject", "kind", "observations", "reason"])
    body += table("Conflict context outside selected filter", w.get("context_observations", []), ["id", "subject", "kind", "value", "status", "basis", "collected_at", "vantage", "import_id", "location"])
    body += table("Identity decisions", w["decisions"], ["left", "right", "reason", "active", "at"])
    body += table("History", w["history"], ["at", "action", "detail"])
    return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Assessment Atlas report</title><style>body{font:15px system-ui;color:#182939;margin:40px}table{border-collapse:collapse;width:100%;font-size:12px;table-layout:fixed}td,th{border:1px solid #bcc9d4;padding:8px;text-align:left;overflow-wrap:anywhere}th{background:#e9f0f4}h1,h2{break-after:avoid}@media print{body{margin:0}thead{display:table-header-group}tr{break-inside:avoid}}</style>' + f'<h1>{esc(w["name"])}</h1><p>{esc(w["scope"])}</p><p>Exported {esc(w["export"]["at"])}. {esc(w["export"]["limitations"])}</p><p>Selection: {esc(w["export"]["selection"])}. Redactions: {esc(w["export"]["redactions"])}</p>' + body + '</html>'

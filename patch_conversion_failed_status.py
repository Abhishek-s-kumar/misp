#!/usr/bin/env python3
"""Patch api/server.py and dashboard/tag-filter.html: surface conversion_failed
status (written by xml_merger.py after the DNF compiler swap) in the dashboard
instead of silently showing those rules as "active" while they're actually
missing from local_rules.xml. Run from repo root."""
import sys, pathlib

# --- 1. api/server.py: /api/rules must read deployment_status from metadata ---
f1 = pathlib.Path("api/server.py")
s1 = f1.read_text(encoding="utf-8")

OLD_RULES_APPEND = '''            if tag and tag not in tags:
                continue
            out.append({"name": f.name, "type": rule_type, "tags": tags, "status": "active"})'''

NEW_RULES_APPEND = '''            if tag and tag not in tags:
                continue
            status = "active"
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text(encoding="utf-8"))
                    if meta.get("deployment_status") == "conversion_failed":
                        status = "conversion_failed"
                except Exception:
                    pass
            out.append({"name": f.name, "type": rule_type, "tags": tags, "status": status})'''

if OLD_RULES_APPEND not in s1:
    sys.exit("api/server.py: /api/rules anchor not found, abort -- file may already be patched or differs from expected")

s1 = s1.replace(OLD_RULES_APPEND, NEW_RULES_APPEND, 1)
f1.write_text(s1, encoding="utf-8")
print("patched api/server.py: /api/rules now surfaces deployment_status=conversion_failed")


# --- 2. dashboard/tag-filter.html: visual marker for conversion_failed rows ---
f2 = pathlib.Path("dashboard/tag-filter.html")
s2 = f2.read_text(encoding="utf-8")

OLD_CSS = ".q{color:#f55}"
NEW_CSS = ".q{color:#f55}\n.cf{color:#f90}"

OLD_ROW = '''      tr.innerHTML = `<td>${row.name}</td><td>${row.type}</td><td>${row.tags.join(', ')}</td><td class="${row.status==='quarantine'?'q':''}">${row.status}</td>`;'''

NEW_ROW = '''      const statusClass = row.status === 'quarantine' ? 'q' : row.status === 'conversion_failed' ? 'cf' : '';
      tr.innerHTML = `<td>${row.name}</td><td>${row.type}</td><td>${row.tags.join(', ')}</td><td class="${statusClass}">${row.status}</td>`;'''

if OLD_CSS not in s2:
    sys.exit("dashboard/tag-filter.html: CSS anchor not found, abort")
if OLD_ROW not in s2:
    sys.exit("dashboard/tag-filter.html: row anchor not found, abort -- file may already be patched or differs from expected")

s2 = s2.replace(OLD_CSS, NEW_CSS, 1)
s2 = s2.replace(OLD_ROW, NEW_ROW, 1)
f2.write_text(s2, encoding="utf-8")
print("patched dashboard/tag-filter.html: conversion_failed rows now shown in orange")

print("done -- restart api/server.py (or docker compose up -d --force-recreate misp-pipeline) to pick up the change")

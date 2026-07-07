#!/usr/bin/env python3
"""Patch dashboard/index.html: add quarantine review section + CSS. Run from repo root."""
import sys, pathlib

f = pathlib.Path("dashboard/index.html")
s = f.read_text(encoding="utf-8")

CSS_ANCHOR = "        footer {"
CSS_INSERT = """        .quarantine-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem;
            border: 1px solid var(--card-border);
            border-radius: 8px;
            margin-bottom: 0.5rem;
            background: rgba(245, 158, 11, 0.03);
        }
        .quarantine-info { display: flex; flex-direction: column; gap: 0.25rem; }
        .quarantine-meta { font-size: 0.75rem; color: var(--text-muted); }
        .quarantine-actions { display: flex; gap: 0.5rem; flex-shrink: 0; }

        footer {"""

JSX_ANCHOR = "                            {/* Console output widget */}"
JSX_INSERT = """                            {/* Quarantine Review Panel */}
                            <div className="card">
                                <div className="card-title">
                                    <i className="fa-solid fa-triangle-exclamation"></i>
                                    Quarantine Review ({quarantineList.length})
                                </div>
                                {quarantineLoading && (
                                    <div style={{color: 'var(--text-muted)', fontSize: '0.85rem'}}>Loading...</div>
                                )}
                                {!quarantineLoading && quarantineList.length === 0 && (
                                    <div style={{color: 'var(--text-muted)', fontSize: '0.85rem'}}>No rules in quarantine.</div>
                                )}
                                {quarantineList.map(entry => (
                                    <div key={entry.rule_name} className="quarantine-item">
                                        <div className="quarantine-info">
                                            <strong>{entry.rule_name}</strong>
                                            <span className="quarantine-meta">
                                                {entry.rule_type} &middot; tags: {(entry.tags || []).join(', ') || 'none'}
                                            </span>
                                        </div>
                                        <div className="quarantine-actions">
                                            <button
                                                className="btn btn-status"
                                                style={{width: 'auto', padding: '0.4rem 0.9rem'}}
                                                onClick={() => promoteQuarantineRule(entry.rule_name)}
                                            >
                                                Approve
                                            </button>
                                            <button
                                                className="btn btn-rollback"
                                                style={{width: 'auto', padding: '0.4rem 0.9rem'}}
                                                onClick={() => rejectQuarantineRule(entry.rule_name)}
                                            >
                                                Reject
                                            </button>
                                        </div>
                                    </div>
                                ))}
                            </div>

                            {/* Console output widget */}"""

if CSS_ANCHOR not in s:
    sys.exit("CSS anchor not found, abort")
if JSX_ANCHOR not in s:
    sys.exit("JSX anchor not found, abort")

s = s.replace(CSS_ANCHOR, CSS_INSERT, 1)
s = s.replace(JSX_ANCHOR, JSX_INSERT, 1)

f.write_text(s, encoding="utf-8")
print("patched dashboard/index.html: quarantine review section added")

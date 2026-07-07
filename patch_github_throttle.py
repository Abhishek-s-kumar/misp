#!/usr/bin/env python3
"""Patch collector/github_provider.py: max_workers 10->4, add throttle delay. Run from repo root."""
import sys, pathlib

f = pathlib.Path("collector/github_provider.py")
s = f.read_text(encoding="utf-8")

OLD_IMPORT = "from concurrent.futures import ThreadPoolExecutor, as_completed"
NEW_IMPORT = "import time\nfrom concurrent.futures import ThreadPoolExecutor, as_completed"

OLD_POOL = """        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(_fetch_one, e) for e in in_scope]
            for i, future in enumerate(as_completed(futures), start=1):
                entry, content, err = future.result()
                if err is not None:
                    log.warning("github_blob_fetch_failed", path=entry["path"], error=str(err))
                    continue
                ext = self._get_extension(entry["path"])
                raw_rules.append(
                    RawRule(
                        rule_type=EXTENSION_MAP[ext],
                        name=entry["path"].replace("/", "__"),
                        content=content,
                        event_id=event_id,
                        event_uuid=entry["sha"],
                        misp_timestamp=datetime.now(timezone.utc),
                        tags=list(self.extra_tags) + [f"repo:{self.repo}"],
                    )
                )
                if i % 50 == 0 or i == len(in_scope):
                    log.info("github_source_fetch_progress", repo=self.repo, done=i, total=len(in_scope))"""

NEW_POOL = """        BATCH_SIZE = 40
        BATCH_DELAY_SECONDS = 2.0
        MAX_WORKERS = 4

        for batch_start in range(0, len(in_scope), BATCH_SIZE):
            batch = in_scope[batch_start:batch_start + BATCH_SIZE]
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                futures = [pool.submit(_fetch_one, e) for e in batch]
                for future in as_completed(futures):
                    entry, content, err = future.result()
                    if err is not None:
                        log.warning("github_blob_fetch_failed", path=entry["path"], error=str(err))
                        continue
                    ext = self._get_extension(entry["path"])
                    raw_rules.append(
                        RawRule(
                            rule_type=EXTENSION_MAP[ext],
                            name=entry["path"].replace("/", "__"),
                            content=content,
                            event_id=event_id,
                            event_uuid=entry["sha"],
                            misp_timestamp=datetime.now(timezone.utc),
                            tags=list(self.extra_tags) + [f"repo:{self.repo}"],
                        )
                    )
            done = min(batch_start + BATCH_SIZE, len(in_scope))
            log.info("github_source_fetch_progress", repo=self.repo, done=done, total=len(in_scope))
            if done < len(in_scope):
                time.sleep(BATCH_DELAY_SECONDS)"""

if OLD_IMPORT not in s:
    sys.exit("import anchor not found, abort")
if OLD_POOL not in s:
    sys.exit("pool anchor not found, abort -- file may already be patched or differs from expected")

s = s.replace(OLD_IMPORT, NEW_IMPORT, 1)
s = s.replace(OLD_POOL, NEW_POOL, 1)

f.write_text(s, encoding="utf-8")
print("patched collector/github_provider.py: max_workers=4, batched w/ 2s inter-batch delay")

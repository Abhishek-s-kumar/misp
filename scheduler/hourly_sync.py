import os
import time
import schedule
import structlog
from mcp_tools.rule_tools import sync_misp_rules
from dotenv import load_dotenv

load_dotenv()

log = structlog.get_logger()

def job():
    if os.environ.get("ENABLE_SCHEDULER", "false").lower() != "true":
        log.info("scheduler_disabled", hint="Set ENABLE_SCHEDULER=true to enable")
        return

    log.info("scheduler_triggered_sync")
    try:
        result = sync_misp_rules(since=None)
        log.info("scheduler_sync_complete", result=result)
    except Exception as e:
        log.error("scheduler_sync_failed", error=str(e))

interval_hours = int(os.environ.get("SCHEDULER_INTERVAL_HOURS", "1"))
schedule.every(interval_hours).hours.do(job)

if __name__ == "__main__":
    log.info("scheduler_starting", interval_hours=interval_hours)
    while True:
        schedule.run_pending()
        time.sleep(60)

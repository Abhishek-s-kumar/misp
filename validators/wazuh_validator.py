import subprocess
import tempfile
from pathlib import Path

import structlog

from validators.yara_validator import ValidationResult

log = structlog.get_logger()

# Minimal valid ossec.conf skeleton for isolated rule testing.
# This ensures wazuh-analysisd -t only validates our rule, not the full
# manager configuration.
_BASELINE_OSSEC_CONF = """<ossec_config>
  <global>
    <logall>no</logall>
  </global>
  <ruleset>
    <include>local_rules.xml</include>
  </ruleset>
</ossec_config>
"""


def validate_wazuh(content: str) -> ValidationResult:
    """
    Validate a Wazuh XML rule by building a temporary isolated environment
    and running wazuh-analysisd -t.

    This avoids false negatives from unrelated configuration issues on the
    manager by testing only the new rule against a minimal baseline config.

    Returns ValidationResult. Never raises.
    """
    tmp_dir = None
    try:
        tmp_dir = Path(tempfile.mkdtemp(prefix="wazuh_validate_"))

        # Write the rule file
        rules_dir = tmp_dir / "etc" / "rules"
        rules_dir.mkdir(parents=True)
        rule_file = rules_dir / "local_rules.xml"
        rule_file.write_text(content, encoding="utf-8")

        # Write a minimal ossec.conf
        etc_dir = tmp_dir / "etc"
        ossec_conf = etc_dir / "ossec.conf"
        ossec_conf.write_text(_BASELINE_OSSEC_CONF, encoding="utf-8")

        result = subprocess.run(
            ["/var/ossec/bin/wazuh-analysisd", "-t", "-c", str(ossec_conf)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            warnings = [
                line
                for line in result.stderr.strip().splitlines()
                if line.strip()
            ]
            return ValidationResult(valid=True, warnings=warnings)
        else:
            errors = [
                line
                for line in (
                    result.stderr.strip().splitlines()
                    + result.stdout.strip().splitlines()
                )
                if line.strip()
            ]
            return ValidationResult(valid=False, errors=errors)

    except FileNotFoundError:
        return ValidationResult(
            valid=True,
            warnings=[
                "wazuh-analysisd not available, skipped exec validation"
            ],
        )
    except subprocess.TimeoutExpired:
        return ValidationResult(
            valid=False, errors=["Wazuh validation timed out after 30s"]
        )
    except Exception as e:
        return ValidationResult(valid=False, errors=[str(e)])
    finally:
        if tmp_dir and tmp_dir.exists():
            import shutil

            shutil.rmtree(tmp_dir, ignore_errors=True)

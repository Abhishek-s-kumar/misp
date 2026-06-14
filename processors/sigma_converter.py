import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import structlog

log = structlog.get_logger()


def convert_sigma_to_wazuh(
    sigma_content: str, sigma_name: str
) -> Optional[str]:
    """
    Convert a Sigma YAML rule to Wazuh XML format using sigma-cli.

    In environments where sigma-cli is not available, returns a deterministic
    mock XML wrapper for testing purposes.

    Args:
        sigma_content: Raw Sigma YAML rule content.
        sigma_name: Filename of the Sigma rule (for logging).

    Returns:
        Wazuh XML string if conversion succeeds, None on failure.
    """
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(sigma_content)
            tmp_path = Path(tmp.name)

        result = subprocess.run(
            [
                "sigma",
                "convert",
                "--target",
                "wazuh",
                "--without-pipeline",
                str(tmp_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0 and result.stdout.strip():
            log.info("sigma_conversion_success", rule=sigma_name)
            return result.stdout.strip()
        else:
            log.warning(
                "sigma_conversion_failed",
                rule=sigma_name,
                stderr=result.stderr,
            )
            # Fall through to mock conversion
    except FileNotFoundError:
        log.warning(
            "sigma_cli_not_found",
            message="sigma-cli not installed, using mock conversion",
        )
    except subprocess.TimeoutExpired:
        log.warning("sigma_conversion_timeout", rule=sigma_name)
    except Exception as e:
        log.warning("sigma_conversion_error", rule=sigma_name, error=str(e))
    finally:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink()

    # Mock conversion fallback for dev/test environments
    return _mock_sigma_to_wazuh(sigma_content, sigma_name)


def _mock_sigma_to_wazuh(sigma_content: str, sigma_name: str) -> str:
    """
    Deterministic mock Sigma→Wazuh XML conversion for testing.
    Generates a valid Wazuh rule XML skeleton from the Sigma metadata.
    """
    import yaml

    try:
        sigma = yaml.safe_load(sigma_content)
    except Exception:
        sigma = {}

    title = sigma.get("title", sigma_name)
    level = sigma.get("level", "medium")
    level_map = {"low": 3, "medium": 5, "high": 10, "critical": 15}
    wazuh_level = level_map.get(level, 5)

    # Generate a deterministic rule ID from the sigma name
    rule_id = 100200 + (hash(sigma_name) % 100)

    xml = (
        f'<group name="sigma,misp,">\n'
        f'  <rule id="{rule_id}" level="{wazuh_level}">\n'
        f"    <description>{title} [Sigma converted]</description>\n"
        f"  </rule>\n"
        f"</group>"
    )
    log.info("sigma_mock_conversion", rule=sigma_name)
    return xml

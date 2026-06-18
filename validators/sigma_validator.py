import subprocess
import tempfile
from pathlib import Path

import structlog

from validators.yara_validator import ValidationResult

log = structlog.get_logger()


def validate_sigma(content: str) -> ValidationResult:
    """
    Validate a Sigma rule using sigma-cli or pySigma fallback.
    Returns ValidationResult. Never raises.
    """
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        # Try newer sigma-cli syntax (check instead of validate)
        result = subprocess.run(
            ["sigma", "check", str(tmp_path)],
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
        # Fallback: try pySigma import validation
        try:
            import yaml
            from sigma.rule import SigmaRule
            data = yaml.safe_load(content)
            SigmaRule.from_dict(data)
            return ValidationResult(
                valid=True,
                warnings=["sigma-cli not found, used pySigma fallback"]
            )
        except ImportError:
            return ValidationResult(
                valid=False,
                errors=["sigma-cli not found. Install: pip install sigma-cli"],
            )
        except Exception as e:
            return ValidationResult(valid=False, errors=[str(e)])
    except subprocess.TimeoutExpired:
        return ValidationResult(
            valid=False, errors=["Sigma validation timed out after 30s"]
        )
    except Exception as e:
        return ValidationResult(valid=False, errors=[str(e)])
    finally:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink()

import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import structlog

log = structlog.get_logger()


@dataclass
class ValidationResult:
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def validate_yara(content: str) -> ValidationResult:
    """
    Validate a YARA rule by writing it to a tempfile and running yara -C.
    Returns ValidationResult. Never raises.
    """
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yar", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        result = subprocess.run(
            ["yara", "-C", str(tmp_path)],
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
                for line in result.stderr.strip().splitlines()
                if line.strip()
            ]
            return ValidationResult(valid=False, errors=errors)

    except FileNotFoundError:
        return ValidationResult(
            valid=False,
            errors=["yara binary not found. Install yara: apt install yara"],
        )
    except subprocess.TimeoutExpired:
        return ValidationResult(
            valid=False, errors=["YARA validation timed out after 30s"]
        )
    except Exception as e:
        return ValidationResult(valid=False, errors=[str(e)])
    finally:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink()

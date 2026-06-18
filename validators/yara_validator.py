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
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yar", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        # Create a dummy file to scan against
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as dummy:
            dummy.write("dummy")
            dummy_path = Path(dummy.name)

        # yara <rules> <target> — if syntax is bad, it exits non-zero
        # -p 0 = no external variables needed
        result = subprocess.run(
            ["yara", "-p", "0", str(tmp_path), str(dummy_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        dummy_path.unlink(missing_ok=True)

        if result.returncode == 0:
            warnings = [line for line in result.stderr.strip().splitlines() if line.strip()]
            return ValidationResult(valid=True, warnings=warnings)
        else:
            errors = [line for line in result.stderr.strip().splitlines() if line.strip()]
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

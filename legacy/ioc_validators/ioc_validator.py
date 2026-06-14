import ipaddress
import re
from dataclasses import dataclass
from collections import defaultdict
import validators
import structlog
from collector.base import RawIOC

log = structlog.get_logger()

class DataQualityError(Exception):
    """Raised when data quality threshold (e.g. >50% rejection) is violated."""
    pass

@dataclass
class ValidatedIOC:
    normalized_type: str  # "ip", "domain", "hash", "url"
    value: str
    source: RawIOC

class IOCValidator:
    """
    Validates IOC values. Returns ValidatedIOC or None (never raises during single validate).
    """
    
    PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),   # link-local
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("255.255.255.255/32"),
    ]
    
    HASH_PATTERNS = {
        "md5":    re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),
        "sha1":   re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE),
        "sha256": re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE),
    }

    def validate(self, raw: RawIOC) -> ValidatedIOC | None:
        ioc_type = raw.ioc_type.lower()
        if ioc_type in ("ip-src", "ip-dst", "ip"):
            return self._validate_ip(raw)
        elif ioc_type in ("domain", "hostname"):
            return self._validate_domain(raw)
        elif ioc_type in ("md5", "sha1", "sha256", "filename|md5", "filename|sha1", "filename|sha256"):
            return self._validate_hash(raw)
        elif ioc_type in ("url", "http-method"):
            return self._validate_url(raw)
        else:
            log.debug("unsupported_ioc_type", type=raw.ioc_type)
            return None

    def _validate_ip(self, raw: RawIOC) -> ValidatedIOC | None:
        try:
            val = raw.value.strip()
            addr = ipaddress.ip_address(val)
            if any(addr in net for net in self.PRIVATE_NETWORKS):
                log.warning("rejected_private_ip", value=raw.value)
                return None
            return ValidatedIOC(normalized_type="ip", value=str(addr), source=raw)
        except ValueError:
            log.warning("rejected_invalid_ip", value=raw.value)
            return None

    def _validate_domain(self, raw: RawIOC) -> ValidatedIOC | None:
        val = raw.value.strip()
        if bool(validators.domain(val)):
            return ValidatedIOC(normalized_type="domain", value=val, source=raw)
        log.warning("rejected_invalid_domain", value=raw.value)
        return None

    def _validate_hash(self, raw: RawIOC) -> ValidatedIOC | None:
        val = raw.value.strip()
        if "|" in val:
            parts = val.split("|")
            val = parts[-1].strip()

        for hash_type, pattern in self.HASH_PATTERNS.items():
            if pattern.match(val):
                return ValidatedIOC(normalized_type="hash", value=val.lower(), source=raw)
        
        log.warning("rejected_invalid_hash", value=raw.value)
        return None

    def _validate_url(self, raw: RawIOC) -> ValidatedIOC | None:
        val = raw.value.strip()
        if bool(validators.url(val)):
            return ValidatedIOC(normalized_type="url", value=val, source=raw)
        log.warning("rejected_invalid_url", value=raw.value)
        return None

    def validate_batch(self, raws: list[RawIOC]) -> tuple[list[ValidatedIOC], dict]:
        """
        Returns (valid_list, rejection_stats).
        Aborts if >50% rejected (MISP data quality alarm).
        """
        valid = []
        stats = {"total": len(raws), "valid": 0, "rejected": 0, "private_ip": 0, "invalid_format": 0}
        
        for raw in raws:
            result = self.validate(raw)
            if result:
                valid.append(result)
                stats["valid"] += 1
            else:
                stats["rejected"] += 1
                ioc_type = raw.ioc_type.lower()
                if ioc_type in ("ip-src", "ip-dst", "ip"):
                    try:
                        addr = ipaddress.ip_address(raw.value.strip())
                        if any(addr in net for net in self.PRIVATE_NETWORKS):
                            stats["private_ip"] += 1
                        else:
                            stats["invalid_format"] += 1
                    except ValueError:
                        stats["invalid_format"] += 1
                else:
                    stats["invalid_format"] += 1

        if len(raws) > 0 and (stats["rejected"] / len(raws)) > 0.5:
            log.error("data_quality_alarm", total=len(raws), rejected=stats["rejected"])
            raise DataQualityError(
                f"Over 50% of IOCs rejected ({stats['rejected']}/{len(raws)}). "
                "Check MISP data quality."
            )
            
        return valid, stats

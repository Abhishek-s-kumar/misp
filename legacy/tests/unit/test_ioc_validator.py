import pytest
from datetime import datetime, timezone
from collector.base import RawIOC
from ioc_validators.ioc_validator import IOCValidator, DataQualityError, ValidatedIOC

@pytest.fixture
def validator():
    return IOCValidator()

def create_raw_ioc(ioc_type: str, value: str) -> RawIOC:
    return RawIOC(
        ioc_type=ioc_type,
        value=value,
        event_id=1,
        event_uuid="event-uuid-123",
        timestamp=datetime.now(timezone.utc),
        tags=["tlp:white"],
        to_ids=True
    )

def test_validate_valid_ip(validator):
    raw = create_raw_ioc("ip-src", "8.8.8.8")
    res = validator.validate(raw)
    assert res is not None
    assert res.normalized_type == "ip"
    assert res.value == "8.8.8.8"

def test_validate_private_ip(validator):
    raw = create_raw_ioc("ip-src", "192.168.1.1")
    res = validator.validate(raw)
    assert res is None

def test_validate_invalid_ip(validator):
    raw = create_raw_ioc("ip-dst", "999.999.999.999")
    res = validator.validate(raw)
    assert res is None

def test_validate_valid_domain(validator):
    raw = create_raw_ioc("domain", "malicious-c2.com")
    res = validator.validate(raw)
    assert res is not None
    assert res.normalized_type == "domain"
    assert res.value == "malicious-c2.com"

def test_validate_invalid_domain(validator):
    raw = create_raw_ioc("domain", "not_a_domain_at_all")
    res = validator.validate(raw)
    assert res is None

def test_validate_valid_hashes(validator):
    # MD5
    raw_md5 = create_raw_ioc("md5", "d41d8cd98f00b204e9800998ecf8427e")
    res_md5 = validator.validate(raw_md5)
    assert res_md5 is not None
    assert res_md5.normalized_type == "hash"
    assert res_md5.value == "d41d8cd98f00b204e9800998ecf8427e"

    # SHA256
    raw_sha = create_raw_ioc("sha256", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
    res_sha = validator.validate(raw_sha)
    assert res_sha is not None
    assert res_sha.normalized_type == "hash"
    assert res_sha.value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" # Normalized to lowercase

def test_validate_invalid_hash(validator):
    raw = create_raw_ioc("sha256", "not-a-valid-hash-value-12345")
    res = validator.validate(raw)
    assert res is None

def test_validate_valid_url(validator):
    raw = create_raw_ioc("url", "http://attacker-c2.org/malware.exe")
    res = validator.validate(raw)
    assert res is not None
    assert res.normalized_type == "url"
    assert res.value == "http://attacker-c2.org/malware.exe"

def test_validate_invalid_url(validator):
    raw = create_raw_ioc("url", "not_a_url")
    res = validator.validate(raw)
    assert res is None

def test_validate_batch_success(validator):
    raws = [
        create_raw_ioc("ip-src", "8.8.8.8"),
        create_raw_ioc("domain", "example.com"),
        create_raw_ioc("ip-src", "10.0.0.1"),  # Private IP (will be rejected)
    ]
    valid, stats = validator.validate_batch(raws)
    assert len(valid) == 2
    assert stats["valid"] == 2
    assert stats["rejected"] == 1
    assert stats["private_ip"] == 1

def test_validate_batch_failure_data_quality(validator):
    raws = [
        create_raw_ioc("ip-src", "10.0.0.1"),  # Rejected
        create_raw_ioc("ip-src", "192.168.0.5"),  # Rejected
        create_raw_ioc("domain", "valid.com"),  # Approved
    ]
    # 2 out of 3 rejected (>50%), should raise DataQualityError
    with pytest.raises(DataQualityError):
        validator.validate_batch(raws)

from skillinquisitor.models import ScanConfig, ScanResult, SegmentType


def test_scan_config_has_default_format():
    config = ScanConfig()
    assert config.default_format == "text"


def test_scan_result_defaults_to_empty_findings():
    result = ScanResult(skills=[])
    assert result.findings == []


def test_segment_type_contains_original():
    assert SegmentType.ORIGINAL.value == "original"

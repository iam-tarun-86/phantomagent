"""PreFilter noise-suppression behaviour"""

from backend.pipeline.prefilter import PreFilter


def test_safe_pattern_is_filtered_as_noise():
    pf = PreFilter()
    event = {"raw_log": "CRON[12345]: (root) CMD (/usr/bin/backup.sh)"}
    assert pf.filter(event) is None
    assert pf.get_stats()["blocked"] == 1


def test_systemd_noise_is_filtered():
    pf = PreFilter()
    assert pf.filter({"raw_log": "systemd[1]: Started Daily apt refresh."}) is None


def test_brute_force_signature_passes_and_is_enriched():
    pf = PreFilter()
    event = {"raw_log": "Failed password for root from 10.0.0.9 port 22 ssh2"}
    result = pf.filter(event)

    assert result is not None
    assert result["prefilter_type"] == "BRUTE_FORCE"
    assert result["prefilter_confidence"] == "HIGH"
    assert result["prefilter_severity"] == 4


def test_malware_signature_carries_high_severity():
    pf = PreFilter()
    result = pf.filter({"raw_log": "rootkit detected in /usr/lib/libc.so"})

    assert result["prefilter_type"] == "MALWARE"
    assert result["prefilter_severity"] == 8


def test_unknown_pattern_passes_with_low_confidence():
    pf = PreFilter()
    result = pf.filter({"raw_log": "something entirely unrecognised happened"})

    assert result is not None
    assert result["prefilter_type"] == "UNKNOWN"
    assert result["prefilter_confidence"] == "LOW"


def test_whitelist_takes_precedence_over_blacklist():
    """A CRON line mentioning a bad keyword must still be suppressed as noise."""
    pf = PreFilter()
    assert pf.filter({"raw_log": "CRON[1]: scanning for rootkit signatures"}) is None

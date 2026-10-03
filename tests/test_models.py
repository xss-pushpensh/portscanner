from portscanner.models import PortResult, PortState, ScanResult, ScanType


def test_portresult_defaults():
    pr = PortResult(port=80, protocol="tcp", state=PortState.OPEN)
    assert pr.port == 80
    assert pr.vuln_hints == []


def test_scanresult_todict():
    r = ScanResult(targets=[], scan_type=ScanType.CONNECT,
                   start_time=ScanResult.now())
    d = r.to_dict()
    assert d["scan_type"] == "connect"
    assert "start_time" in d

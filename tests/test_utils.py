import pytest

from portscanner.utils import parse_ports, parse_targets


def test_parse_ports_single():
    assert parse_ports("80") == [80]


def test_parse_ports_list():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_ports_range():
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]


def test_parse_ports_top100():
    result = parse_ports("top-100")
    assert len(result) == 100


def test_parse_ports_invalid():
    with pytest.raises(ValueError):
        parse_ports("99999")


def test_parse_targets_single_ip():
    assert parse_targets("127.0.0.1") == ["127.0.0.1"]


def test_parse_targets_cidr():
    result = parse_targets("192.168.1.0/30")
    assert len(result) == 2


def test_parse_targets_range():
    result = parse_targets("192.168.1.1-3")
    assert result == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

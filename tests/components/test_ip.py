# Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
#           Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import pytest
from AIDojoCoordinator.game_components import IP

@pytest.fixture
def sample_private_ip1():
    """Fixture to provide a sample IP object"""
    ip_str = "192.168.1.15"
    return IP(ip_str), ip_str

@pytest.fixture
def sample_private_ip1_copy():
    """Fixture to provide a sample IP object"""
    ip_str = "192.168.1.15"
    return IP(ip_str), ip_str


@pytest.fixture
def sample_private_ip2():
    """Fixture to provide a sample IP object different from sample_private_ip1"""
    ip_str = "192.168.2.15"
    return IP(ip_str), ip_str

@pytest.fixture
def sample_public_ip():
    """Fixture to provide a sample public IP object"""
    ip_str = "8.8.8.8"
    return IP(ip_str), ip_str

class TestComponentIP:
    """
    Tests related to the IP datclass
    """
    def test_ip_repr(self, sample_private_ip1):
        """Test the object representation"""
        ip_1, ip_str = sample_private_ip1
        assert repr(ip_1) == ip_str

    def test_ip_equal(self, sample_private_ip1, sample_private_ip1_copy):
        """Test that two IP objects with the same IP are equal"""
        ip_1, _ = sample_private_ip1
        ip_2, _ = sample_private_ip1_copy
        assert ip_1 == ip_2

    def test_ip_not_equal(self, sample_private_ip1, sample_private_ip2):
        """Test that two IP objects with different IPs are not equal"""
        ip_1, _ = sample_private_ip1
        ip_2, _ = sample_private_ip2
        assert ip_1 != ip_2

    def test_ip_not_str(self, sample_private_ip1):
        """Test that the IP object is not equal to a string"""
        ip_1, _ = sample_private_ip1
        ip_2 = "192.168.2.15"
        assert ip_1 != ip_2

    def test_ip_is_private(self, sample_private_ip1):
        ip_1, _ = sample_private_ip1
        assert ip_1.is_private() is True

    def test_ip_is_not_private(self, sample_public_ip):
        ip_1, _ = sample_public_ip
        assert ip_1.is_private() is False

    def test_ip_from_dict(self, sample_private_ip1):
        """Test creating an IP object from a dictionary"""
        ip_1, ip1_str = sample_private_ip1
        d = {"ip": ip1_str}
        ip = IP.from_dict(d)
        assert isinstance(ip, IP)
        assert ip.ip == ip1_str
        assert ip == ip_1

    def test_ip_from_dict_invalid(self):
        """Test creating an IP object from an invalid dictionary"""
        d = {"ip": "invalid_ip"}
        try:
            ip = IP.from_dict(d)
            assert False, "Expected ValueError for invalid IP"
        except ValueError:
            pass
    def test_ip_hash(self, sample_private_ip1, sample_private_ip1_copy):
        """Test that the hash of two IP objects with the same IP is equal"""
        ip_1, _ = sample_private_ip1
        ip_2, _ = sample_private_ip1_copy
        assert hash(ip_1) == hash(ip_2)
# Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
#           Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
from AIDojoCoordinator.game_components import IP

class TestComponentIP:
    """
    Tests related to the IP datclass
    """
    def test_ip_repr(self):
        """Test the object representation"""
        ip_1 = IP("192.168.1.15")
        assert repr(ip_1) == "192.168.1.15"

    def test_ip_equal(self):
        """Test that two IP objects with the same IP are equal"""
        ip_1 = IP("192.168.1.15")
        ip_2 = IP("192.168.1.15")
        assert ip_1 == ip_2

    def test_ip_not_equal(self):
        """Test that two IP objects with different IPs are not equal"""
        ip_1 = IP("192.168.1.15")
        ip_2 = IP("192.168.2.15")
        assert ip_1 != ip_2

    def test_ip_not_str(self):
        """Test that the IP object is not equal to a string"""
        ip_1 = IP("192.168.1.15")
        ip_2 = "192.168.2.15"
        assert ip_1 != ip_2

    def test_ip_is_private(self):
        ip_1 = IP("192.168.1.15")
        assert ip_1.is_private() is True
    
    def test_ip_is_not_private(self):
        ip_1 = IP("192.143.1.15")
        assert ip_1.is_private() is False

    def test_ip_from_dict(self):
        """Test creating an IP object from a dictionary"""
        d = {"ip": "10.0.0.1"}
        ip = IP.from_dict(d)
        assert isinstance(ip, IP)
        assert ip.ip == "10.0.0.1"
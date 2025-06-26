# Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
#           Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
from AIDojoCoordinator.game_components import Network

class TestComponentNetwork:
    """
    Test cases for the Network dataclass
    """
    def test_net_creation(self):
        """
        Test that the network is created and all elements can be accessed
        """
        net = Network("125.36.21.3", 16)
        assert net.ip == "125.36.21.3"
        assert net.mask == 16

    def test_net_str(self):
        """
        Test the string representaion of the network
        """
        net = Network("125.36.21.3", 16)
        assert str(net) == "125.36.21.3/16"

    def test_net_repr(self):
        """
        Test the repr of the Network
        """
        net = Network("125.36.21.3", 16)
        assert repr(net) == "125.36.21.3/16"

    def test_net_equal(self):
        """
        Test that two network objects with the same paramters are equal
        """
        net_1 = Network("125.36.21.3", 16)
        net_2 = Network("125.36.21.3", 16)
        assert net_1 == net_2

    def test_net_not_equal(self):
        """
        Test that two network objects with different paramters are not equal
        """
        net_1 = Network("125.36.21.3", 16)
        net_2 = Network("192.168.1.3", 16)
        assert net_1 != net_2

    def test_net_is_not_private(self):
        net_1 = Network("125.36.21.3", 16)
        assert net_1.is_private() is False
    
    def test_net_is_private(self):
        net_1 = Network("192.168.1.0", 16)
        assert net_1.is_private() is True
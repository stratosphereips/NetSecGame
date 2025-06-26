# Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
#           Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import pytest
import dataclasses
from AIDojoCoordinator.game_components import Network

# Pytest fixture for creating a sample Network object
@pytest.fixture
def sample_private_network1():
    """Fixture to provide a sample Network object with private IP"""
    return Network("192.168.1.0", 24)

@pytest.fixture
def sample_private_network2():
    """Fixture to provide a sample Network object with private IP different from sample_private_network1"""
    return Network("192.168.2.0", 24)
@pytest.fixture
def sample_public_network():
    """Fixture to provide a sample Network object with public IP"""
    return Network("8.8.8.8", 24)

# Test cases for the Network class
def test_net_creation(sample_private_network1):
    """
    Test that the network is created and all elements can be accessed
    """
    net = sample_private_network1
    assert net.ip == "192.168.1.0"
    assert net.mask == 24

def test_net_str(sample_private_network1):
    """
    Test the string representaion of the network
    """
    net = sample_private_network1
    assert str(net) == "192.168.1.0/24"

def test_net_repr(sample_private_network1):
    """
    Test the repr of the Network
    """
    net = sample_private_network1
    assert repr(net) == "192.168.1.0/24"

def test_net_equal(sample_private_network1, sample_private_network2):
    """
    Test that two network objects with the same paramters are equal
    """
    net_1 = sample_private_network1
    net_2 = sample_private_network2
    assert net_1 == net_2

def test_net_not_equal(sample_private_network1, sample_public_network):
    """
    Test that two network objects with different paramters are not equal
    """
    net_1 = sample_private_network1
    net_2 = sample_public_network
    assert net_1 != net_2

def test_net_is_not_private(sample_public_network):
    net_1 = sample_public_network
    assert net_1.is_private() is False

def test_net_is_private(sample_private_network1):
    net_1 = sample_private_network1
    assert net_1.is_private() is True

def test_net_from_dict(sample_private_network1):
    """
    Test creating a Network object from a dictionary
    """
    d = dataclasses.asdict(sample_private_network1)
    net = Network.from_dict(d)
    assert isinstance(net, Network)
    assert net.ip == "192.168.1.0"
    assert net.mask == 24
    assert net == sample_private_network1
    assert net is not sample_private_network1
# Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
#           Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import pytest
import dataclasses
from netsecgame.game_components import Service

# Fixtures for Service objects
@pytest.fixture
def sample_service1():
    """Fixture to provide a sample Service object with minimal fields"""
    return Service(name="rdp", type="passive", version="1.067", is_local=True)
@pytest.fixture
def sample_service1_copy():
    """Fixture to provide a sample Service object with minimal fields same as sample_service1"""
    return Service(name="rdp", type="passive", version="1.067", is_local=True)
@pytest.fixture
def sample_service2():
    """Fixture to provide a sample Service object with different fields from sample_service1"""
    return Service(name="sql", type="passive", version="5.0", is_local=True)


# Test cases for Service class
def test_service_creation(sample_service1):
    """
    Test that the service is created and all elements can be accessed
    """
    assert sample_service1.name == "rdp"
    assert sample_service1.type == "passive"
    assert sample_service1.version == "1.067"
    assert sample_service1.is_local

def test_services_equal(sample_service1, sample_service1_copy):
    """
    Test that two services with the same parameters are equal
    """
    assert sample_service1 == sample_service1_copy
    assert sample_service1 is not sample_service1_copy

def test_services_not_equal(sample_service1, sample_service2):
    """
    Test that two services with different parameters are not equal
    """
    assert sample_service1 != sample_service2

def test_service_from_dict(sample_service1):
    """
    Test creating a Service object from a dictionary
    """
    service_dict = dataclasses.asdict(sample_service1)
    service_from_dict = Service.from_dict(service_dict)
    assert service_from_dict == sample_service1
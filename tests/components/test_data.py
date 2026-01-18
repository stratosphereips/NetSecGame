# Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
#           Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import pytest
import dataclasses
from netsecgame.game_components import Data

@pytest.fixture
def sample_data_minimal():
    """Fixture to provide a sample Data object with minimal fields"""
    return Data(owner="User", id="Password")
@pytest.fixture
def sample_data_minimal_copy():
    """Fixture to provide a sample Data object with minimal fields same as sample_data_minimal"""
    return Data(owner="User", id="Password")
@pytest.fixture
def sample_data_minimal2():
    """Fixture to provide a sample Data object with minimal fields different from sample_data_minimal"""
    return Data(owner="User2", id="Password")

@pytest.fixture
def sample_data_all():
    """Fixture to provide a sample Data object with all fields"""
    return Data(owner="User", id="Password", size=42, type="txt")

@pytest.fixture
def sample_data_all_copy():
    """Fixture to provide a sample Data object with all fields same as sample_data_all"""
    return Data(owner="User", id="Password", size=42, type="txt")

@pytest.fixture
def sample_data_all2():
    """Fixture to provide a sample Data object with all fields different from sample_data_all"""
    return Data(owner="User2", id="Password", size=42, type="txt")

def test_create_data_minimal(sample_data_minimal):
    """
    Test that the data object is created with ONLY required fields (using default for the rest)
    """
    data = sample_data_minimal
    assert data.owner == "User"
    assert data.id == "Password"
    assert data.type == ""
    assert data.size == 0

def test_create_data_all(sample_data_all):
    """
    Test that the data object is created with ALL fields (using default for the rest)
    """
    data = sample_data_all
    assert data.owner == "User"
    assert data.id == "Password"
    assert data.type == "txt"
    assert data.size == 42

def test_data_equal(sample_data_all, sample_data_all_copy, sample_data_minimal, sample_data_minimal_copy):
    """
    Test that two data objects with the same required parameters are equal
    """
    data = sample_data_all
    data2 = sample_data_all_copy
    # test equality with all fields used
    data3 = sample_data_minimal
    data4 = sample_data_minimal_copy
    assert data == data2
    assert data3 == data4

def test_data_not_equal(sample_data_all, sample_data_all2, sample_data_minimal, sample_data_minimal2):
    """
    Test that two data objects with different required parameters are NOT equal
    """
    data = sample_data_minimal
    data2 = sample_data_minimal2
    data3 = sample_data_all
    data4 = sample_data_all2
    assert data != data2
    assert data3 != data4

def test_data_hash_equal(sample_data_all, sample_data_all_copy, sample_data_minimal, sample_data_minimal_copy):
    """
    Test that the hash of two data objects with the same required parameters is equal
    """
    data = sample_data_minimal
    data2 = sample_data_minimal_copy
    # test equality with all fields used
    data3 = sample_data_all
    data4 = sample_data_all_copy
    assert hash(data) == hash(data2)
    assert hash(data3) == hash(data4)

def test_data_hash_not_equal(sample_data_all, sample_data_all2, sample_data_minimal, sample_data_minimal2):
    data = sample_data_minimal
    data2 = sample_data_minimal2
    # test equality with all fields used
    data3 = sample_data_all
    data4 = sample_data_all2
    assert hash(data) != hash(data2)
    assert hash(data3) != hash(data4)

def test_data_from_dict(sample_data_all):
    d = dataclasses.asdict(sample_data_all)
    data = Data.from_dict(d)
    assert isinstance(data, Data)
    assert data.owner == "User"
    assert data.id == "Password"
    assert data.size == 42
    assert data.type == "txt"
    assert data == sample_data_all
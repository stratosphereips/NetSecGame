# Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
#           Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import json
import pytest
from NetSecGame.game_components import GameState, IP, Network, Data, Service

# pytest fixtures for creating sample objects
@pytest.fixture
def sample_ip():
    """Fixture to provide a sample IP object"""
    return IP("192.168.1.1")

@pytest.fixture
def sample_ip2():
    """Fixture to provide a sample IP object"""
    return IP("192.168.1.2")

@pytest.fixture
def sample_network():
    """Fixture to provide a sample Network object"""
    return Network("192.168.1.0", 24)

@pytest.fixture
def sample_service():
    """Fixture to provide a sample Service object"""
    return Service(name="rdp", type="passive", version="1.067", is_local=True)

@pytest.fixture
def sample_data():
    """Fixture to provide a sample Data object"""
    return Data(owner="User", id="Password", size=42, type="txt")


# Test cases for the GameState class
def test_create_game_state(sample_ip, sample_ip2, sample_network, sample_service, sample_data):
    """
    Test the correct creation of the GameState class
    """
    game_state = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip, sample_ip2},
        known_services={sample_ip:{sample_service}},
        known_data={sample_ip:{sample_data}},
        known_networks={sample_network}
    )

    assert len(game_state.known_hosts) == 2
    assert len(game_state.known_services) == 1
    assert len(game_state.known_data) == 1
    assert len(game_state.known_networks) == 1
    assert sample_ip in game_state.controlled_hosts
    assert sample_ip2 in game_state.known_hosts
    assert sample_ip in game_state.known_hosts
    assert sample_ip in game_state.known_services
    assert sample_service in game_state.known_services[sample_ip]
    assert sample_ip in game_state.known_data
    assert sample_data in game_state.known_data[sample_ip]
    assert sample_network in game_state.known_networks
    assert isinstance(game_state.known_hosts, set)
    assert isinstance(game_state.known_services, dict)
    assert isinstance(game_state.known_data, dict)
    assert isinstance(game_state.known_networks, set)
    assert isinstance(game_state.controlled_hosts, set)
    assert isinstance(game_state, GameState)

def test_create_game_state_empty():
    """
    Test the correct creation of the GameState class with empty parameters
    """
    game_state = GameState(
        controlled_hosts=set(),
        known_hosts=set(),
        known_services=dict(),
        known_data=dict(),
        known_networks=set()
    )

    assert isinstance(game_state.controlled_hosts, set)
    assert isinstance(game_state.known_hosts, set)
    assert isinstance(game_state.known_services, dict)
    assert isinstance(game_state.known_data, dict)
    assert isinstance(game_state.known_networks, set)
    assert len(game_state.controlled_hosts) == 0
    assert len(game_state.known_hosts) == 0
    assert len(game_state.known_services) == 0
    assert len(game_state.known_data) == 0
    assert len(game_state.known_networks) == 0
    assert isinstance(game_state, GameState)

def test_state_equal(sample_ip, sample_ip2, sample_network, sample_service, sample_data):
    """
    Test that two game states with the same parameters are equal
    """
    game_state = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip, sample_ip2},
        known_services={sample_ip:[sample_service]},
        known_data={sample_ip:[sample_data]},
        known_networks={sample_network}
    )

    game_state2 = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip, sample_ip2},
        known_services={sample_ip:[sample_service]},
        known_data={sample_ip:[sample_data]},
        known_networks={sample_network}
    )

    assert game_state == game_state2
    assert game_state is not game_state2  # Ensure they are different instances

def test_state_not_equal_diff_control(sample_ip, sample_ip2, sample_network, sample_service, sample_data):
    """
    Test that two game states with diffrent parameters are not equal.
    Different controlled hosts.
    """
    game_state = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip, sample_ip2},
        known_services={sample_ip:[sample_service]},
        known_data={sample_ip:[sample_data]},
        known_networks={sample_network}
    )

    game_state2 = GameState(
        controlled_hosts={sample_ip2},  # Different controlled hosts
        known_hosts={sample_ip, sample_ip2},
        known_services={sample_ip:[sample_service]},
        known_data={sample_ip:[sample_data]},
        known_networks={sample_network}
    )


    assert game_state != game_state2

def test_state_not_equal_diff_known(sample_ip, sample_ip2, sample_network, sample_service, sample_data):
    """
    Test that two game states with diffrent parameters are not equal
    Different known hosts.
    """
    game_state = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip, sample_ip2},
        known_services={sample_ip:[sample_service]},
        known_data={sample_ip:[sample_data]},
        known_networks={sample_network}
    )

    game_state2 = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip},  # Different known hosts
        known_services={sample_ip:[sample_service]},
        known_data={sample_ip:[sample_data]},
        known_networks={sample_network}
    )
    assert game_state != game_state2

def test_state_not_equal_diff_data(sample_ip, sample_ip2, sample_network, sample_service, sample_data):
    """
    Test that two game states with diffrent parameters are not equal.
    Different data.
    """
    game_state = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip, sample_ip2},
        known_services={sample_ip:[sample_service]},
        known_data={sample_ip:[sample_data]},
        known_networks={sample_network}
    )

    game_state2 = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip, sample_ip2},
        known_services=set(),
        known_data={},  # Different data
        known_networks={sample_network}
    )
    assert game_state != game_state2

def test_state_not_equal_diff_service(sample_ip, sample_ip2, sample_network, sample_service, sample_data):
    """
    Test that two game states with diffrent parameters are not equal.
    """
    game_state = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip, sample_ip2},
        known_services={sample_ip:[sample_service]},
        known_data={sample_ip:[sample_data]},
        known_networks={sample_network}
    )

    game_state2 = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip, sample_ip2},
        known_services={sample_ip2:[sample_service]}, # Different services
        known_data={sample_ip:[sample_data]},
        known_networks={sample_network}
    )

    assert game_state != game_state2


def test_game_state_as_json(sample_ip, sample_ip2, sample_network, sample_service, sample_data):
    """Test the serialization of the GameState class to JSON format"""
    game_state = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip, sample_ip2},
        known_services={sample_ip:[sample_service]},
        known_data={sample_ip:[sample_data]},
        known_networks={sample_network}
    )

    game_json = game_state.as_json()
    try:
        data = json.loads(game_json)
    except ValueError:
        data = None
    # Check if the JSON data is correctly deserialized
    assert data is not None
    assert isinstance(data, dict)
    # Check if the expected keys are present in the JSON data
    assert "known_networks" in data
    assert "known_hosts" in data
    assert "controlled_hosts" in data
    assert "known_services" in data
    assert "known_data" in data
    # Check if the types of the values are correct
    assert isinstance(data["known_networks"], list)
    assert isinstance(data["known_hosts"], list)
    assert isinstance(data["controlled_hosts"], list)
    assert isinstance(data["known_services"], dict)
    assert isinstance(data["known_data"], dict)
    # Check if the values in the JSON data match the original game state
    assert {"ip": "192.168.1.0", "mask": 24} in data["known_networks"]
    assert {"ip": "192.168.1.1"} in data["known_hosts"]
    assert {"ip": "192.168.1.2"} in data["known_hosts"]
    assert {"ip": "192.168.1.1"} in data["controlled_hosts"]
    assert "192.168.1.1" in data["known_services"]
    assert data["known_services"]["192.168.1.1"] == [{"name": "rdp", "type": "passive", "version": "1.067", "is_local": True}]
    assert "192.168.1.1" in data["known_data"]
    assert data["known_data"]["192.168.1.1"] == [{"owner": "User", "id": "Password", "size": 42, "type": "txt", "content": ""}]


def test_game_state_json_deserialized(sample_ip, sample_ip2, sample_network, sample_service, sample_data):
    game_state = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip, sample_ip2},
        known_services={sample_ip:{sample_service}},
        known_data={sample_ip:{sample_data}},
        known_networks={sample_network}
    )
    state_json = game_state.as_json()
    deserialized_state = GameState.from_json(state_json)
    assert game_state is not deserialized_state
    assert game_state == deserialized_state

def test_game_state_as_dict(sample_ip, sample_ip2, sample_network, sample_service, sample_data):
    game_state = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip, sample_ip2},
        known_services={sample_ip:{sample_service}},
        known_data={sample_ip:{sample_data}},
        known_networks={sample_network}
    )
    game_dict = game_state.as_dict
    # Check if the dictionary is correctly created
    assert isinstance(game_dict, dict)
    # Check if the expected keys are present in the dictionary
    assert "known_networks" in game_dict
    assert "known_hosts" in game_dict
    assert "controlled_hosts" in game_dict
    assert "known_services" in game_dict
    assert "known_data" in game_dict
    # Check if the types of the values are correct
    assert isinstance(game_dict["known_networks"], list)
    assert isinstance(game_dict["known_hosts"], list)
    assert isinstance(game_dict["controlled_hosts"], list)
    assert isinstance(game_dict["known_services"], dict)
    assert isinstance(game_dict["known_data"], dict)
    # Check if the values in the dictionary match the original game state
    assert {"ip": "192.168.1.0", "mask": 24} in game_dict["known_networks"]
    assert {"ip": "192.168.1.1"} in game_dict["known_hosts"]
    assert {"ip": "192.168.1.2"} in game_dict["known_hosts"]
    assert {"ip": "192.168.1.1"} in game_dict["controlled_hosts"]
    assert "192.168.1.1" in game_dict["known_services"]
    assert game_dict["known_services"]["192.168.1.1"] == [{"name": "rdp", "type": "passive", "version": "1.067", "is_local": True}]
    assert "192.168.1.1" in game_dict["known_data"]
    assert game_dict["known_data"]["192.168.1.1"] == [{"owner": "User", "id": "Password", "size": 42, "type": "txt", "content": ""}]


def test_game_state_from_dict(sample_ip, sample_ip2, sample_network, sample_service, sample_data):
    game_state = GameState(
        controlled_hosts={sample_ip},
        known_hosts={sample_ip, sample_ip2},
        known_services={sample_ip:{sample_service}},
        known_data={sample_ip:{sample_data}},
        known_networks={sample_network}
    )
    game_dict = game_state.as_dict
    deserialized_state = GameState.from_dict(game_dict)
    assert game_state is not deserialized_state
    assert game_state == deserialized_state
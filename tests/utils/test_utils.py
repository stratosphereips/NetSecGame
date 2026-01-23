import pytest
import json
import logging
from unittest.mock import MagicMock, patch
from netsecgame.utils.utils import (
    get_str_hash,
    state_as_ordered_string,
    observation_as_dict,
    observation_to_str,
    observation_from_dict,
    observation_from_str,
    parse_log_content,
    get_logging_level,
    generate_valid_actions
)
from netsecgame.game_components import (
    GameState,
    Observation,
    Action,
    ActionType,
    IP,
    Network,
    Service,
    Data
)

# --- Fixtures ---

@pytest.fixture
def sample_gamestate():
    net1 = Network("10.0.0.0", 24)
    host1 = IP("10.0.0.1")
    host2 = IP("10.0.0.2")
    service1 = Service("http", "tcp", "80", False)
    data1 = Data("root", "secret", "file", 100)
    
    return GameState(
        controlled_hosts={host1},
        known_hosts={host1, host2},
        known_services={host2: {service1}},
        known_data={host1: {data1}},
        known_networks={net1},
        known_blocks={host1: {host2}}
    )

@pytest.fixture
def sample_observation(sample_gamestate):
    return Observation(
        state=sample_gamestate,
        reward=10.0,
        end=False,
        info={"reason": "test"}
    )

# --- Tests ---

def test_get_str_hash():
    s = "hello world"
    # sha256 of "hello world"
    expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert get_str_hash(s) == expected

def test_state_as_ordered_string(sample_gamestate):
    # This function produces a specific string format.
    # We verify it contains expected substrings and is deterministic.
    s1 = state_as_ordered_string(sample_gamestate)
    s2 = state_as_ordered_string(sample_gamestate)
    assert s1 == s2
    assert "nets:[10.0.0.0/24]" in s1
    assert "hosts:[10.0.0.1,10.0.0.2]" in s1
    assert "services:{10.0.0.2:[Service(name='http', type='tcp', version='80', is_local=False)]}" in s1

def test_observation_conversion_roundtrip(sample_observation):
    # dict conversion
    obs_dict = observation_as_dict(sample_observation)
    assert obs_dict["reward"] == 10.0
    assert obs_dict["end"] is False
    assert obs_dict["info"]["reason"] == "test"
    
    # restore from dict
    obs_restored = observation_from_dict(obs_dict)
    assert obs_restored.reward == sample_observation.reward
    assert obs_restored.end == sample_observation.end
    assert obs_restored.info == sample_observation.info
    # State equality depends on GameState equality implementation
    assert obs_restored.state.known_hosts == sample_observation.state.known_hosts

def test_observation_json_roundtrip(sample_observation):
    # str conversion
    json_str = observation_to_str(sample_observation)
    assert isinstance(json_str, str)
    
    # restore from str
    obs_restored = observation_from_str(json_str)
    assert obs_restored.reward == sample_observation.reward
    assert obs_restored.end == sample_observation.end
    assert obs_restored.state.known_hosts == sample_observation.state.known_hosts

def test_observation_from_dict_error():
    # Invalid input
    with pytest.raises(Exception):
        observation_from_dict({"reward": 10}) # missing state

def test_observation_from_str_error():
    with pytest.raises(Exception):
        observation_from_str("invalid json")

def test_parse_log_content():
    log_json = '[{"source_host": "10.0.0.1", "action_type": "ScanNetwork"}]'
    logs = parse_log_content(log_json)
    assert len(logs) == 1
    assert logs[0]["source_host"] == IP("10.0.0.1")
    assert logs[0]["action_type"] == ActionType.ScanNetwork

def test_parse_log_content_invalid():
    assert parse_log_content("invalid json") is None

def test_get_logging_level():
    assert get_logging_level("DEBUG") == logging.DEBUG
    assert get_logging_level("info") == logging.INFO
    assert get_logging_level("UNKNOWN") == logging.ERROR

def test_generate_valid_actions(sample_gamestate):
    actions = generate_valid_actions(sample_gamestate, include_blocks=True)
    assert isinstance(actions, list)
    assert len(actions) > 0
    # Check for specific expected actions based on sample state
    # Controlled host is 10.0.0.1
    # It should be able to ScanNetwork 10.0.0.0/24
    scan_actions = [a for a in actions if a.type == ActionType.ScanNetwork]
    assert any(a.parameters["target_network"] == Network("10.0.0.0", 24) for a in scan_actions)

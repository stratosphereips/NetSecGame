import pytest
from unittest.mock import MagicMock, patch
from netsecgame import TrajectoryRecorder
from netsecgame.game_components import Action, ActionType, GameState, Network

# Mock objects needed for tests
@pytest.fixture
def mock_action():
    return Action(ActionType.ScanNetwork, parameters={"target": "10.0.0.1"})

@pytest.fixture
def mock_gamestate():
    # Minimal GameState for testing
    return GameState(
        controlled_hosts=set(),
        known_hosts=set(),
        known_services={},
        known_data={},
        known_networks=set()
    )

@pytest.fixture
def recorder():
    return TrajectoryRecorder(agent_name="test_agent", agent_role="Attacker")

def test_initialization(recorder):
    assert recorder.agent_name == "test_agent"
    assert recorder.agent_role == "Attacker"
    data = recorder.get_trajectory()
    assert data["agent_name"] == "test_agent"
    assert data["agent_role"] == "Attacker"
    assert data["trajectory"]["states"] == []
    assert data["trajectory"]["actions"] == []
    assert data["trajectory"]["rewards"] == []
    assert data["end_reason"] is None

def test_add_initial_state(recorder, mock_gamestate):
    recorder.add_initial_state(mock_gamestate)
    data = recorder.get_trajectory()
    assert len(data["trajectory"]["states"]) == 1
    assert data["trajectory"]["states"][0] == mock_gamestate.as_dict

def test_add_step(recorder, mock_action, mock_gamestate):
    recorder.add_step(mock_action, reward=10.0, next_state=mock_gamestate, end_reason=None)
    data = recorder.get_trajectory()
    
    assert len(data["trajectory"]["actions"]) == 1
    assert data["trajectory"]["actions"][0] == mock_action.as_dict
    
    assert len(data["trajectory"]["rewards"]) == 1
    assert data["trajectory"]["rewards"][0] == 10.0
    
    assert len(data["trajectory"]["states"]) == 1
    assert data["trajectory"]["states"][0] == mock_gamestate.as_dict
    
    assert data["end_reason"] is None

def test_add_step_with_end_reason(recorder, mock_action, mock_gamestate):
    recorder.add_step(mock_action, reward=0, next_state=mock_gamestate, end_reason="Timeout")
    data = recorder.get_trajectory()
    assert data["end_reason"] == "Timeout"

def test_reset(recorder, mock_action, mock_gamestate):
    recorder.add_step(mock_action, 10, mock_gamestate)
    recorder.reset()
    data = recorder.get_trajectory()
    
    assert data["trajectory"]["states"] == []
    assert data["trajectory"]["actions"] == []
    assert data["trajectory"]["rewards"] == []
    assert data["end_reason"] is None
    assert data["agent_name"] == "test_agent"

@patch("netsecgame.utils.trajectory_recorder.store_trajectories_to_jsonl")
def test_save_to_file(mock_store, recorder):
    recorder.save_to_file(location="/tmp/logs")
    
    # Check if called with correct args
    mock_store.assert_called_once()
    args, _ = mock_store.call_args
    
    saved_data = args[0]
    location = args[1]
    filename = args[2]
    
    assert saved_data == recorder.get_trajectory()
    assert location == "/tmp/logs"
    assert "test_agent_Attacker" in filename

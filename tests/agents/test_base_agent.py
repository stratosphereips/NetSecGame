import pytest
import json
import socket
from unittest.mock import patch, MagicMock

from netsecgame.agents.base_agent import BaseAgent
from netsecgame.game_components import Action, ActionType, GameStatus, Observation, GameState, AgentRole, ProtocolConfig

class TestAgent(BaseAgent):
    """A concrete implementation of BaseAgent for testing."""
    def __init__(self, host, port, role):
        super().__init__(host, port, role)

@pytest.fixture
def mock_socket():
    with patch('socket.socket') as mock_sock_class:
        mock_sock_instance = MagicMock()
        mock_sock_class.return_value = mock_sock_instance
        yield mock_sock_instance

@pytest.fixture
def agent(mock_socket):
    return TestAgent('localhost', 5000, AgentRole.Attacker)

def test_initialization_success(mock_socket):
    agent = TestAgent('localhost', 5000, AgentRole.Attacker)
    assert agent._connection_details == ('localhost', 5000)
    assert agent.role == AgentRole.Attacker
    assert agent.socket == mock_socket
    mock_socket.connect.assert_called_once_with(('localhost', 5000))

def test_initialization_failure():
    with patch('socket.socket') as mock_sock_class:
        mock_sock_instance = MagicMock()
        mock_sock_instance.connect.side_effect = socket.error("Connection refused")
        mock_sock_class.return_value = mock_sock_instance
        
        agent = TestAgent('localhost', 5000, AgentRole.Attacker)
        assert getattr(agent, "sock", None) is None

def test_terminate_connection(agent, mock_socket):
    assert agent.socket is not None
    agent.terminate_connection()
    mock_socket.close.assert_called_once()
    assert agent.socket is None

def test_del_closes_connection(mock_socket):
    agent = TestAgent('localhost', 5000, AgentRole.Attacker)
    agent.__del__()
    mock_socket.close.assert_called_once()

@patch('netsecgame.agents.base_agent.GameState.from_dict')
def test_communicate_success(mock_from_dict, agent, mock_socket):
    action = Action(ActionType.JoinGame, parameters={})
    
    # Mock response from server
    response_data = {
        "status": "GameStatus.CREATED",
        "observation": {"state": {}, "reward": 0, "end": False, "info": {}},
        "message": "Success"
    }
    encoded_response = json.dumps(response_data).encode() + ProtocolConfig.END_OF_MESSAGE
    mock_socket.recv.side_effect = [encoded_response]

    status, observation, message = agent.communicate(action)

    # Verify sending
    mock_socket.sendall.assert_called_once()
    sent_data = mock_socket.sendall.call_args[0][0]
    assert sent_data == action.to_json().encode()

    # Verify receiving and parsing
    assert status == GameStatus.CREATED
    assert observation["reward"] == 0
    assert observation["end"] is False
    assert message == "Success"

def test_communicate_invalid_action(agent):
    with pytest.raises(ValueError):
        agent.communicate("not_an_action")

def test_communicate_incomplete_response(agent, mock_socket):
    action = Action(ActionType.JoinGame, parameters={})
    # Response without EOF marker
    mock_socket.recv.side_effect = [b"incomplete data", b""]

    with pytest.raises(ConnectionError, match="Unfinished connection."):
        agent.communicate(action)

@patch('netsecgame.agents.base_agent.GameState.from_dict')
def test_register_success(mock_from_dict, agent):
    mock_state = MagicMock(spec=GameState)
    mock_from_dict.return_value = mock_state
    
    observation_dict = {
        "state": {},
        "reward": 0,
        "end": False,
        "info": {}
    }
    with patch.object(agent, 'communicate', return_value=(GameStatus.CREATED, observation_dict, "Registered")) as mock_communicate:
        observation = agent.register()
        
        mock_communicate.assert_called_once()
        action_sent = mock_communicate.call_args[0][0]
        assert action_sent.action_type == ActionType.JoinGame
        assert action_sent.parameters["agent_info"].name == "TestAgent"
        assert action_sent.parameters["agent_info"].role == AgentRole.Attacker.value
        
        assert isinstance(observation, Observation)
        assert observation.reward == 0
        assert observation.end is False

def test_register_failure(agent):
    with patch.object(agent, 'communicate', return_value=(GameStatus.BAD_REQUEST, {}, "Failed")):
        observation = agent.register()
        assert observation is None

@patch('netsecgame.agents.base_agent.GameState.from_dict')
def test_make_step_success(mock_from_dict, agent):
    mock_state = MagicMock(spec=GameState)
    mock_from_dict.return_value = mock_state
    
    action = Action(ActionType.ScanNetwork, parameters={})
    observation_dict = {
        "state": {},
        "reward": 10,
        "end": True,
        "info": {"msg": "found"}
    }
    with patch.object(agent, 'communicate', return_value=(GameStatus.OK, observation_dict, "Step ok")):
        observation = agent.make_step(action)
        
        assert isinstance(observation, Observation)
        assert observation.reward == 10
        assert observation.end is True
        assert observation.info == {"msg": "found"}

def test_make_step_failure(agent):
    action = Action(ActionType.ScanNetwork, parameters={})
    with patch.object(agent, 'communicate', return_value=(GameStatus.BAD_REQUEST, {}, "Step failed")):
        observation = agent.make_step(action)
        assert observation is None

@patch('netsecgame.agents.base_agent.GameState.from_dict')
def test_request_game_reset_success(mock_from_dict, agent):
    mock_state = MagicMock(spec=GameState)
    mock_from_dict.return_value = mock_state
    
    observation_dict = {
        "state": {},
        "reward": 0,
        "end": False,
        "info": {}
    }
    with patch.object(agent, 'communicate', return_value=(GameStatus.OK, observation_dict, "Reset ok")) as mock_communicate:
        observation = agent.request_game_reset(request_trajectory=True, randomize_topology=False, randomize_topology_seed=42)
        
        mock_communicate.assert_called_once()
        action_sent = mock_communicate.call_args[0][0]
        assert action_sent.action_type == ActionType.ResetGame
        assert action_sent.parameters["request_trajectory"] is True
        assert action_sent.parameters["randomize_topology"] is False
        assert action_sent.parameters["randomize_topology_seed"] == 42
        
        assert isinstance(observation, Observation)

def test_request_game_reset_failure(agent):
    with patch.object(agent, 'communicate', return_value=(None, {}, "Reset failed")):
        observation = agent.request_game_reset()
        assert observation is None

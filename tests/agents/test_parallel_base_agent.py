import pytest
from unittest.mock import patch, MagicMock
import socket
from netsecgame.agents.parallel_base_agent import ParallelBaseAgent
from netsecgame.game_components import (
    Action, Observation, ActionType, GameStatus, AgentRole
)

# Helper for empty valid state
VALID_STATE_DICT = {
    "known_networks": [],
    "known_hosts": [],
    "controlled_hosts": [],
    "known_services": {},
    "known_data": {}
}


@pytest.fixture
def mock_socket():
    with patch('netsecgame.agents.parallel_base_agent.socket.socket') as mock_sock:
        yield mock_sock


class TestParallelBaseAgent:

    def test_single_env_init(self, mock_socket):
        agent = ParallelBaseAgent("127.0.0.1", 9000, AgentRole.Attacker)
        assert agent.num_envs == 1
        assert agent._single_env is True
        assert len(agent._sockets) == 1
        assert agent.connected == [True]
        
    def test_broadcast_host_init(self, mock_socket):
        agent = ParallelBaseAgent("127.0.0.1", [9000, 9001, 9002], AgentRole.Attacker)
        assert agent.num_envs == 3
        assert agent._single_env is False
        assert len(agent._sockets) == 3
        assert agent.connected == [True, True, True]

    def test_multi_host_init(self, mock_socket):
        agent = ParallelBaseAgent(["127.0.0.1", "127.0.0.2"], [9000, 9001], AgentRole.Attacker)
        assert agent.num_envs == 2
        assert agent._single_env is False
        
    def test_mismatched_lengths(self, mock_socket):
        with pytest.raises(ValueError, match="must be 1 .* or match game_ports length"):
            ParallelBaseAgent(["127.0.0.1", "127.0.0.2"], [9000, 9001, 9002], AgentRole.Attacker)

    def test_connection_failures(self, mock_socket):
        mock_instance = MagicMock()
        def connect_side_effect(addr):
            if addr[1] == 9001:
                raise socket.error("Mocked connection error")
        mock_instance.connect.side_effect = connect_side_effect
        mock_socket.return_value = mock_instance
        
        agent = ParallelBaseAgent("127.0.0.1", [9000, 9001, 9002], AgentRole.Attacker)
        assert agent.num_envs == 3
        assert agent.connected == [True, False, True]
        assert agent._sockets[1] is None
        assert agent.done_mask == [False, True, False]

    def test_terminate_connection(self, mock_socket):
        mock_socket.side_effect = lambda *args, **kwargs: MagicMock()
        agent = ParallelBaseAgent("127.0.0.1", [9000, 9001], AgentRole.Attacker)
        sockets = list(agent._sockets)
        agent.terminate_connection()
        
        for sock in sockets:
            sock.close.assert_called_once()
        assert agent._sockets == [None, None]

    @patch('netsecgame.agents.parallel_base_agent.ParallelBaseAgent._communicate_single')
    def test_register_single_env(self, mock_comm, mock_socket):
        mock_comm.return_value = (
            GameStatus.CREATED,
            {"state": VALID_STATE_DICT, "reward": 0, "end": False},
            "Registered"
        )
        agent = ParallelBaseAgent("127.0.0.1", 9000, AgentRole.Attacker)
        obs = agent.register()
        
        assert isinstance(obs, Observation)
        assert agent.done_mask is False

    @patch('netsecgame.agents.parallel_base_agent.ParallelBaseAgent._communicate_single')
    def test_register_multi_env(self, mock_comm, mock_socket):
        mock_comm.side_effect = [
            (GameStatus.CREATED, {"state": VALID_STATE_DICT, "reward": 0, "end": False}, "Registered"),
            (GameStatus.CREATED, {"state": VALID_STATE_DICT, "reward": 1, "end": False}, "Registered")
        ]
        
        agent = ParallelBaseAgent("127.0.0.1", [9000, 9001], AgentRole.Attacker)
        obs_list = agent.register()
        
        assert len(obs_list) == 2
        assert isinstance(obs_list[0], Observation)
        assert isinstance(obs_list[1], Observation)
        assert agent.done_mask == [False, False]

    @patch('netsecgame.agents.parallel_base_agent.ParallelBaseAgent._communicate_single')
    def test_register_partial_failure(self, mock_comm, mock_socket):
        mock_comm.side_effect = [
            (GameStatus.CREATED, {"state": VALID_STATE_DICT, "reward": 0, "end": False}, "Registered"),
            (GameStatus.BAD_REQUEST, {}, "Failed")
        ]
        agent = ParallelBaseAgent("127.0.0.1", [9000, 9001], AgentRole.Attacker)
        obs_list = agent.register()
        
        assert obs_list[0] is not None
        assert obs_list[1] is None
        assert agent.done_mask == [False, True]

    @patch('netsecgame.agents.parallel_base_agent.ParallelBaseAgent._communicate_single')
    def test_make_step_single_env(self, mock_comm, mock_socket):
        mock_comm.return_value = (
            GameStatus.OK, 
            {"state": VALID_STATE_DICT, "reward": 1, "end": False, "info": {}}, 
            "Step 1"
        )
        agent = ParallelBaseAgent("127.0.0.1", 9000, AgentRole.Attacker)
        agent._done_mask = [False]
        obs = agent.make_step(Action(ActionType.ScanNetwork))
        
        assert isinstance(obs, Observation)
        assert agent.done_mask is False

    @patch('netsecgame.agents.parallel_base_agent.ParallelBaseAgent._communicate_single')
    def test_make_step_multi_env(self, mock_comm, mock_socket):
        mock_comm.side_effect = [
            (GameStatus.OK, {"state": VALID_STATE_DICT, "reward": 0, "end": False, "info": {}}, "Step 1"),
            (GameStatus.OK, {"state": VALID_STATE_DICT, "reward": 1, "end": True, "info": {}}, "Step 2")
        ]
        
        agent = ParallelBaseAgent("127.0.0.1", [9000, 9001], AgentRole.Attacker)
        agent._done_mask = [False, False]
        actions = [Action(ActionType.ScanNetwork), Action(ActionType.ScanNetwork)]
        
        obs_list = agent.make_step(actions)
        
        assert len(obs_list) == 2
        assert obs_list[0].end is False
        assert obs_list[1].end is True
        
        assert agent.done_mask == [False, True]
        assert agent.all_done is False

    @patch('netsecgame.agents.parallel_base_agent.ParallelBaseAgent._communicate_single')
    def test_make_step_skips_done(self, mock_comm, mock_socket):
        mock_comm.side_effect = [
            (GameStatus.OK, {"state": VALID_STATE_DICT, "reward": 0, "end": False, "info": {}}, "Step 1"),
        ]
        
        agent = ParallelBaseAgent("127.0.0.1", [9000, 9001], AgentRole.Attacker)
        agent._done_mask = [False, True]
        
        actions = [Action(ActionType.ScanNetwork), Action(ActionType.ScanNetwork)]
        obs_list = agent.make_step(actions)
        
        assert len(obs_list) == 2
        assert isinstance(obs_list[0], Observation)
        assert obs_list[1] is None
        assert mock_comm.call_count == 1
        
    @patch('netsecgame.agents.parallel_base_agent.ParallelBaseAgent._communicate_single')
    def test_request_game_reset(self, mock_comm, mock_socket):
        mock_comm.side_effect = [
            (GameStatus.RESET_DONE, {"state": VALID_STATE_DICT, "reward": 0, "end": False}, "Reset"),
            (GameStatus.RESET_DONE, {"state": VALID_STATE_DICT, "reward": 0, "end": False}, "Reset")
        ]
        
        agent = ParallelBaseAgent("127.0.0.1", [9000, 9001], AgentRole.Attacker)
        agent._done_mask = [True, True]
        
        obs_list = agent.request_game_reset()
        
        assert len(obs_list) == 2
        assert agent.done_mask == [False, False]

    def test_request_game_reset_topology_no_seed(self, mock_socket):
        agent = ParallelBaseAgent("127.0.0.1", 9000, AgentRole.Attacker)
        with pytest.raises(ValueError, match="Topology randomization without seed is not supported."):
            agent.request_game_reset(randomize_topology=True, seed=None)
            
    def test_run_parallel_exception_isolation(self, mock_socket):
        agent = ParallelBaseAgent("127.0.0.1", [9000, 9001, 9002], AgentRole.Attacker)
        agent._done_mask = [False, False, False]
        
        def faulty_fn(env_idx):
            if env_idx == 1:
                raise ValueError("Thread crash")
            return f"Success {env_idx}"
            
        results = agent._run_parallel(faulty_fn)
        
        assert results == ["Success 0", None, "Success 2"]

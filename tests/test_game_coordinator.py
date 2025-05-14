import asyncio
import pytest
from unittest.mock import AsyncMock, Mock
from AIDojoCoordinator.coordinator import AgentServer, GameCoordinator

def test_game_coordinator_initialization():
    """
    Test that the GameCoordinator is initialized correctly with the expected properties.
    """
    # Test input
    game_host = "localhost"
    game_port = 8000
    service_host = "localhost"
    service_port = 8080
    allowed_roles = ["Attacker", "Defender", "Benign"]
    task_config_file = "test_config.json"

    # Create an instance of GameCoordinator
    coordinator = GameCoordinator(
        game_host=game_host,
        game_port=game_port,
        service_host=service_host,
        service_port=service_port,
        allowed_roles=allowed_roles,
        task_config_file=task_config_file,
    )

    # Assertions for basic initialization
    assert coordinator.host == game_host, "GameCoordinator host should be set correctly."
    assert coordinator.port == game_port, "GameCoordinator port should be set correctly."
    assert coordinator._service_host == service_host, "Service host should be set correctly."
    assert coordinator._service_port == service_port, "Service port should be set correctly."
    assert coordinator.ALLOWED_ROLES == allowed_roles, "Allowed roles should match the input."
    assert coordinator._task_config_file == task_config_file, "Task config file should match the input."

    # Assertions for events and locks
    assert isinstance(coordinator.shutdown_flag, asyncio.Event), "shutdown_flag should be an asyncio.Event."
    assert isinstance(coordinator._reset_event, asyncio.Event), "reset_event should be an asyncio.Event."
    assert isinstance(coordinator._episode_end_event, asyncio.Event), "episode_end_event should be an asyncio.Event."
    assert isinstance(coordinator._reset_lock, asyncio.Lock), "reset_lock should be an asyncio.Lock."
    assert isinstance(coordinator._agents_lock, asyncio.Lock), "agents_lock should be an asyncio.Lock."

    # Assertions for agent-related data structures
    assert isinstance(coordinator._agent_action_queue, asyncio.Queue), "agent_action_queue should be an asyncio.Queue."
    assert isinstance(coordinator._agent_response_queues, dict), "agent_response_queues should be a dictionary."
    assert isinstance(coordinator.agents, dict), "agents should be a dictionary."
    assert isinstance(coordinator._agent_steps, dict), "agent_steps should be a dictionary."
    assert isinstance(coordinator._reset_requests, dict), "reset_requests should be a dictionary."
    assert isinstance(coordinator._agents_status, dict), "agent_status should be a dictionary."
    assert isinstance(coordinator._agent_observations, dict), "agent_observations should be a dictionary."
    assert isinstance(coordinator._agent_rewards, dict), "agent_rewards should be a dictionary."
    assert isinstance(coordinator._agent_trajectories, dict), "agent_trajectories should be a dictionary."

    # Assertions for tasks
    assert isinstance(coordinator._tasks, set), "tasks should be a set."

    # Assertions for configuration
    assert coordinator._cyst_objects is None, "cyst_objects should be None at initialization."
    assert coordinator._cyst_object_string is None, "cyst_object_string should be None at initialization."

    # Assertions for logging
    assert coordinator.logger.name == "AIDojo-GameCoordinator", "Logger should be initialized with the correct name."


def test_starting_positions():
    """Test that starting positions are correctly initialized for each role."""
    coordinator = GameCoordinator(
        game_host="localhost",
        game_port=8000,
        service_host="localhost",
        service_port=8080,
        allowed_roles=["Attacker", "Defender", "Benign"],
    )
    coordinator.task_config = Mock()  # Mock the task_config
    coordinator.task_config.get_start_position.side_effect = lambda agent_role: {"x": 0, "y": 0}

    starting_positions = coordinator._get_starting_position_per_role()

    assert starting_positions["Attacker"] == {"x": 0, "y": 0}
    assert starting_positions["Defender"] == {"x": 0, "y": 0}
    assert starting_positions["Benign"] == {"x": 0, "y": 0}



# Agent Server
def test_agent_server_initialization():
    """
    Test that the AgentServer is initialized correctly with the expected attributes.
    """
    # Test inputs
    actions_queue = asyncio.Queue()
    agent_response_queues = {}
    max_connections = 5

    # Create an instance of AgentServer
    server = AgentServer(actions_queue, agent_response_queues, max_connections)

    # Assertions for basic attributes
    assert server.actions_queue is actions_queue, "AgentServer's actions_queue should be set correctly."
    assert server.answers_queues is agent_response_queues, "AgentServer's answers_queues should be set correctly."
    assert server.max_connections == max_connections, "AgentServer's max_connections should match the input."
    assert server.current_connections == 0, "AgentServer's current_connections should be initialized to 0."

    # Assertions for logging
    assert server.logger.name == "AIDojo-AgentServer", "Logger should be initialized with the correct name."


@pytest.mark.asyncio
async def test_handle_new_agent_max_connections():
    """Test that a new agent connection is rejected when max_connections is reached."""
    # Test setup
    actions_queue = asyncio.Queue()
    agent_response_queues = {}
    max_connections = 1
    server = AgentServer(actions_queue, agent_response_queues, max_connections)

    # Mock reader and writer
    reader_mock = AsyncMock()
    writer_mock = Mock()
    writer_mock.get_extra_info.return_value = ("127.0.0.1", 12345)

    # Simulate max connections
    server.current_connections = max_connections

    # Run handle_new_agent
    await server.handle_new_agent(reader_mock, writer_mock)

    # Assertions
    assert server.current_connections == max_connections, "Connection count should remain unchanged."
    assert ("127.0.0.1", 12345) not in agent_response_queues, "Queue should not be created for rejected agent."
    writer_mock.write.assert_not_called(), "No data should be sent to the rejected agent."
    writer_mock.close.assert_called_once(), "Connection should be closed for the rejected agent."

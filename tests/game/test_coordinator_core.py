# Authors:  Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace

from netsecgame.game.coordinator import GameCoordinator
from netsecgame.game_components import ActionType, Action, AgentStatus, GameState, Observation, GameStatus

# -----------------------
# Fixtures
# -----------------------
@pytest.fixture
def empty_game_state():
    """Fixture of empty game state."""
    return GameState(
        known_networks={},
        known_services={},
        known_hosts={},
        known_data={},
        known_blocks={},
        controlled_hosts= {},
    )
@pytest.fixture
def empty_observation(empty_game_state):
    """Fixture of empty observation."""
    return Observation(
        state=empty_game_state,
        reward=0,
        end=False,
        info={},
    )

@pytest.fixture
def test_config_file_path():
    # Path to your local test config file (adjust as needed)
    return "tests/netsecenv-task-for-testing.yaml"

@pytest.fixture
def gc_with_test_config(test_config_file_path):
    return GameCoordinator(
        game_host="localhost",
        game_port=9999,
        service_host=None,  # force local config loading
        service_port=0,
        allowed_roles=["Attacker", "Defender", "Benign"],
        task_config_file=test_config_file_path,
    )


@pytest.fixture
def initialized_coordinator(gc_with_test_config):
    gc_with_test_config._starting_positions_per_role = {"Attacker": MagicMock()}
    gc_with_test_config._goal_description_per_role = {"Attacker": "Achieve goal"}
    gc_with_test_config._steps_limit_per_role = {"Attacker": 100}
    gc_with_test_config._CONFIG_FILE_HASH = "dummyhash"
    gc_with_test_config._min_required_players = 1
    gc_with_test_config._agent_status = {}
    gc_with_test_config._rewards = {"step": 0, "success": 10, "failure": -10}
    return gc_with_test_config

@pytest.fixture
def mock_writer():
    writer = AsyncMock()
    writer.get_extra_info.return_value = ("127.0.0.1", 12345)
    return writer

@pytest.fixture
def mock_reader_empty():
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=b"")  # Simulate client disconnect
    return reader

@pytest.fixture
def agent_server():
    """Fixture for a mock agent server."""
    return GameCoordinator(
        game_host="localhost",
        game_port=9999,
        service_host=None,
        service_port=0,
        allowed_roles=["Attacker", "Defender", "Benign"],
        task_config_file=None,
    )

@pytest.fixture
def make_writer_with_peer():
    def _make(ip: str, port: int):
        writer = AsyncMock()
        writer.get_extra_info.return_value = (ip, port)
        return writer
    return _make

# -----------------------
# GameCoordinator Tests (Config-related)
# -----------------------

@pytest.mark.asyncio
async def test_load_initialization_objects_loads_config(gc_with_test_config):
    """Test that loading initialization objects sets up config and cyst objects."""
    gc_with_test_config._load_initialization_objects()
    assert gc_with_test_config._cyst_objects is not None
    assert hasattr(gc_with_test_config, "_CONFIG_FILE_HASH")

def test_convert_msg_dict_to_json_success(gc_with_test_config):
    """Test that convert_msg_dict_to_json correctly serializes a dictionary."""
    msg = {"foo": "bar"}
    json_str = gc_with_test_config.convert_msg_dict_to_json(msg)
    assert json_str == '{"foo": "bar"}'


def test_convert_msg_dict_to_json_failure(gc_with_test_config):
    """Test that convert_msg_dict_to_json raises TypeError for unserializable objects."""
    class Unserializable:
        pass

    with pytest.raises(TypeError):
        gc_with_test_config.convert_msg_dict_to_json({"bad": Unserializable()})


@pytest.mark.asyncio
async def test_create_agent_queue_adds_new_queue(gc_with_test_config):
    """Test that create_agent_queue adds a new queue for the agent."""
    agent = ("127.0.0.1", 12345)
    await gc_with_test_config.create_agent_queue(agent)
    assert agent in gc_with_test_config._agent_response_queues
    assert isinstance(gc_with_test_config._agent_response_queues[agent], asyncio.Queue)


@pytest.mark.asyncio
async def test_create_agent_queue_idempotent(gc_with_test_config):
    """Test that create_agent_queue does not create a new queue if it already exists."""
    agent = ("127.0.0.1", 12345)
    await gc_with_test_config.create_agent_queue(agent)
    q1 = gc_with_test_config._agent_response_queues[agent]
    await gc_with_test_config.create_agent_queue(agent)
    q2 = gc_with_test_config._agent_response_queues[agent]
    assert q1 is q2


def test_load_initialization_objects(gc_with_test_config):
    """Test that _load_initialization_objects initializes config and cyst objects."""
    gc_with_test_config._load_initialization_objects()
    assert gc_with_test_config._cyst_objects is not None
    assert hasattr(gc_with_test_config, "_CONFIG_FILE_HASH")


def test_get_starting_position_per_role(gc_with_test_config):
    """Test that _get_starting_position_per_role returns positions for all roles."""
    gc_with_test_config._load_initialization_objects()
    positions = gc_with_test_config._get_starting_position_per_role()
    assert set(positions.keys()) == set(gc_with_test_config.ALLOWED_ROLES)


def test_get_goal_description_per_role(gc_with_test_config):
    """Test that _get_goal_description_per_role returns descriptions for all roles."""
    gc_with_test_config._load_initialization_objects()
    desc = gc_with_test_config._get_goal_description_per_role()
    assert set(desc.keys()) == set(gc_with_test_config.ALLOWED_ROLES)


def test_get_win_condition_per_role(gc_with_test_config):
    """Test that _get_win_condition_per_role returns win conditions for all roles."""
    gc_with_test_config._load_initialization_objects()
    win = gc_with_test_config._get_win_condition_per_role()
    assert set(win.keys()) == set(gc_with_test_config.ALLOWED_ROLES)


def test_get_max_steps_per_role(gc_with_test_config):
    """Test that _get_max_steps_per_role returns max steps for all roles."""
    gc_with_test_config._load_initialization_objects()
    steps = gc_with_test_config._get_max_steps_per_role()
    assert isinstance(steps, dict)
    # values can be int or None
    assert all(isinstance(v, int) or v is None for v in steps.values())


@pytest.mark.asyncio
async def test_shutdown_signal_handler_sets_flag(gc_with_test_config):
    """Test that shutdown_signal_handler sets the shutdown flag."""
    assert not gc_with_test_config.shutdown_flag.is_set()
    await gc_with_test_config.shutdown_signal_handler()
    assert gc_with_test_config.shutdown_flag.is_set()


@pytest.mark.asyncio
async def test_spawn_task_registers_task(gc_with_test_config):
    """Test that _spawn_task registers the task in _tasks."""
    async def dummy():
        await asyncio.sleep(0.01)

    task = gc_with_test_config._spawn_task(dummy)
    assert task in gc_with_test_config._tasks

    await task  # Make sure task completes


@pytest.mark.asyncio
@pytest.mark.parametrize("action_type", [
    ActionType.QuitGame,
    ActionType.ResetGame,
    ActionType.FindData,
    ActionType.ExfiltrateData,
    ActionType.BlockIP,
    ActionType.ExploitService,
])
async def test_run_game_spawns_expected_action_tasks(gc_with_test_config, action_type):
    """Test that run_game spawns tasks for different action types."""
    dummy_action = MagicMock()
    dummy_action.type = action_type
    dummy_json = json.dumps({"type": action_type.value})

    # Put real test message
    gc_with_test_config._agent_action_queue.put_nowait((("127.0.0.1", 9999), dummy_json))

    # Patch Action.from_json to return our dummy
    with patch.object(Action, "from_json", return_value=dummy_action):
        with patch.object(gc_with_test_config, "_spawn_task") as spawn_mock:
            
            async def stop_soon():
                await asyncio.sleep(0.01)
                gc_with_test_config.shutdown_flag.set()
                # Poison pill: unblock .get() after shutdown
                gc_with_test_config._agent_action_queue.put_nowait((("0.0.0.0", 0), None))

            stopper = asyncio.create_task(stop_soon())

            await gc_with_test_config.run_game()
            await stopper

            spawn_mock.assert_called_once()
            assert spawn_mock.call_args[0][0].__name__.startswith("_process_")

# -----------------------
# GameCoordinator Tests (Action Processing)
# -----------------------   
@pytest.mark.asyncio
async def test_process_join_game_action_success(initialized_coordinator):
    """Test that _process_join_game_action successfully processes a join game action."""
    agent = ("127.0.0.1", 5555)
    await initialized_coordinator.create_agent_queue(agent)

    # Minimal working state
    initialized_coordinator._starting_positions_per_role = {"Attacker": MagicMock()}
    initialized_coordinator._goal_description_per_role = {"Attacker": "Goal"}
    initialized_coordinator._win_conditions_per_role = {"Attacker": MagicMock()}
    initialized_coordinator._steps_limit_per_role = {"Attacker": 10}
    initialized_coordinator._CONFIG_FILE_HASH = "abc123"
    initialized_coordinator._min_required_players = 1
    initialized_coordinator._agent_status = {agent: MagicMock()}
    initialized_coordinator._episode_start_event.set()  # Prevent wait

    action = MagicMock()
    agent_info = MagicMock()
    agent_info.name = "AgentX"
    agent_info.role = "Attacker"
    action.parameters = {"agent_info": agent_info}
    observation = SimpleNamespace(
        state=SimpleNamespace(as_dict={}),  # empty dict works here
        reward=0,
        end=False,
        info={}
    )

    with patch.object(initialized_coordinator, "register_agent", new_callable=AsyncMock, return_value=(MagicMock(),MagicMock())), \
         patch.object(initialized_coordinator, "_initialize_new_player", return_value=observation), \
         patch.object(initialized_coordinator.logger, "info"), \
         patch.object(initialized_coordinator.logger, "debug"):
        await initialized_coordinator._process_join_game_action(agent, action)
        assert agent in initialized_coordinator.agents
        assert not initialized_coordinator._agent_response_queues[agent].empty()

@pytest.mark.asyncio
async def test_process_quit_game_action_removal(initialized_coordinator, empty_game_state, empty_observation):
    """Test that _process_quit_game_action removes an agent correctly."""
    agent = ("127.0.0.1", 5555)
    initialized_coordinator._agent_states[agent] = empty_game_state
    initialized_coordinator._agent_observations[agent] = empty_observation

    with patch.object(initialized_coordinator, "remove_agent", new_callable=AsyncMock) as remove_mock, \
         patch.object(initialized_coordinator, "_remove_agent_from_game", new_callable=AsyncMock) as remove_game_mock, \
         patch.object(initialized_coordinator.logger, "info") as log_info, \
         patch.object(initialized_coordinator.logger, "debug") as log_debug:

        await initialized_coordinator._process_quit_game_action(agent)

        remove_mock.assert_awaited_once_with(agent, initialized_coordinator._agent_states[agent])
        remove_game_mock.assert_awaited_once_with(agent)
        log_info.assert_any_call(f"Agent {agent} removed from the game. {remove_game_mock.return_value}")
        log_debug.assert_any_call(f"Cleaning up after QuitGame for {agent}.")

@pytest.mark.asyncio
async def test_process_reset_game_action_sets_flag(initialized_coordinator, empty_observation):
    """Test that _process_reset_game_action sets the reset flag"""
    agent = ("127.0.0.1", 5555)
    initialized_coordinator._reset_requests = {agent: False}
    initialized_coordinator._agent_observations[agent] = empty_observation
    initialized_coordinator._episode_start_event.set()
    initialized_coordinator._goal_description_per_role = {"Attacker": "Goal"}
    initialized_coordinator._steps_limit_per_role = {"Attacker": 10}
    initialized_coordinator.agents[agent] = ("name", "Attacker")
    initialized_coordinator._agent_trajectories[agent] = [1, 2, 3]
    initialized_coordinator._CONFIG_FILE_HASH = "hash"
    initialized_coordinator._reset_trajectory = lambda x: []

    await initialized_coordinator.create_agent_queue(agent)
    reset_action = MagicMock()
    reset_action.parameters = {"request_trajectory": True}

    with patch.object(initialized_coordinator.logger, "debug"):
        async def trigger_reset_done():
            await asyncio.sleep(0.01)
            async with initialized_coordinator._reset_done_condition:
                initialized_coordinator._reset_done_condition.notify_all()

        stopper = asyncio.create_task(trigger_reset_done())
        await initialized_coordinator._process_reset_game_action(agent, reset_action)
        await stopper
        assert not initialized_coordinator._agent_response_queues[agent].empty()

@pytest.mark.asyncio
async def test_process_game_action_episode_ended(initialized_coordinator, empty_game_state):
    agent = ("127.0.0.1", 5555)
    action = Action(action_type = ActionType.FindData, parameters={})  # or any game action type

    # Setup state indicating episode ended for the agent
    initialized_coordinator._episode_ends = {agent: True}
    initialized_coordinator.agents = {agent: ("AgentName", "Attacker")}
    initialized_coordinator._agent_observations = {agent: Observation(empty_game_state, reward=5, end=True, info={})}
    initialized_coordinator._agent_rewards = {agent: 5}
    initialized_coordinator._agent_status = {agent: AgentStatus.TimeoutReached}
    await initialized_coordinator.create_agent_queue(agent)

    # Call the method
    await initialized_coordinator._process_game_action(agent, action)

    # Check response queue got a message with FORBIDDEN status
    msg_json = await initialized_coordinator._agent_response_queues[agent].get()
    assert '"status": "' + str(GameStatus.FORBIDDEN) + '"' in msg_json
    assert "Episode ended" in msg_json


@pytest.mark.asyncio
async def test_process_game_action_ongoing_episode(initialized_coordinator, empty_game_state):
    agent = ("127.0.0.1", 5555)
    action = Action(action_type = ActionType.FindData, parameters={})  # or any game action type

    # Setup state indicating episode ongoing for the agent
    initialized_coordinator._episode_ends = {agent: False}
    initialized_coordinator.agents = {agent: ("AgentName", "Attacker")}
    initialized_coordinator._agent_states = {agent: empty_game_state}
    initialized_coordinator._agent_last_action = {agent: None}
    initialized_coordinator._agent_steps = {agent: 0}
    initialized_coordinator._agent_status = {agent: AgentStatus.Playing}
    initialized_coordinator._agent_rewards = {agent: 0}
    initialized_coordinator._agent_observations = {agent: Observation(empty_game_state, reward=0, end=False, info={})}
    await initialized_coordinator.create_agent_queue(agent)

    # Mocks and patches
    initialized_coordinator.step = AsyncMock(return_value=empty_game_state)
    initialized_coordinator._update_agent_status = MagicMock(return_value=AgentStatus.Playing)
    initialized_coordinator._update_agent_episode_end = MagicMock(return_value=False)
    initialized_coordinator._add_step_to_trajectory = MagicMock()
    initialized_coordinator._episode_end_event.clear()
    initialized_coordinator._episode_rewards_condition = asyncio.Condition()
    initialized_coordinator._agents_lock = asyncio.Lock()

    # Call the method
    await initialized_coordinator._process_game_action(agent, action)

    # Check that step was called with expected params
    initialized_coordinator.step.assert_awaited_with(agent_id=agent, agent_state=empty_game_state, action=action)

    # Check response queue got a message with OK status
    msg_json = await initialized_coordinator._agent_response_queues[agent].get()
    assert '"status": "' + str(GameStatus.OK) + '"' in msg_json
    assert '"reward": 0' in msg_json
    assert '"end": false' in msg_json
    assert '"info": {}' in msg_json

# -----------------------
# New tests for refactored methods (_parse_action, _dispatch_action, run_game)
# -----------------------
class TestCoordinatorRefactoredMethods:
    @pytest.fixture
    def mock_coordinator_core(self):
        # Create a mock coordinator slightly different from integration fixtures to purely test logic
        coord = MagicMock(spec=GameCoordinator)
        coord.logger = MagicMock()
        coord._agent_action_queue = AsyncMock()
        coord.shutdown_flag = MagicMock()
        # Side effect to stop loop after one iteration
        coord.shutdown_flag.is_set.side_effect = [False, True]
        
        # Bind refactored methods
        coord._parse_action_message = GameCoordinator._parse_action_message.__get__(coord)
        coord._dispatch_action = GameCoordinator._dispatch_action.__get__(coord)
        coord.run_game = GameCoordinator.run_game.__get__(coord)
        
        # Set __name__ for the mocked handlers so assert .__name__ works
        coord._process_join_game_action.__name__ = "_process_join_game_action"
        coord._process_quit_game_action.__name__ = "_process_quit_game_action"
        coord._process_reset_game_action.__name__ = "_process_reset_game_action"
        coord._process_game_action.__name__ = "_process_game_action"
        
        return coord

    def test_parse_action_message_valid(self, mock_coordinator_core):
        """New test for refactored method: _parse_action_message with valid input."""
        from netsecgame.game_components import AgentRole
        valid_json = '{"action_type": "ActionType.JoinGame", "parameters": {"agent_info": {"name": "TestAgent", "role": "Attacker"}}}'
        agent_addr = ("127.0.0.1", 12345)
        
        action = mock_coordinator_core._parse_action_message(agent_addr, valid_json)
        
        assert action is not None
        assert action.type == ActionType.JoinGame
        assert action.parameters["agent_info"].role == AgentRole.Attacker

    def test_parse_action_message_invalid(self, mock_coordinator_core):
        """New test for refactored method: _parse_action_message with invalid input."""
        invalid_json = '{"invalid": "json"}'
        agent_addr = ("127.0.0.1", 12345)
        
        action = mock_coordinator_core._parse_action_message(agent_addr, invalid_json)
        
        assert action is None
        mock_coordinator_core.logger.error.assert_called()
        # Verify agent address is in the error log
        args, _ = mock_coordinator_core.logger.error.call_args
        assert str(agent_addr) in args[0]

    def test_dispatch_action(self, mock_coordinator_core):
        """New test for refactored method: _dispatch_action routing."""
        action = Action(ActionType.ScanNetwork, parameters={})
        agent_addr = ("127.0.0.1", 12345)
        
        mock_coordinator_core._dispatch_action(agent_addr, action)
        
        mock_coordinator_core._spawn_task.assert_called_once()
        args = mock_coordinator_core._spawn_task.call_args[0]
        # Should route to _process_game_action for ScanNetwork
        assert args[0].__name__ == "_process_game_action"

    @pytest.mark.asyncio
    async def test_run_game_flow(self, mock_coordinator_core):
        """New test for refactored method: run_game flow (parse -> dispatch)."""
        agent_addr = ("127.0.0.1", 12345)
        valid_json = '{"action_type": "ActionType.ScanNetwork", "parameters": {}}'
        
        # Setup queue
        mock_coordinator_core._agent_action_queue.get.return_value = (agent_addr, valid_json)
        
        with patch.object(mock_coordinator_core, '_parse_action_message') as mock_parse, \
             patch.object(mock_coordinator_core, '_dispatch_action') as mock_dispatch:
             
            mock_action = Action(ActionType.ScanNetwork, {})
            mock_parse.return_value = mock_action
            
            await mock_coordinator_core.run_game()
            
            mock_parse.assert_called_once_with(agent_addr, valid_json)
            mock_dispatch.assert_called_once_with(agent_addr, mock_action)
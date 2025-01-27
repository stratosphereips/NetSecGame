# from coordinator import Coordinator, AgentStatus
# import pytest
# import queue
# import asyncio

# CONFIG_FILE = "tests/netsecenv-task-for-testing.yaml"
# ALLOWED_ROLES = ["Attacker", "Defender", "Benign"]

# import sys
# from os import path

# sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
# from env.game_components import Action, ActionType, AgentInfo, Network, IP, GameState, Service, Data


# @pytest.fixture
# async def coordinator_init():
#     """Initialize Coordinator instance for tests."""
#     actions = asyncio.Queue()
#     answers = {}
#     world_requests = asyncio.Queue()
#     world_responses = asyncio.Queue()

#     coord = Coordinator(
#         actions, answers, world_requests, world_responses, CONFIG_FILE, ALLOWED_ROLES
#     )
#     return coord

# @pytest.fixture
# async def coordinator_registered_player(coordinator_init):
#     """Register a player with the Coordinator."""
#     coord = coordinator_init
#     registration = Action(
#         ActionType.JoinGame,
#         params={"agent_info": AgentInfo(name="mari", role="Attacker")},
#     )

#     # Process join action asynchronously
#     result = await coord._process_join_game_action(
#         agent_addr=("192.168.1.1", "3300"),
#         action=registration,
#     )
#     return coord, result
# class TestCoordinator:
    
#     @pytest.mark.asyncio
#     async def test_class_init():
#         actions = asyncio.Queue()
#         answers = {}
#         world_requests = asyncio.Queue()
#         world_responses = asyncio.Queue()

#         coord = Coordinator(actions, answers, world_requests, world_responses, CONFIG_FILE, ALLOWED_ROLES)

#         assert coord.ALLOWED_ROLES == ALLOWED_ROLES
#         assert coord.agents == {}
#         assert coord._agent_steps == {}
#         assert coord._reset_requests == {}
#         assert coord._agent_starting_position == {}
#         assert coord._agent_observations == {}
#         assert coord._agent_states == {}
#         assert coord._agent_rewards == {}
#         assert coord._agent_statuses == {}
#         assert isinstance(coord._actions_queue, asyncio.Queue)
#         assert isinstance(coord._answers_queues, dict)
#         assert isinstance(coord._world_action_queue, asyncio.Queue)
#         assert not isinstance(coord._world_response_queue, asyncio.Queue)

#     @pytest.mark.asyncio
#     async def test_initialize_new_player(self, coordinator_init):
#         coord = coordinator_init
#         agent_addr = ("1.1.1.1", "4242")
#         agent_name = "TestAgent"
#         agent_role = "Attacker"
#         new_obs = coord._initialize_new_player(agent_addr, agent_name, agent_role)

#         assert agent_addr in coord.agents
#         assert coord.agents[agent_addr] == (agent_name, agent_role)
#         assert coord._agent_steps[agent_addr] == 0
#         assert not coord._reset_requests[agent_addr]
#         assert coord._agent_statuses[agent_addr] == AgentStatus.PlayingActive

#         assert new_obs.reward == 0
#         assert new_obs.end is False
#         assert new_obs.info == {}

#     def test_join(self, coordinator_init):
#         coord = coordinator_init

#         registration = Action(
#             ActionType.JoinGame,
#             params={"agent_info": AgentInfo(name="mari", role="Attacker")},
#         )

#         result = coord._process_join_game_action(
#             agent_addr=("192.168.1.1", "3300"),
#             action=registration,
#         )
#         assert result["to_agent"] == ("192.168.1.1", "3300")
#         assert result["status"] == "GameStatus.CREATED"
#         assert "max_steps" in result["message"].keys()
#         assert "goal_description" in result["message"].keys()
#         assert not result["observation"]["end"]
#         assert "configuration_hash" in result["message"].keys()
    
#     # def test_reset(self, coordinator_registered_player):
#     #     coord, _ = coordinator_registered_player
#     #     result = coord._process_reset_game_action(("192.168.1.1", "3300"))

#     #     assert result["to_agent"] == ("192.168.1.1", "3300")
#     #     assert "Resetting" in result["message"]["message"]
#     #     assert "max_steps" in result["message"].keys()
#     #     assert "goal_description" in result["message"].keys()
#     #     assert result["status"] == "GameStatus.OK"

#     #     assert coord._agent_steps[("192.168.1.1", "3300")] == 0
#     #     assert coord._agent_goal_reached[("192.168.1.1", "3300")] is False
#     #     assert coord._agent_episode_ends[("192.168.1.1", "3300")] is False
#     #     assert coord._reset_requests[("192.168.1.1", "3300")] is False

#     def test_generic_action(self, coordinator_registered_player):
#         coord, init_result = coordinator_registered_player
#         action = Action(
#             ActionType.ScanNetwork,
#             params={
#                 "source_host": IP("192.168.2.2"),
#                 "target_network": Network("192.168.1.0", 24),
#             },
#         )
#         result = coord._process_generic_action(("192.168.1.1", "3300"), action)

#         assert result["to_agent"] == ("192.168.1.1", "3300")
#         assert result["status"] == "GameStatus.OK"
#         assert init_result["observation"]["state"] != result["observation"]["state"]

#     def test_check_goal_valid(self, coordinator_init):
#         game_state = GameState(
#             controlled_hosts=[IP("1.1.1.1"), IP("1.1.1.2")],
#             known_hosts=[IP("1.1.1.1"), IP("1.1.1.2"), IP("1.1.1.3"), IP("1.1.1.4")],
#             known_services={
#                 IP("1.1.1.1"):[Service("test_service1", "passive", "1.01", is_local=False)]
#             },
#             known_data={
#                 IP("1.1.1.1"):[Data("Joe Doe", "password", 10, "txt")]
#             },
#             known_networks=[Network("1.1.1.1","24")],
#             known_blocks={}

#         )
#         win_conditions = {
#             "known_networks":[],
#             "known_hosts":[IP("1.1.1.2")],
#             "controlled_hosts":[IP("1.1.1.1")],
#             "known_services":{
#                  IP("1.1.1.1"):[Service("test_service1", "passive", "1.01", is_local=False)],
#             },
#             "known_data":{
                
#             },
#             "known_blocks":{}
#         }

#         assert coordinator_init._check_goal(game_state, win_conditions) is True

#     def test_check_goal_invalid(self, coordinator_init):
#             game_state = GameState(
#                 controlled_hosts=[IP("1.1.1.1"), IP("1.1.1.2")],
#                 known_hosts=[IP("1.1.1.1"), IP("1.1.1.2"), IP("1.1.1.3"), IP("1.1.1.4")],
#                 known_services={
#                     IP("1.1.1.1"):[Service("test_service1", "passive", "1.01", is_local=False)]
#                 },
#                 known_data={
#                     IP("1.1.1.1"):[Data("Joe Doe", "password", 10, "txt")]
#                 },
#                 known_networks=[Network("1.1.1.1","24")],
#                 known_blocks={}
#             )
#             win_conditions = {
#                 "known_networks":[],
#                 "known_hosts":[IP("1.1.1.5")],
#                 "controlled_hosts":[IP("1.1.1.1")],
#                 "known_services":{
#                     IP("1.1.1.1"):[Service("test_service1", "passive", "1.01", is_local=False)],
#                 },
#                 "known_data":{
                    
#                 },
#                 "known_blocks":{}
#             }

#             assert coordinator_init._check_goal(game_state, win_conditions) is False
    
#     def test_check_goal_empty(self, coordinator_init):
#         game_state = GameState(
#         controlled_hosts=[IP("1.1.1.1"), IP("1.1.1.2")],
#         known_hosts=[IP("1.1.1.1"), IP("1.1.1.2"), IP("1.1.1.3"), IP("1.1.1.4")],
#         known_services={
#             IP("1.1.1.1"):[Service("test_service1", "passive", "1.01", is_local=False)]
#         },
#         known_data={
#             IP("1.1.1.1"):[Data("Joe Doe", "password", 10, "txt")]
#         },
#         known_networks=[Network("1.1.1.1","24")],
#         known_blocks={}
#         )
#         win_conditions = {
#             "known_networks":[],
#             "known_hosts":[],
#             "controlled_hosts":[],
#             "known_services":{},
#             "known_data":{},
#             "known_blocks":{}
#         }
#         assert coordinator_init._check_goal(game_state, win_conditions) is True

#     def test_timeout(self, coordinator_registered_player):
#         coord, init_result = coordinator_registered_player
#         action = Action(
#             ActionType.ScanNetwork,
#             params={
#                 "source_host": IP("192.168.2.2"),
#                 "target_network": Network("192.168.1.0", 24),
#             },
#         )
#         result = init_result
#         for _ in range(15):
#             result = coord._process_generic_action(("192.168.1.1", "3300"), action)
#         assert result["to_agent"] == ("192.168.1.1", "3300")
#         assert result["status"] == "GameStatus.OK"
#         assert init_result["observation"]["state"] != result["observation"]["state"]
#         assert coord._agent_steps[("192.168.1.1", "3300")] == 15
#         assert coord._agent_statuses[("192.168.1.1", "3300")] == "max_steps"
#         assert result["observation"]["end"]
#         assert result["observation"]["info"]["end_reason"] == "max_steps"


import pytest
from unittest.mock import AsyncMock, MagicMock
from AIDojoCoordinator.coordinator import Coordinator, AgentStatus, Action, ActionType
from AIDojoCoordinator.game_components import AgentInfo, Network, IP

CONFIG_FILE = "tests/netsecenv-task-for-testing.yaml"
ALLOWED_ROLES = ["Attacker", "Defender", "Benign"]


@pytest.fixture
def coordinator_init():
    """Initialize the Coordinator instance."""
    actions_queue = MagicMock()
    answers_queues = {}
    coord = Coordinator(
        actions_queue,
        answers_queues,
        CONFIG_FILE,
        ALLOWED_ROLES,
    )
    return coord


@pytest.mark.asyncio
async def test_agent_joining_game(coordinator_init):
    """Test agent successfully joining the game."""
    coord = coordinator_init

    action = Action(
        ActionType.JoinGame,
        params={"agent_info": AgentInfo(name="TestAgent", role="Attacker")},
    )
    agent_addr = ("192.168.1.1", "3300")

    # Mock the world reset
    coord._world.reset = AsyncMock(return_value=None)
    coord._world.update_goal_dict = MagicMock(return_value={})
    coord._world.update_goal_descriptions = MagicMock(return_value={})
    coord._world.create_state_from_view = MagicMock(return_value={})

    await coord._process_join_game_action(agent_addr, action)

    assert agent_addr in coord.agents
    assert coord.agents[agent_addr] == ("TestAgent", "Attacker")
    assert coord._agent_statuses[agent_addr] == AgentStatus.JoinRequested

@pytest.mark.asyncio
async def test_agent_playing_scan_network_with_mocking(coordinator_init):
    """Test an agent performing the ScanNetwork action with mocked queue interactions."""
    # Arrange
    coord = coordinator_init

    # Mock agent details
    agent_addr = ("192.168.1.1", "3300")
    agent_name = "TestAgent"
    agent_role = "Attacker"
    coord.agents[agent_addr] = (agent_name, agent_role)
    coord._agent_statuses[agent_addr] = AgentStatus.Playing
    coord._agent_states[agent_addr] = MagicMock()  # Mocked GameState
    coord._agent_rewards[agent_addr] = None  # Initialize the reward to avoid KeyError

    # Create the ScanNetwork action
    action = Action(
        ActionType.ScanNetwork,
        params={
            "source_host": IP("192.168.2.2"),
            "target_network": Network("192.168.1.0", 24),
        },
    )

    # Mock the action queue
    coord._actions_queue.get = AsyncMock(return_value=(agent_addr, action.as_json()))
    coord._world_action_queue.put = AsyncMock()
    coord._answers_queues[agent_addr] = AsyncMock()  # Mock agent's answer queue

    # Mock `_world._rewards` to provide reward values
    coord._world = MagicMock()
    coord._world._rewards = {"goal": 10, "detection": -5, "step": 1}

    # Act
    agent_addr, message = await coord._actions_queue.get()
    action = Action.from_json(message)
    await coord._process_generic_action(agent_addr, action)

    # Assert
    coord._world_action_queue.put.assert_called_once_with(
        (agent_addr, action, coord._agent_states[agent_addr])
    )
    coord._answers_queues[agent_addr].put.assert_not_called()  # No immediate response expected
    assert coord._agent_statuses[agent_addr] == AgentStatus.Playing
    assert coord._agent_rewards[agent_addr] is None  # No end rewards assigned yet

@pytest.mark.asyncio
async def test_agent_playing_scan_network(coordinator_init):
    """Test agent performing a scan network action."""
    coord = coordinator_init

    # Set up agent in the game
    agent_addr = ("192.168.1.1", "3300")
    coord.agents[agent_addr] = ("TestAgent", "Attacker")
    coord._agent_statuses[agent_addr] = AgentStatus.Playing
    coord._agent_states[agent_addr] = MagicMock()  # Mock game state

    action = Action(
        ActionType.ScanNetwork,
        params={
            "source_host": IP("192.168.2.2"),
            "target_network": Network("192.168.1.0", 24),
        },
    )

    # Mock the world action queue
    coord._world_action_queue.put = AsyncMock()

    # Call the method under test
    await coord._process_generic_action(agent_addr, action)

    # Assertions
    coord._world_action_queue.put.assert_called_once_with(
        (agent_addr, action, coord._agent_states[agent_addr])
    )
    assert coord._agent_statuses[agent_addr] == AgentStatus.Playing


@pytest.mark.asyncio
async def test_agent_requesting_reset(coordinator_init):
    """Test agent requesting a reset."""
    coord = coordinator_init

    # Set up agent in the game
    agent_addr = ("192.168.1.1", "3300")
    coord.agents[agent_addr] = ("TestAgent", "Attacker")
    coord._reset_requests[agent_addr] = False

    action = Action(ActionType.ResetGame, params={})
    coord._world.reset = AsyncMock(return_value=None)

    await coord._process_generic_action(agent_addr, action)

    assert coord._reset_requests[agent_addr] is True
    coord._world_action_queue.put.assert_called_with(("world", action, None))


@pytest.mark.asyncio
async def test_agent_leaving_game(coordinator_init):
    """Test agent leaving the game."""
    coord = coordinator_init

    # Set up agent in the game
    agent_addr = ("192.168.1.1", "3300")
    coord.agents[agent_addr] = ("TestAgent", "Attacker")
    coord._agent_statuses[agent_addr] = AgentStatus.Playing

    action = Action(ActionType.QuitGame, params={})
    coord._world_action_queue.put = AsyncMock(return_value=None)

    await coord._process_generic_action(agent_addr, action)

    coord._world_action_queue.put.assert_called_once_with((agent_addr, action, coord._agent_states.get(agent_addr)))
    assert agent_addr not in coord.agents
from coordinator import Coordinator
import pytest
import queue

CONFIG_FILE = "tests/netsecenv-task-for-testing.yaml"
ALLOWED_ROLES = ["Attacker", "Defender", "Benign"]

import sys
from os import path

sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
from env.game_components import Action, ActionType, AgentInfo, Network, IP


@pytest.fixture
def coordinator_init():
    """After init step"""
    actions = queue.Queue()
    answers = queue.Queue()

    coord = Coordinator(actions, answers, CONFIG_FILE, ALLOWED_ROLES)
    return coord

@pytest.fixture
def coordinator_registered_player(coordinator_init):
        coord = coordinator_init

        registration = Action(
            ActionType.JoinGame,
            params={"agent_info": AgentInfo(name="mari", role="Attacker")},
        )

        obs = coord._world.reset()

        result = coord._process_join_game_action(
            agent_addr=("192.168.1.1", "3300"),
            action=registration,
            current_observation=obs,
        )
        return coord, result


class TestCoordinator:
    def test_class_init(self):
        actions = queue.Queue()
        answers = queue.Queue()

        coord = Coordinator(actions, answers, CONFIG_FILE, ALLOWED_ROLES)

        assert coord.ALLOWED_ROLES == ALLOWED_ROLES
        assert coord.agents == {}
        assert coord._agent_steps == {}
        assert coord._reset_requests == {}
        assert coord._agent_starting_position == {}
        assert coord._agent_observations == {}
        assert coord._agent_states == {}
        assert coord._agent_goal_reached == {}
        assert coord._agent_episode_ends == {}
        assert type(coord._actions_queue) == queue.Queue
        assert type(coord._answers_queue) == queue.Queue
    
    def test_initialize_new_player(self, coordinator_init):
        coord = coordinator_init
        agent_addr = ("1.1.1.1", "4242")
        agent_name = "TestAgent"
        agent_role = "Attacker"
        new_obs = coord._initialize_new_player(agent_addr, agent_name, agent_role)

        assert agent_addr in coord.agents
        assert coord.agents[agent_addr] == (agent_name, agent_role)
        assert coord._agent_steps[agent_addr] == 0
        assert not coord._reset_requests[agent_addr]
        assert not coord._agent_episode_ends[agent_addr]

        assert new_obs.reward == 0
        assert new_obs.end is False
        assert new_obs.info == {}

    def test_join(self, coordinator_init):
        coord = coordinator_init

        registration = Action(
            ActionType.JoinGame,
            params={"agent_info": AgentInfo(name="mari", role="Attacker")},
        )

        result = coord._process_join_game_action(
            agent_addr=("192.168.1.1", "3300"),
            action=registration,
            current_observation=None,
        )
        assert result["to_agent"] == ("192.168.1.1", "3300")
        assert result["status"] == "GameStatus.CREATED"
        assert "max_steps" in result["message"].keys()
        assert "goal_description" in result["message"].keys()
        assert not result["observation"]["end"]
    #     assert result["observation"]["state"] == obs.state.as_dict
    #     assert result["observation"]["info"] == obs.info
    #     assert result["observation"]["reward"] == coord._world.num_actions

    # def test_reset(self, coordinator_init):
    #     coord = coordinator_init
    #     result = coord._process_reset_game_action(("192.168.1.1", "3300"))

    #     assert result["to_agent"] == ("192.168.1.1", "3300")
    #     assert "Resetting" in result["message"]["message"]
    #     assert "max_steps" in result["message"].keys()
    #     assert "goal_description" in result["message"].keys()
    #     assert result["status"] == "GameStatus.OK"

    def test_generic_action(self, coordinator_registered_player):
        coord, init_result = coordinator_registered_player
        action = Action(
            ActionType.ScanNetwork,
            params={
                "source_host": IP("192.168.2.2"),
                "target_network": Network("192.168.1.0", 24),
            },
        )
        result = coord._process_generic_action(("192.168.1.1", "3300"), action)

        assert result["to_agent"] == ("192.168.1.1", "3300")
        assert result["status"] == "GameStatus.OK"
        assert init_result["observation"]["state"] != result["observation"]["state"]

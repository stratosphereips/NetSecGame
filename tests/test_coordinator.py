from coordinator import Coordinator
import pytest
import queue

CONFIG_FILE = "tests/netsecenv-task-for-testing.yaml"
ALLOWED_ROLES = ["Attacker", "Defender", "Human"]

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
    coord.agents = {}
    return coord


class TestCoordinator:
    def test_class_init(self):
        actions = queue.Queue()
        answers = queue.Queue()

        coord = Coordinator(actions, answers, CONFIG_FILE, ALLOWED_ROLES)

        assert coord.ALLOWED_ROLES == ALLOWED_ROLES
        assert coord._action_processor._observations == {}
        assert type(coord._actions_queue) == queue.Queue
        assert type(coord._answers_queue) == queue.Queue

    def test_join(self, coordinator_init):
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

        assert result["to_agent"] == ("192.168.1.1", "3300")
        assert result["status"] == "GameStatus.CREATED"
        assert "Welcome" in result["message"]
        assert not result["observation"]["end"]
        assert result["observation"]["state"] == obs.state.as_dict
        assert result["observation"]["info"] == obs.info
        assert result["observation"]["reward"] == obs.reward

    def test_reset(self, coordinator_init):
        coord = coordinator_init
        result = coord._process_reset_game_action(("192.168.1.1", "3300"))

        assert result["to_agent"] == ("192.168.1.1", "3300")
        assert "Resetting" in result["message"]
        assert result["status"] == "GameStatus.OK"

    def test_generic_action(self, coordinator_init):
        coord = coordinator_init

        obs = coord._world.reset()

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
        assert obs.state.as_dict != result["observation"]["state"]

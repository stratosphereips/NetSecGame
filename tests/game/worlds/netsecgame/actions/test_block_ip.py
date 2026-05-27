import pytest
from netsecgame.game_components import Action, ActionType, IP, Network, GameState
from netsecgame.game.worlds.NetSecGame import NetSecGame

@pytest.fixture
def base_game():
    game = NetSecGame(game_host="localhost", game_port=9999, task_config="tests/netsecenv-task-for-testing.yaml", seed=42)
    game.config_manager._load_local_configuration()
    game._ip_to_hostname = {
        IP("192.168.1.1"): "host1",
        IP("192.168.1.2"): "host2",
        IP("192.168.1.3"): "host3",
    }
    game._networks = {
        Network("192.168.1.0", 24): {IP("192.168.1.1"), IP("192.168.1.2"), IP("192.168.1.3")}
    }
    game._data = {
        "host1": set(),
        "host2": set(),
        "host3": set(),
    }
    # Initial firewall rules allowing connections
    game._firewall = {
        IP("192.168.1.1"): {IP("192.168.1.1"), IP("192.168.1.2"), IP("192.168.1.3")},
        IP("192.168.1.2"): {IP("192.168.1.2"), IP("192.168.1.1"), IP("192.168.1.3")},
        IP("192.168.1.3"): {IP("192.168.1.3"), IP("192.168.1.1"), IP("192.168.1.2")},
    }
    return game

def test_block_ip_success(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")}, # both source and target are 1.1 which is controlled
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.BlockIP,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.1"),
            "blocked_host": IP("192.168.1.2")
        }
    )
    
    agent_id = ("Defender", 1)
    new_state = base_game._execute_block_ip_action(current_state, action, agent_id=agent_id)
    
    # Connection between target (1.1) and blocked (1.2) must be removed from firewall in both directions
    assert IP("192.168.1.2") not in base_game._firewall[IP("192.168.1.1")]
    assert IP("192.168.1.1") not in base_game._firewall[IP("192.168.1.2")]
    
    # Verify state known_blocks is updated
    assert IP("192.168.1.2") in new_state.known_blocks[IP("192.168.1.1")]
    assert IP("192.168.1.1") in new_state.known_blocks[IP("192.168.1.2")]
    
    # Verify that self._fw_blocks in environment is also updated
    assert IP("192.168.1.2") in base_game._fw_blocks[IP("192.168.1.1")]
    assert IP("192.168.1.1") in base_game._fw_blocks[IP("192.168.1.2")]
    
    # Verify rule was registered under agent_id
    assert agent_id in base_game._agent_fw_rules[(IP("192.168.1.1"), IP("192.168.1.2"))]
    assert agent_id in base_game._agent_fw_rules[(IP("192.168.1.2"), IP("192.168.1.1"))]

def test_block_ip_self_blocking_prevention(base_game):
    # Attempting to block target_host itself
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")},
        known_hosts={IP("192.168.1.1")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.BlockIP,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.1"),
            "blocked_host": IP("192.168.1.1") # self-block
        }
    )
    
    new_state = base_game._execute_block_ip_action(current_state, action, agent_id=("Defender", 1))
    
    # Firewall should still contain itself
    assert IP("192.168.1.1") in base_game._firewall[IP("192.168.1.1")]
    # State remains unchanged
    assert new_state == current_state

def test_block_ip_source_not_controlled(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.2")}, # source 1.1 is NOT controlled
        known_hosts={IP("192.168.1.1")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.BlockIP,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.1"),
            "blocked_host": IP("192.168.1.2")
        }
    )
    
    new_state = base_game._execute_block_ip_action(current_state, action, agent_id=("Defender", 1))
    assert new_state == current_state

def test_block_ip_target_not_controlled(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")}, # source 1.1 is controlled but target 1.2 is NOT controlled
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.BlockIP,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2"),
            "blocked_host": IP("192.168.1.3")
        }
    )
    
    new_state = base_game._execute_block_ip_action(current_state, action, agent_id=("Defender", 1))
    assert new_state == current_state

def test_block_ip_firewall_blocked_benign_agent(base_game):
    # Setup so that source 1.1 is controlled, target 1.3 is controlled, but firewall blocked from 1.1 to 1.3
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1"), IP("192.168.1.3")},
        known_hosts={IP("192.168.1.1"), IP("192.168.1.3")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    # Remove 1.3 from 1.1's allowed firewall hosts to block them
    base_game._firewall[IP("192.168.1.1")].discard(IP("192.168.1.3"))
    
    action = Action(
        action_type=ActionType.BlockIP,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.3"),
            "blocked_host": IP("192.168.1.2")
        }
    )
    
    agent_id = ("Benign", 1)
    base_game.agents = {agent_id: ("BenignAgent", "Benign")}
    base_game._agent_fw_rules = {
        (IP("192.168.1.1"), IP("192.168.1.3")): {("Defender", 1)}
    }
    
    base_game._execute_block_ip_action(current_state, action, agent_id=agent_id)
    assert base_game._agent_false_positives.get(("Defender", 1), 0) == 1

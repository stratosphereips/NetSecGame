import pytest
from netsecgame.game_components import Action, ActionType, IP, Network, Data, GameState
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
        "host2": {Data("User1", "DatabaseData")},
        "host3": set(),
    }
    game._fw_blocks = {
        IP("192.168.1.2"): {IP("192.168.1.3")}
    }
    game._firewall = {
        IP("192.168.1.1"): {IP("192.168.1.1"), IP("192.168.1.2")},
        IP("192.168.1.2"): {IP("192.168.1.2"), IP("192.168.1.1")},
        IP("192.168.1.3"): set(),
    }
    return game

def test_find_data_success(base_game):
    # Both 1.1 and target 1.2 are controlled
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.FindData,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2")
        }
    )
    
    new_state = base_game._execute_find_data_action(current_state, action, agent_id=("Attacker", 1))
    
    # Verify target data is found
    assert IP("192.168.1.2") in new_state.known_data
    assert Data("User1", "DatabaseData") in new_state.known_data[IP("192.168.1.2")]
    
    # Verify firewall block on host2 is discovered
    assert IP("192.168.1.2") in new_state.known_blocks
    assert IP("192.168.1.3") in new_state.known_blocks[IP("192.168.1.2")]
    
    # Target log updated
    host2_logs = [d for d in base_game._data["host2"] if d.owner == "system" and d.type == "log"]
    assert len(host2_logs) == 1

def test_find_data_uncontrolled_target(base_game):
    # Only 1.1 is controlled, target 1.2 is NOT controlled
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")},
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.FindData,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2")
        }
    )
    
    new_state = base_game._execute_find_data_action(current_state, action, agent_id=("Attacker", 1))
    
    # No data or blocks should be discovered because target is not controlled
    assert IP("192.168.1.2") not in new_state.known_data
    assert IP("192.168.1.2") not in new_state.known_blocks
    
    # But log is still updated because the firewall connection was open
    host2_logs = [d for d in base_game._data["host2"] if d.owner == "system" and d.type == "log"]
    assert len(host2_logs) == 1

def test_find_data_source_not_controlled(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.2")},  # source 1.1 is not controlled
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.FindData,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2")
        }
    )
    
    new_state = base_game._execute_find_data_action(current_state, action, agent_id=("Attacker", 1))
    assert new_state == current_state

def test_find_data_firewall_blocked_benign_agent(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")},
        known_hosts={IP("192.168.1.1"), IP("192.168.1.3")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.FindData,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.3")  # blocked
        }
    )
    
    agent_id = ("Benign", 1)
    base_game.agents = {agent_id: ("BenignAgent", "Benign")}
    base_game._agent_fw_rules = {
        (IP("192.168.1.1"), IP("192.168.1.3")): {("Defender", 1)}
    }
    
    base_game._execute_find_data_action(current_state, action, agent_id=agent_id)
    assert base_game._agent_false_positives.get(("Defender", 1), 0) == 1

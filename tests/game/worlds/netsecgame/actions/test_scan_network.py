import pytest
import json
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
        "host2": set(),
        "host3": set(),
    }
    # host1 can reach host2, but host3 is blocked form host1
    game._firewall = {
        IP("192.168.1.1"): {IP("192.168.1.2")},
        IP("192.168.1.2"): {IP("192.168.1.1")},
        IP("192.168.1.3"): set(),
    }
    return game

def test_scan_network_success(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")},
        known_hosts={IP("192.168.1.1")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.ScanNetwork,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_network": Network("192.168.1.0", 24)
        }
    )
    
    new_state = base_game._execute_scan_network_action(current_state, action, agent_id=("Attacker", 1))
    
    # 192.168.1.2 should be discovered because it's allowed by firewall
    assert IP("192.168.1.2") in new_state.known_hosts
    # 192.168.1.3 should NOT be discovered because connection is not in firewall
    assert IP("192.168.1.3") not in new_state.known_hosts
    
    # Verify that target log on host2 is updated
    host2_logs = [d for d in base_game._data["host2"] if d.owner == "system" and d.type == "log"]
    assert len(host2_logs) == 1
    log_data = json.loads(host2_logs[0].content)
    assert log_data[-1]["source_host"] == "192.168.1.1"
    assert log_data[-1]["action_type"] == "ActionType.ScanNetwork"

def test_scan_network_non_existent(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")},
        known_hosts={IP("192.168.1.1")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.ScanNetwork,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_network": Network("10.0.0.0", 24)
        }
    )
    
    new_state = base_game._execute_scan_network_action(current_state, action, agent_id=("Attacker", 1))
    assert new_state == current_state

def test_scan_network_source_not_controlled(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.2")},  # 1.1 is NOT controlled
        known_hosts={IP("192.168.1.1")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.ScanNetwork,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_network": Network("192.168.1.0", 24)
        }
    )
    
    new_state = base_game._execute_scan_network_action(current_state, action, agent_id=("Attacker", 1))
    assert new_state == current_state

def test_scan_network_firewall_blocked_benign_agent(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")},
        known_hosts={IP("192.168.1.1")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.ScanNetwork,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_network": Network("192.168.1.0", 24)
        }
    )
    
    # Create benign agent to check false positive recording
    agent_id = ("Benign", 1)
    base_game.agents = {agent_id: ("BenignAgent", "Benign")}
    base_game._agent_fw_rules = {
        (IP("192.168.1.1"), IP("192.168.1.3")): {("Defender", 1)}
    }
    
    assert base_game._agent_false_positives.get(("Defender", 1), 0) == 0
    
    new_state = base_game._execute_scan_network_action(current_state, action, agent_id=agent_id)
    
    # 1.3 is blocked, so it should not be discovered
    assert IP("192.168.1.3") not in new_state.known_hosts
    
    # False positive should be recorded because a benign agent attempted connection blocked by Defender
    assert base_game._agent_false_positives.get(("Defender", 1), 0) == 1

import pytest
import json
from netsecgame.game_components import Action, ActionType, IP, Network, Data, Service, GameState
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
    game._services = {
        "host1": {Service("ssh", "active", "1.0", is_local=True), Service("web", "passive", "2.0", is_local=False)},
        "host2": {Service("db", "passive", "3.0", is_local=False), Service("local_only", "active", "4.0", is_local=True)},
        "host3": set(),
    }
    game._data = {
        "host1": set(),
        "host2": set(),
        "host3": set(),
    }
    game._firewall = {
        IP("192.168.1.1"): {IP("192.168.1.1"), IP("192.168.1.2")},
        IP("192.168.1.2"): {IP("192.168.1.2"), IP("192.168.1.1")},
        IP("192.168.1.3"): set(),
    }
    return game

def test_find_services_success(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")},
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.FindServices,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2")
        }
    )
    
    new_state = base_game._execute_find_services_action(current_state, action, agent_id=("Attacker", 1))
    
    # Target is NOT controlled, so only non-local services (db) should be discovered
    discovered_services = new_state.known_services[IP("192.168.1.2")]
    assert len(discovered_services) == 1
    assert Service("db", "passive", "3.0", is_local=False) in discovered_services
    assert Service("local_only", "active", "4.0", is_local=True) not in discovered_services

    # Verify that log is updated on target
    host2_logs = [d for d in base_game._data["host2"] if d.owner == "system" and d.type == "log"]
    assert len(host2_logs) == 1

def test_find_services_local_success(base_game):
    # Testing search on a controlled target host (1.1 itself)
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")},
        known_hosts={IP("192.168.1.1")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.FindServices,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.1")
        }
    )
    
    new_state = base_game._execute_find_services_action(current_state, action, agent_id=("Attacker", 1))
    
    # Target IS controlled, so both local (ssh) and non-local (web) services should be discovered
    discovered_services = new_state.known_services[IP("192.168.1.1")]
    assert len(discovered_services) == 2
    assert Service("ssh", "active", "1.0", is_local=True) in discovered_services
    assert Service("web", "passive", "2.0", is_local=False) in discovered_services

def test_find_services_unknown_host_extends_state(base_game):
    # target_host (1.2) is not in known_hosts initially
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")},
        known_hosts={IP("192.168.1.1")},
        known_networks=set()
    )
    
    action = Action(
        action_type=ActionType.FindServices,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2")
        }
    )
    
    new_state = base_game._execute_find_services_action(current_state, action, agent_id=("Attacker", 1))
    
    # Host and Network should be dynamically added
    assert IP("192.168.1.2") in new_state.known_hosts
    assert Network("192.168.1.0", 24) in new_state.known_networks
    assert IP("192.168.1.2") in new_state.known_services

def test_find_services_source_not_controlled(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.2")},  # 1.1 is not controlled
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.FindServices,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2")
        }
    )
    
    new_state = base_game._execute_find_services_action(current_state, action, agent_id=("Attacker", 1))
    assert new_state == current_state

def test_find_services_firewall_blocked_benign_agent(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")},
        known_hosts={IP("192.168.1.1"), IP("192.168.1.3")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.FindServices,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.3")  # blocked by firewall
        }
    )
    
    agent_id = ("Benign", 1)
    base_game.agents = {agent_id: ("BenignAgent", "Benign")}
    base_game._agent_fw_rules = {
        (IP("192.168.1.1"), IP("192.168.1.3")): {("Defender", 1)}
    }
    
    new_state = base_game._execute_find_services_action(current_state, action, agent_id=agent_id)
    assert IP("192.168.1.3") not in new_state.known_services
    assert base_game._agent_false_positives.get(("Defender", 1), 0) == 1

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
        "host1": {Data("User1", "DatabaseData")},
        "host2": set(),
        "host3": set(),
    }
    game._firewall = {
        IP("192.168.1.1"): {IP("192.168.1.1"), IP("192.168.1.2")},
        IP("192.168.1.2"): {IP("192.168.1.2"), IP("192.168.1.1")},
        IP("192.168.1.3"): set(),
    }
    return game

def test_exfiltrate_data_success(base_game):
    db_data = Data("User1", "DatabaseData")
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_data={IP("192.168.1.1"): {db_data}},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.ExfiltrateData,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2"),
            "data": db_data
        }
    )
    
    new_state = base_game._execute_exfiltrate_data_action(current_state, action, agent_id=("Attacker", 1))
    
    # Target host 1.2 should now have the exfiltrated data
    assert IP("192.168.1.2") in new_state.known_data
    assert db_data in new_state.known_data[IP("192.168.1.2")]
    
    # Environment-level _data of host2 should also contain this data now
    assert db_data in base_game._data["host2"]
    
    # Target log updated
    host2_logs = [d for d in base_game._data["host2"] if d.owner == "system" and d.type == "log"]
    assert len(host2_logs) == 1

def test_exfiltrate_data_source_uncontrolled(base_game):
    db_data = Data("User1", "DatabaseData")
    current_state = GameState(
        controlled_hosts={IP("192.168.1.2")},  # source 1.1 is NOT controlled
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_data={IP("192.168.1.1"): {db_data}},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.ExfiltrateData,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2"),
            "data": db_data
        }
    )
    
    new_state = base_game._execute_exfiltrate_data_action(current_state, action, agent_id=("Attacker", 1))
    assert db_data not in new_state.known_data.get(IP("192.168.1.2"), set())

def test_exfiltrate_data_target_uncontrolled(base_game):
    db_data = Data("User1", "DatabaseData")
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")},  # target 1.2 is NOT controlled
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_data={IP("192.168.1.1"): {db_data}},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.ExfiltrateData,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2"),
            "data": db_data
        }
    )
    
    new_state = base_game._execute_exfiltrate_data_action(current_state, action, agent_id=("Attacker", 1))
    assert db_data not in new_state.known_data.get(IP("192.168.1.2"), set())

def test_exfiltrate_data_agent_unaware_of_data(base_game):
    db_data = Data("User1", "DatabaseData")
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_data={},  # Agent does not know about db_data yet!
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.ExfiltrateData,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2"),
            "data": db_data
        }
    )
    
    new_state = base_game._execute_exfiltrate_data_action(current_state, action, agent_id=("Attacker", 1))
    assert db_data not in new_state.known_data.get(IP("192.168.1.2"), set())

def test_exfiltrate_data_firewall_blocked_benign_agent(base_game):
    db_data = Data("User1", "DatabaseData")
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1"), IP("192.168.1.3")},
        known_hosts={IP("192.168.1.1"), IP("192.168.1.3")},
        known_data={IP("192.168.1.1"): {db_data}},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.ExfiltrateData,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.3"),  # blocked by firewall
            "data": db_data
        }
    )
    
    agent_id = ("Benign", 1)
    base_game.agents = {agent_id: ("BenignAgent", "Benign")}
    base_game._agent_fw_rules = {
        (IP("192.168.1.1"), IP("192.168.1.3")): {("Defender", 1)}
    }
    
    new_state = base_game._execute_exfiltrate_data_action(current_state, action, agent_id=agent_id)
    assert db_data not in new_state.known_data.get(IP("192.168.1.3"), set())
    assert base_game._agent_false_positives.get(("Defender", 1), 0) == 1

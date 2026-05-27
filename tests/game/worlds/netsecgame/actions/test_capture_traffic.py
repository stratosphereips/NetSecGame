import pytest
import json
from unittest.mock import patch
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
    game._firewall = {
        IP("192.168.1.2"): {IP("192.168.1.1"), IP("192.168.1.3")},
        IP("192.168.1.1"): {IP("192.168.1.2")},
        IP("192.168.1.3"): {IP("192.168.1.2")},
    }
    return game

def test_capture_traffic_validation(base_game):
    # Setup state where source is controlled but target is NOT controlled
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1")},
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.CaptureTraffic,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2")  # Not controlled!
        }
    )
    
    new_state = base_game._execute_capture_traffic_action(current_state, action, agent_id=("Attacker", 1))
    
    # Assert no change has occurred (since target_host was not controlled)
    assert new_state == current_state

def test_capture_traffic_success_base_probability(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.CaptureTraffic,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2")
        }
    )
    
    # 1. Force discovery success using patch of random.random to return 0.05
    # Since same-network is true, base probability (0.1) is doubled to 0.2. 0.05 < 0.2 succeeds.
    with patch("netsecgame.game.worlds.NetSecGame.random.random", return_value=0.05):
        new_state = base_game._execute_capture_traffic_action(current_state, action, agent_id=("Attacker", 1))
        
        # Verify host3 was discovered
        assert IP("192.168.1.3") in new_state.known_hosts
        # Verify that networks were NOT extended (as per requirements)
        assert new_state.known_networks == current_state.known_networks
        
    # 2. Force discovery failure using patch of random.random to return 0.95 (greater than boosted prob 0.2)
    with patch("netsecgame.game.worlds.NetSecGame.random.random", return_value=0.95):
        new_state2 = base_game._execute_capture_traffic_action(current_state, action, agent_id=("Attacker", 1))
        assert IP("192.168.1.3") not in new_state2.known_hosts

def test_capture_traffic_same_network_bonus(base_game):
    """Verifies that discovery probability is doubled when target_host and h_new are in the same subnet."""
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.CaptureTraffic,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2")
        }
    )
    
    # Base probability is 0.1. With same_net_prob_bonus = 2.0, boosted prob is 0.2.
    # A roll of 0.15 is greater than 0.1 (would fail without bonus) but less than 0.2 (succeeds with bonus).
    with patch("netsecgame.game.worlds.NetSecGame.random.random", return_value=0.15):
        new_state = base_game._execute_capture_traffic_action(current_state, action, agent_id=("Attacker", 1), same_net_prob_bonus=2.0)
        assert IP("192.168.1.3") in new_state.known_hosts

    # A roll of 0.15 with same_net_prob_bonus = 1.0 (no bonus) should fail.
    with patch("netsecgame.game.worlds.NetSecGame.random.random", return_value=0.15):
        new_state2 = base_game._execute_capture_traffic_action(current_state, action, agent_id=("Attacker", 1), same_net_prob_bonus=1.0)
        assert IP("192.168.1.3") not in new_state2.known_hosts

def test_capture_traffic_log_connection_boost(base_game):
    current_state = GameState(
        controlled_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_hosts={IP("192.168.1.1"), IP("192.168.1.2")},
        known_networks={Network("192.168.1.0", 24)}
    )
    
    action = Action(
        action_type=ActionType.CaptureTraffic,
        parameters={
            "source_host": IP("192.168.1.1"),
            "target_host": IP("192.168.1.2")
        }
    )
    
    # Add previous connections between target_host (1.2) and h_new (1.3) in target_host's system log
    log_content = json.dumps([
        {"source_host": "192.168.1.3", "action_type": "ScanNetwork"},
        {"source_host": "192.168.1.3", "action_type": "FindServices"}
    ])
    base_game._data["host2"].add(Data(owner="system", id="logfile", type="log", size=len(log_content), content=log_content))
    
    # Connection count is 2. Log Boost: 1 - 0.5^2 = 0.75.
    # Same net bonus applies: base_prob 0.1 becomes 0.2.
    # Final Prob: 0.2 + (1 - 0.2) * 0.75 = 0.2 + 0.6 = 0.8
    # Force random.random to return 0.5 (which is less than 0.8 but greater than boosted prob 0.2)
    with patch("netsecgame.game.worlds.NetSecGame.random.random", return_value=0.5):
        new_state = base_game._execute_capture_traffic_action(current_state, action, agent_id=("Attacker", 1))
        assert IP("192.168.1.3") in new_state.known_hosts

import pytest
import sys
from unittest.mock import patch, mock_open, MagicMock

# 1. Define the mocks you need for THIS file
MOCK_MODULES = {
    'aiohttp': MagicMock(),
    'cyst': MagicMock(),
    'cyst.api': MagicMock(),
    'cyst.api.environment': MagicMock(),
    'cyst.api.environment.environment': MagicMock(),
    'faker': MagicMock()
}

# 2. Use a fixture to safely inject and clean up the mocks
@pytest.fixture(scope="module", autouse=True)
def isolate_mocks():
    """
    Safely injects mocks into sys.modules only for the duration of this module.
    Once the tests in this file finish, patch.dict automatically restores the original sys.modules.
    """
    with patch.dict('sys.modules', MOCK_MODULES):
        yield  # The tests run here

# 3. Standard imports
# Because you implemented the Lazy Registry earlier, importing ConfigParser 
# here is safe and won't prematurely trigger real 'cyst' imports.
from netsecgame.game.config_parser import ConfigParser
from netsecgame.game.scenarios import SCENARIO_REGISTRY
from netsecgame.game_components import IP, Data, Network, Service

# --- Mock Configurations ---

VALID_CONFIG = {
    "env": {
        "actions": {
            "test_action": {"prob_success": 0.5}
        },
        "rewards": {
            "step": -1,
            "success": 100
        },
        "use_dynamic_addresses": True,
        "save_trajectories": True,
        "scenario": "scenario1",
        "use_firewall": True,
        "use_global_defender": True,
        "required_players": 2,
    },
    "coordinator": {
        "agents": {
            "Attacker": {
                "max_steps": 50,
                "goal": {
                    "description": "Compromise host 10.0.0.1",
                    "known_networks": ["10.0.0.0/24"],
                    "known_hosts": ["10.0.0.1", "random", "all_local"],
                    "controlled_hosts": ["10.0.0.2"],
                    "known_services": {
                        "10.0.0.1": [["ssh", "tcp", "22", True], "random"]
                    },
                    "known_blocks": {
                        "10.0.0.1": ["10.0.0.2"],
                        "10.0.0.3": "all_attackers"
                    },
                    "known_data": {
                        "10.0.0.1": [["Admin", "Password"], "random"]
                    }
                },
                "start_position": {
                    "known_networks": [],
                    "known_hosts": [],
                    "controlled_hosts": ["random"],
                    "known_services": {},
                    "known_data": {}
                }
            },
            "Defender": {
                "max_steps": {}, # to trigger TypeError fallback
                "goal": {
                     # empty goal for defaults
                },
                "start_position": {
                    "known_networks": [],
                    "known_hosts": [],
                    "controlled_hosts": ["192.168.1.1"],
                    "known_services": {},
                    "known_data": {}
                }
            }
        }
    },
    "random_entity": {
        "random_seed": 42
    },
    "random_entity_str": {
        "random_seed": "random"
    }
}

@pytest.fixture
def parser():
    return ConfigParser(config_dict=VALID_CONFIG)

@pytest.fixture
def empty_parser():
    return ConfigParser(config_dict={"empty_dummy": True})

# --- Tests ---

def test_initialization():
    # Test valid dict
    cp = ConfigParser(config_dict={"key": "value"})
    assert cp.config == {"key": "value"}

    # Test missing both file and dict raises error via log, but creates object
    with patch('logging.Logger.error') as mock_log:
        cp = ConfigParser()
        mock_log.assert_called_once_with("You must provide either the configuration file or a dictionary with the configuration!")
    
    # Test file reading
    mock_yaml = "key: value\n"
    with patch('builtins.open', mock_open(read_data=mock_yaml)):
        cp = ConfigParser(task_config_file="dummy.yaml")
        assert cp.config == {"key": "value"}

    # Test file reading error
    with patch('builtins.open', mock_open()) as mocked_file, patch('logging.Logger.error') as mock_log:
        mocked_file.side_effect = IOError("File not found")
        cp = ConfigParser(task_config_file="dummy.yaml")
        mock_log.assert_called_once()
        assert not hasattr(cp, 'config')

def test_read_env_action_data(parser, empty_parser):
    assert parser.read_env_action_data("test_action") == 0.5
    assert parser.read_env_action_data("unknown_action") == 1
    assert empty_parser.read_env_action_data("test_action") == 1

def test_get_simple_values(parser, empty_parser):
    # Firewall
    assert parser.get_use_firewall() is True
    assert empty_parser.get_use_firewall(default_value=False) is False

    # Dynamic Addresses
    assert parser.get_use_dynamic_addresses() is True
    assert empty_parser.get_use_dynamic_addresses(default_value=False) is False
    
    # Global Defender
    assert parser.get_use_global_defender() is True
    assert empty_parser.get_use_global_defender(default_value=False) is False

    # Required Num Players
    assert parser.get_required_num_players() == 2
    assert empty_parser.get_required_num_players(default_value=1) == 1
    
    # Store trajectories
    assert parser.get_store_trajectories() is True
    assert empty_parser.get_store_trajectories(default_value=False) is False

def test_get_rewards(parser, empty_parser):
    rewards = parser.get_rewards(["step", "success", "fail"], default_value=0)
    assert rewards["step"] == -1
    assert rewards["success"] == 100
    assert rewards["fail"] == 0 # Default fallback

    empty_rewards = empty_parser.get_rewards(["step"], default_value=5)
    assert empty_rewards["step"] == 5

def test_get_max_steps(parser):
    assert parser.get_max_steps("Attacker") == 50
    assert parser.get_max_steps("Defender") is None # Triggered TypeError handling
    assert parser.get_max_steps("Unknown") is None # Triggered KeyError handling

def test_get_goal_description(parser):
    assert parser.get_goal_description("Attacker") == "Compromise host 10.0.0.1"
    assert parser.get_goal_description("Defender") == ""
    assert parser.get_goal_description("Benign") == ""
    
    with pytest.raises(ValueError, match="Unsupported agent role"):
        parser.get_goal_description("UnknownRole")

def test_validate_goal_description(parser):
    with patch('logging.Logger.warning') as mock_warn:
        # 10.0.0.2 is in controlled_hosts but missing from the desc text
        parser.validate_goal_description("Attacker", "Compromise host 10.0.0.1")
        mock_warn.assert_called_once()
        assert "Controlled Host: 10.0.0.2" in mock_warn.call_args[0][0]

def test_read_agents_known_networks(parser):
    networks = parser.read_agents_known_networks("Attacker", "goal")
    assert len(networks) == 1
    net = list(networks)[0]
    assert isinstance(net, Network)
    assert net.ip == "10.0.0.0"
    assert net.mask == 24

def test_read_agents_known_hosts(parser):
    hosts = parser.read_agents_known_hosts("Attacker", "goal")
    assert len(hosts) == 3
    assert IP("10.0.0.1") in hosts
    assert "random" in hosts
    assert "all_local" in hosts

def test_read_agents_controlled_hosts(parser):
    hosts = parser.read_agents_controlled_hosts("Attacker", "goal")
    assert len(hosts) == 1
    assert IP("10.0.0.2") in hosts

def test_read_agents_known_services(parser):
    services = parser.read_agents_known_services("Attacker", "goal")
    assert IP("10.0.0.1") in services
    srv_list = services[IP("10.0.0.1")]
    assert len(srv_list) == 2
    assert isinstance(srv_list[0], Service)
    assert srv_list[0].name == "ssh"
    assert srv_list[0].type == "tcp"
    assert srv_list[0].version == "22"
    assert srv_list[0].is_local is True
    assert srv_list[1] == "random"

def test_read_agents_known_blocks(parser):
    blocks = parser.read_agents_known_blocks("Attacker", "goal")
    assert IP("10.0.0.1") in blocks
    assert list(blocks[IP("10.0.0.1")]) == [IP("10.0.0.2")] # it stores map iterator, resolve to list for assertion
    assert blocks[IP("10.0.0.3")] == "all_attackers"

def test_read_agents_known_data(parser):
    data_dict = parser.read_agents_known_data("Attacker", "goal")
    assert IP("10.0.0.1") in data_dict
    data_set = data_dict[IP("10.0.0.1")]
    
    assert len(data_set) == 2
    assert "random" in data_set
    
    # Find the Data object
    data_obj = next(d for d in data_set if isinstance(d, Data))
    assert data_obj.owner == "Admin"
    assert data_obj.id == "Password"

def test_get_start_position(parser):
    pos = parser.get_start_position("Attacker")
    assert "random" in pos["controlled_hosts"]
    assert len(pos["known_networks"]) == 0

    assert parser.get_start_position("Defender")["controlled_hosts"].pop() == IP("192.168.1.1")
    
    benign_pos = parser.get_start_position("Benign")
    assert benign_pos["controlled_hosts"] == ["random", "random", "random"]
    
    with pytest.raises(ValueError):
        parser.get_start_position("Unknown")

def test_get_win_conditions(parser):
    win = parser.get_win_conditions("Attacker")
    assert "random" in win["known_hosts"]

    benign_win = parser.get_win_conditions("Benign")
    assert len(benign_win["known_networks"]) == 0
    assert IP("1.1.1.1") in benign_win["known_data"]
    
    with pytest.raises(ValueError):
        parser.get_win_conditions("Unknown")

def test_get_scenario(parser):
    test_scenario_name = "scenario1" 
    parser.config = {'env': {'scenario': test_scenario_name}}
    result = parser.get_scenario()
    
    assert result is not None
    assert result == SCENARIO_REGISTRY[test_scenario_name]

def test_get_scenario_invalid(empty_parser):
    empty_parser.config = {"env": {"scenario": "unsupported_scenario"}}
    with pytest.raises(ValueError, match="Unsupported scenario"):
        empty_parser.get_scenario()

def test_get_seed(parser):
    assert parser.get_seed("random_entity") == 42
    
    # Assuming randint won't return exactly -1 unless we mock it, we just check it is an int
    seed = parser.get_seed("random_entity_str")
    assert isinstance(seed, int)
    assert 0 <= seed <= 100

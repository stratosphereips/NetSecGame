import pytest
import sys
from unittest.mock import patch, MagicMock, AsyncMock

# Mock out dependencies that might not be installed in the test environment
sys.modules['aiohttp'] = MagicMock()
sys.modules['cyst'] = MagicMock()
sys.modules['cyst.api'] = MagicMock()
sys.modules['cyst.api.environment'] = MagicMock()
sys.modules['cyst.api.environment.environment'] = MagicMock()
sys.modules['faker'] = MagicMock()

from netsecgame.game.configuration_manager import ConfigurationManager
from netsecgame.game_components import AgentRole

@pytest.fixture
def manager_local():
    return ConfigurationManager(task_config_file="dummy.yaml")

@pytest.fixture
def manager_remote():
    return ConfigurationManager(service_host="localhost", service_port=8080)

@pytest.fixture
def manager_both():
    return ConfigurationManager(task_config_file="dummy.yaml", service_host="localhost", service_port=8080)

@pytest.fixture
def manager_none():
    return ConfigurationManager()

def test_initialization():
    cm = ConfigurationManager(task_config_file="dummy.yaml", service_host="localhost", service_port=8080)
    assert cm._task_config_file == "dummy.yaml"
    assert cm._service_host == "localhost"
    assert cm._service_port == 8080
    assert cm._parser is None
    assert cm._cyst_objects is None

import asyncio

def test_load_no_source(manager_none):
    with pytest.raises(ValueError, match="Task configuration source not specified"):
        asyncio.run(manager_none.load())

@patch('netsecgame.game.configuration_manager.ConfigParser')
def test_load_local(mock_config_parser, manager_local):
    mock_parser_instance = MagicMock()
    mock_config_parser.return_value = mock_parser_instance
    mock_parser_instance.get_scenario.return_value = {"cyst": "objects"}

    asyncio.run(manager_local.load())

    mock_config_parser.assert_called_once_with(task_config_file="dummy.yaml")
    assert manager_local._parser == mock_parser_instance
    assert manager_local._cyst_objects == {"cyst": "objects"}
    assert manager_local._config_file_hash is not None

@patch('netsecgame.game.configuration_manager.get_str_hash')
@patch('netsecgame.game.configuration_manager.Environment')
@patch('netsecgame.game.configuration_manager.ConfigParser')
def test_load_remote_success(mock_config_parser, mock_environment, mock_get_str_hash, manager_remote):
    mock_env_instance = MagicMock()
    mock_environment.create.return_value = mock_env_instance
    mock_env_instance.configuration.general.load_configuration.return_value = {"cyst": "objects"}

    mock_parser_instance = MagicMock()
    mock_config_parser.return_value = mock_parser_instance
    
    mock_get_str_hash.return_value = "mocked_hash"

    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json.return_value = {"key": "value"}
    mock_response.__aenter__.return_value = mock_response

    mock_session = MagicMock()
    mock_session.get.return_value = mock_response
    mock_session.__aenter__.return_value = mock_session

    with patch('netsecgame.game.configuration_manager.ClientSession', return_value=mock_session):
        asyncio.run(manager_remote.load())

    assert manager_remote._cyst_objects == {"cyst": "objects"}
    mock_config_parser.assert_called_once_with(config_dict={"key": "value"})
    assert manager_remote._parser == mock_parser_instance

@patch('netsecgame.game.configuration_manager.ConfigParser')
def test_load_remote_failure_with_fallback(mock_config_parser, manager_both):
    mock_parser_instance = MagicMock()
    mock_config_parser.return_value = mock_parser_instance
    mock_parser_instance.get_scenario.return_value = {"cyst": "objects_local"}

    mock_response = AsyncMock()
    mock_response.status = 500
    mock_response.__aenter__.return_value = mock_response

    mock_session = MagicMock()
    mock_session.get.return_value = mock_response
    mock_session.__aenter__.return_value = mock_session

    with patch('netsecgame.game.configuration_manager.ClientSession', return_value=mock_session):
        asyncio.run(manager_both.load())

    # It should fall back to local configuration
    mock_config_parser.assert_called_once_with(task_config_file="dummy.yaml")
    assert manager_both._cyst_objects == {"cyst": "objects_local"}

def test_load_remote_failure_no_fallback(manager_remote):
    mock_response = AsyncMock()
    mock_response.status = 500
    mock_response.__aenter__.return_value = mock_response

    mock_session = MagicMock()
    mock_session.get.return_value = mock_response
    mock_session.__aenter__.return_value = mock_session

    with patch('netsecgame.game.configuration_manager.ClientSession', return_value=mock_session):
        with pytest.raises(RuntimeError, match="Remote configuration fetch failed"):
            asyncio.run(manager_remote.load())

def test_accessors_without_load(manager_local):
    with pytest.raises(RuntimeError, match="Configuration not loaded."):
        manager_local.get_starting_position("Attacker")
    
    with pytest.raises(RuntimeError, match="Configuration not loaded."):
        manager_local.get_win_conditions("Attacker")
        
    with pytest.raises(RuntimeError, match="Configuration not loaded."):
        manager_local.get_max_steps("Attacker")
        
    with pytest.raises(RuntimeError, match="Configuration not loaded."):
        manager_local.get_use_dynamic_addresses()

@pytest.fixture
def loaded_manager():
    cm = ConfigurationManager(task_config_file="dummy.yaml")
    cm._parser = MagicMock()
    cm._cyst_objects = {"cyst": "data"}
    cm._config_file_hash = "hash123"
    return cm

def test_get_cyst_objects(loaded_manager):
    assert loaded_manager.get_cyst_objects() == {"cyst": "data"}

def test_get_config_hash(loaded_manager):
    assert loaded_manager.get_config_hash() == "hash123"

def test_get_starting_position(loaded_manager):
    loaded_manager._parser.get_start_position.return_value = {"pos": (0, 0)}
    assert loaded_manager.get_starting_position("Attacker") == {"pos": (0, 0)}
    loaded_manager._parser.get_start_position.assert_called_once_with(agent_role="Attacker")

def test_get_use_firewall(loaded_manager):
    loaded_manager._parser.get_use_firewall.return_value = True
    assert loaded_manager.get_use_firewall() is True
    loaded_manager._parser.get_use_firewall.assert_called_once()

def test_get_required_num_players(loaded_manager):
    loaded_manager._parser.get_required_num_players.return_value = 2
    assert loaded_manager.get_required_num_players() == 2
    loaded_manager._parser.get_required_num_players.assert_called_once()

def test_get_all_starting_positions(loaded_manager):
    def mock_get_start(agent_role):
        if agent_role == AgentRole.Attacker:
            return {"network": "10.0.0.0"}
        raise KeyError
    
    loaded_manager._parser.get_start_position.side_effect = mock_get_start
    
    result = loaded_manager.get_all_starting_positions()
    assert result[AgentRole.Attacker] == {"network": "10.0.0.0"}
    assert result[AgentRole.Defender] == {}
    assert result[AgentRole.Benign] == {}

def test_get_all_max_steps(loaded_manager):
    def mock_get_steps(agent_role):
        if agent_role == AgentRole.Attacker:
            return 100
        return None
    
    loaded_manager._parser.get_max_steps.side_effect = mock_get_steps
    
    result = loaded_manager.get_all_max_steps()
    assert result[AgentRole.Attacker] == 100
    assert result[AgentRole.Defender] is None

"""
Tests related to the actions in the Network Security Game Environment
Author: Maria Rigaki - maria.rigaki@fel.cvut.cz
"""
import sys
from os import path
sys.path.append( path.dirname(path.dirname( path.abspath(__file__) ) ))
from env.network_security_game import Network_Security_Environment
import env.game_components as components
from env.scenarios import scenario_configuration

import pytest


GOAL = {
    "known_networks":set(),
    "known_hosts":set(),
    "controlled_hosts":set(),
    "known_services":{},
    "known_data":{components.IP("213.47.23.195"):{components.Data("User1", "DatabaseData")}}
}
START = {
    "known_networks":set(),
    "known_hosts":set(),
    "controlled_hosts":{components.IP("213.47.23.195"), components.IP("192.168.2.4")},
    "known_services":{},
    "known_data":{}
}

# Fixture are used to hold the current state and the environment
# Each step takes the previous one as input and returns the env and new obseravation variables
@pytest.fixture
def env_obs():
    """After init step"""
    env = Network_Security_Environment(random_start=False, verbosity=0)
    observation = env.initialize(win_conditions=GOAL, defender_positions=None, attacker_start_position=START, max_steps=500, agent_seed=42, cyst_config=scenario_configuration.configuration_objects)
    return (env, observation)

@pytest.fixture
def env_obs_scan(env_obs):
    """After scanning network"""
    env, _ = env_obs
    parameters = {"target_network":components.Network('192.168.1.0', 24)}
    action = components.Action(components.ActionType.ScanNetwork, parameters)
    new_obs = env.step(action)
    return (env, new_obs)

@pytest.fixture
def env_obs_found_service(env_obs_scan):
    """After finding service"""
    env, _ = env_obs_scan
    parameters = {"target_host":components.IP('192.168.1.3')}
    action = components.Action(components.ActionType.FindServices, parameters)
    new_obs = env.step(action)
    return (env, new_obs)

@pytest.fixture
def env_obs_exploited_service(env_obs_found_service):
    """After exploiting service"""
    env, _ = env_obs_found_service
    parameters = {"target_host":components.IP('192.168.1.3'), "target_service":components.Service('postgresql', 'passive', '14.3.0', False)}
    action = components.Action(components.ActionType.ExploitService, parameters)
    new_obs = env.step(action)
    return (env, new_obs)

@pytest.fixture
def env_obs_found_data(env_obs_exploited_service):
    """After finding data"""
    env, _ = env_obs_exploited_service
    parameters = {"target_host":components.IP('192.168.1.3')}
    action = components.Action(components.ActionType.FindData, parameters)
    new_obs = env.step(action)
    return (env, new_obs)

class TestActionsNoDefender:
    def test_scan_network_not_exist(self, env_obs):
        """
        Load initial state and scan a non-existing network
        """
        env, observation = env_obs
        parameters = {"target_network":components.Network('192.168.5.0', 24)}
        action = components.Action(components.ActionType.ScanNetwork, parameters)
        obs = env.step(action)
        assert obs.state == observation.state
        assert obs.reward == -1
        assert obs.done is False

    def test_scan_network_exists(self, env_obs):
        env, observation = env_obs
        parameters = {"target_network":components.Network('192.168.1.0', 24)}
        action = components.Action(components.ActionType.ScanNetwork, parameters)
        obs = env.step(action)
        assert obs.state != observation.state
        assert components.IP("192.168.1.3") in obs.state.known_hosts

    def test_scan_service_exists(self, env_obs_scan):
        env, observation = env_obs_scan
        parameters = {"target_host":components.IP('192.168.1.3')}
        action = components.Action(components.ActionType.FindServices, parameters)
        obs = env.step(action)
        assert obs.state != observation.state
        assert components.Service('postgresql', 'passive', '14.3.0', False) in obs.state.known_services[components.IP('192.168.1.3')]
        assert obs.reward == -1
        assert obs.done is False

    def test_scan_service_not_exist(self, env_obs_scan):
        env, observation = env_obs_scan
        parameters = {"target_host":components.IP('192.168.1.1')}
        action = components.Action(components.ActionType.FindServices, parameters)
        obs = env.step(action)
        assert obs.state == observation.state
        assert obs.reward == -1
        assert obs.done is False

    def test_exploit_service_remote_success(self, env_obs_found_service):
        env, observation = env_obs_found_service
        parameters = {"target_host":components.IP('192.168.1.3'), "target_service":components.Service('postgresql', 'passive', '14.3.0', False)}
        action = components.Action(components.ActionType.ExploitService, parameters)
        obs = env.step(action)
        assert obs.state != observation.state
        assert components.IP("192.168.1.3") in obs.state.controlled_hosts
        assert obs.reward == -1
        assert obs.done is False

    def test_exploit_service_remote_wrong_host(self, env_obs_found_service):
        """The service does not exist in this host"""
        env, observation = env_obs_found_service
        parameters = {"target_host":components.IP('192.168.1.4'), "target_service":components.Service('postgresql', 'passive', '14.3.0', False)}
        action = components.Action(components.ActionType.ExploitService, parameters)
        obs = env.step(action)
        assert obs.state == observation.state
        assert obs.reward == -1
        assert obs.done is False

    def test_exploit_service_remote_wrong_service(self, env_obs_found_service):
        """The service does not exist"""
        env, observation = env_obs_found_service
        parameters = {"target_host":components.IP('192.168.1.3'), "target_service":components.Service('dummy', 'passive', '14.3.0', False)}
        action = components.Action(components.ActionType.ExploitService, parameters)
        obs = env.step(action)
        assert obs.state == observation.state
        assert obs.reward == -1
        assert obs.done is False

    def test_find_data_in_after_exploit(self, env_obs_exploited_service):
        """Exploit known service"""
        env, observation = env_obs_exploited_service
        parameters = {"target_host":components.IP('192.168.1.3')}
        action = components.Action(components.ActionType.FindData, parameters)
        obs = env.step(action)
        assert obs.state != observation.state
        assert components.Data("User1", "DatabaseData") in obs.state.known_data[components.IP('192.168.1.3')]
        assert obs.reward == -1
        assert obs.done is False

    def test_find_data_no_access(self, env_obs_exploited_service):
        """No access to the host"""
        env, observation = env_obs_exploited_service
        parameters = {"target_host":components.IP('192.168.1.4')}
        action = components.Action(components.ActionType.FindData, parameters)
        obs = env.step(action)
        assert obs.state == observation.state
        assert obs.reward == -1
        assert obs.done is False

    def test_find_data_no_data(self, env_obs_exploited_service):
        """Controlled host with no data"""
        env, observation = env_obs_exploited_service
        # No data
        parameters = {"target_host":components.IP('192.168.2.2')}
        action = components.Action(components.ActionType.FindData, parameters)
        obs = env.step(action)
        assert obs.state == observation.state
        assert obs.reward == -1
        assert obs.done is False

    def test_exfiltrate_data_to_host_win(self, env_obs_found_data):
        """Exfiltrate found data to the target"""
        env, observation = env_obs_found_data
        parameters = {"target_host":components.IP('213.47.23.195'), "data":components.Data("User1", "DatabaseData"), "source_host":components.IP("192.168.1.3")}
        action = components.Action(components.ActionType.ExfiltrateData, parameters)
        obs = env.step(action)
        assert obs.state != observation.state
        assert components.Data("User1", "DatabaseData") in obs.state.known_data[components.IP('213.47.23.195')]
        assert obs.reward == 99
        assert obs.done

    def test_exfiltrate_data_to_host_nowin(self, env_obs_found_data):
        """Exfiltrate found data to controlled host"""
        env, observation = env_obs_found_data
        parameters = {"target_host":components.IP('192.168.2.4'), "data":components.Data("User1", "DatabaseData"), "source_host":components.IP("192.168.1.3")}
        action = components.Action(components.ActionType.ExfiltrateData, parameters)
        obs = env.step(action)
        assert obs.state != observation.state
        assert components.Data("User1", "DatabaseData") in obs.state.known_data[components.IP('192.168.2.4')]
        assert obs.reward == -1
        assert obs.done is False

    def test_exfiltrate_wrong_data(self, env_obs_found_data):
        """Exfiltrate wrong data to the target"""
        env, observation = env_obs_found_data
        parameters = {"target_host":components.IP('192.168.2.4'), "data":components.Data("User2", "DatabaseData"), "source_host":components.IP("192.168.1.3")}
        action = components.Action(components.ActionType.ExfiltrateData, parameters)
        obs = env.step(action)
        assert obs.state == observation.state
        assert obs.reward == -1
        assert obs.done is False

    def test_exfiltrate_data_wrong_source(self, env_obs_found_data):
        """Try to exfiltrate data to a host we don't control"""
        env, observation = env_obs_found_data
        parameters = {"target_host":components.IP('192.168.2.4'), "data":components.Data("User1", "DatabaseData"), "source_host":components.IP("192.168.1.4")}
        action = components.Action(components.ActionType.ExfiltrateData, parameters)
        obs = env.step(action)
        assert obs.state == observation.state
        assert obs.reward == -1
        assert obs.done is False

    def test_exfiltrate_data_wrong_target(self, env_obs_found_data):
        """Try to exfiltrate data to a host we don't control"""
        env, observation = env_obs_found_data
        parameters = {"target_host":components.IP('192.168.2.5'), "data":components.Data("User1", "DatabaseData"), "source_host":components.IP("192.168.1.4")}
        action = components.Action(components.ActionType.ExfiltrateData, parameters)
        obs = env.step(action)
        assert obs.state == observation.state
        assert obs.reward == -1
        assert obs.done is False

"""
Tests related to the actions in the Network Security Game Environment
Author: Maria Rigaki - maria.rigaki@fel.cvut.cz
"""
import sys
from os import path
sys.path.append( path.dirname(path.dirname( path.abspath(__file__) ) ))
from env.worlds.network_security_game import NetworkSecurityEnvironment
import env.game_components as components
import pytest


# Fixture are used to hold the current state and the environment
# Each step takes the previous one as input and returns the env and new obseravation variables
@pytest.fixture
def env_obs():
    """After init step"""
    env = NetworkSecurityEnvironment('tests/netsecenv-task-for-testing.yaml')
    starting_state = components.GameState(
        controlled_hosts=set([components.IP("213.47.23.195"), components.IP("192.168.2.2")]),
        known_hosts = set([components.IP("213.47.23.195"), components.IP("192.168.2.2")]),
        known_services={},
        known_data={},
        known_networks=set([components.Network('192.168.1.0', 24), components.Network('192.168.2.0', 24)])
    )
    env.reset()
    return (env, starting_state)

@pytest.fixture
def env_obs_scan(env_obs):
    """After scanning network"""
    env, state = env_obs
    parameters = {"target_network":components.Network('192.168.1.0', 24), "source_host":components.IP("192.168.2.2")}
    action = components.Action(components.ActionType.ScanNetwork, parameters)
    new_state = env.step(state=state, action=action, agent_id=None)
    return (env, new_state)

@pytest.fixture
def env_obs_found_service(env_obs_scan):
    """After finding service"""
    env, state = env_obs_scan
    parameters = {"target_host":components.IP('192.168.1.3'), "source_host":components.IP("192.168.2.2")}
    action = components.Action(components.ActionType.FindServices, parameters)
    new_state = env.step(state=state, action=action, agent_id=None)
    return (env, new_state)

@pytest.fixture
def env_obs_found_service2(env_obs_scan):
    """After finding service"""
    env, state = env_obs_scan
    parameters = {"target_host":components.IP('192.168.1.4'), "source_host":components.IP("192.168.2.2")}
    action = components.Action(components.ActionType.FindServices, parameters)
    new_state = env.step(state=state, action=action, agent_id=None)
    return (env, new_state)

@pytest.fixture
def env_obs_exploited_service(env_obs_found_service):
    """After exploiting service"""
    env, state = env_obs_found_service
    parameters = {"target_host":components.IP('192.168.1.3'), "target_service":components.Service('postgresql', 'passive', '14.3.0', False),
                "source_host":components.IP("192.168.2.2")}
    action = components.Action(components.ActionType.ExploitService, parameters)
    new_state = env.step(state=state, action=action, agent_id=None)
    return (env, new_state)

@pytest.fixture
def env_obs_exploited_service2(env_obs_found_service2):
    """After exploiting service"""
    env, state = env_obs_found_service2
    parameters = {"target_host":components.IP('192.168.1.4'),
                   "target_service":components.Service('lighttpd', 'passive', '1.4.54', False),
                   "source_host":components.IP("192.168.2.2")}
    action = components.Action(components.ActionType.ExploitService, parameters)
    new_state = env.step(state=state, action=action, agent_id=None)
    return (env, new_state)

@pytest.fixture
def env_obs_found_data(env_obs_exploited_service):
    """After finding data"""
    env, state = env_obs_exploited_service
    parameters = {"target_host":components.IP('192.168.1.3'),"source_host":components.IP('192.168.1.3') }
    action = components.Action(components.ActionType.FindData, parameters)
    new_state = env.step(state=state, action=action, agent_id=None)
    return (env, new_state)

@pytest.fixture
def env_obs_found_data2(env_obs_exploited_service2):
    """After finding data"""
    env, state = env_obs_exploited_service2
    parameters = {"target_host":components.IP('192.168.1.4'), "source_host":components.IP('192.168.1.4')}
    action = components.Action(components.ActionType.FindData, parameters)
    new_state = env.step(state=state, action=action, agent_id=None)
    return (env, new_state)

@pytest.fixture
def env_obs_blocked_connection(env_obs_exploited_service):
    "After blocking"
    env, state = env_obs_exploited_service
    source_host = components.IP('192.168.2.2')
    target_host = components.IP('192.168.1.3')
    blocked_host = components.IP('192.168.2.2')
    parameters = {
        "target_host":target_host,
        "source_host":source_host,
        "blocked_host": blocked_host}
    action = components.Action(components.ActionType.BlockIP, parameters)
    new_state = env.step(state=state, action=action, agent_id=None)
    return (env, new_state)

class TestActionsNoDefender:
    def test_scan_network_not_exist(self, env_obs):
        """
        Load initial state and scan a non-existing network
        """
        env, state = env_obs
        parameters = {"target_network":components.Network('192.168.5.0', 24), "source_host":components.IP("192.168.2.2")}
        action = components.Action(components.ActionType.ScanNetwork, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert new_state == state

    def test_scan_network_exists(self, env_obs):
        env, state = env_obs
        parameters = {"target_network":components.Network('192.168.1.0', 24), "source_host":components.IP("192.168.2.2")}
        action = components.Action(components.ActionType.ScanNetwork, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state != new_state
        assert components.IP("192.168.1.3") in new_state.known_hosts
    
    def test_scan_source_host_not_valid(self, env_obs):
        """
        Load initial state and scan a network from non-controlled host
        """
        env, state = env_obs
        parameters = {"target_network":components.Network('192.168.1.0', 24), "source_host":components.IP("1.1.1.1")}
        action = components.Action(components.ActionType.ScanNetwork, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state == new_state

    def test_scan_service_exists(self, env_obs_scan):
        env, state = env_obs_scan
        parameters = {"target_host":components.IP('192.168.1.3'), "source_host":components.IP("192.168.2.2")}
        action = components.Action(components.ActionType.FindServices, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state != new_state
        assert components.Service('postgresql', 'passive', '14.3.0', False) in new_state.known_services[components.IP('192.168.1.3')]

    def test_scan_service_not_exist(self, env_obs_scan):
        env, state = env_obs_scan
        parameters = {"target_host":components.IP('192.168.1.1'), "source_host":components.IP("192.168.2.2")}
        action = components.Action(components.ActionType.FindServices, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state == new_state

    def test_scan_service_source_host_not_valid(self, env_obs_scan):
        env, state = env_obs_scan
        parameters = {"target_host":components.IP('192.168.1.3'), "source_host":components.IP("1.1.1.1")}
        action = components.Action(components.ActionType.FindServices, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        #assert components.IP('192.168.1.3') not in obs.state.known_services.keys()
        assert state == new_state

    def test_exploit_service_remote_success(self, env_obs_found_service):
        env, state = env_obs_found_service
        parameters = {"target_host":components.IP('192.168.1.3'),
                       "target_service":components.Service('postgresql', 'passive', '14.3.0', False),
                       "source_host":components.IP("192.168.2.2")}
        action = components.Action(components.ActionType.ExploitService, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state != new_state
        assert components.IP("192.168.1.3") in new_state.controlled_hosts

    def test_exploit_service_remote_wrong_target_host(self, env_obs_found_service):
        """The service does not exist in this host"""
        env, state = env_obs_found_service
        parameters = {"target_host":components.IP('192.168.1.4'),
                       "target_service":components.Service('postgresql', 'passive', '14.3.0', False),
                       "source_host":components.IP("192.168.2.2")}
        action = components.Action(components.ActionType.ExploitService, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state == new_state
    
    def test_exploit_service_remote_wrong_source_host(self, env_obs_found_service):
        """The service does not exist in this host"""
        env, state = env_obs_found_service
        parameters = {"target_host":components.IP('192.168.1.3'),
                       "target_service":components.Service('postgresql', 'passive', '14.3.0', False),
                       "source_host":components.IP("1.1.1.1")}
        action = components.Action(components.ActionType.ExploitService, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state == new_state

    def test_exploit_service_remote_wrong_service(self, env_obs_found_service):
        """The service does not exist"""
        env, state = env_obs_found_service
        parameters = {"target_host":components.IP('192.168.1.3'),
                       "target_service":components.Service('dummy', 'passive', '14.3.0', False),
                       "source_host":components.IP("192.168.2.2")}
        action = components.Action(components.ActionType.ExploitService, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state == new_state

    def test_find_data_in_after_exploit(self, env_obs_exploited_service):
        """Exploit known service"""
        env, state = env_obs_exploited_service
        parameters = {"target_host":components.IP('192.168.1.3'), "source_host":components.IP('192.168.1.3')}
        action = components.Action(components.ActionType.FindData, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state != new_state
        assert components.Data("User1", "DatabaseData") in new_state.known_data[components.IP('192.168.1.3')]

    def test_find_data_no_access(self, env_obs_exploited_service):
        """
        No access to the host
        Exploited service is 192.168.1.3
        """
        env, state = env_obs_exploited_service
        parameters = {"target_host":components.IP('192.168.1.4'),"source_host":components.IP('192.168.1.4')}
        action = components.Action(components.ActionType.FindData, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state == new_state

    def test_find_data_no_data(self, env_obs_exploited_service):
        """Controlled host with no data"""
        env, state = env_obs_exploited_service
        # No data
        parameters = {"target_host":components.IP('192.168.2.2'), "source_host":components.IP('192.168.2.2')}
        action = components.Action(components.ActionType.FindData, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state == new_state
    
    def test_find_data_wrong_source_host(self, env_obs_exploited_service):
        """Controlled host with no data"""
        env, state = env_obs_exploited_service
        # No data
        parameters = {"target_host":components.IP('192.168.1.3'), "source_host":components.IP('1.1.1.1')}
        action = components.Action(components.ActionType.FindData, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state == new_state

    def test_exfiltrate_data_to_host_win(self, env_obs_found_data):
        """Exfiltrate found data to the target"""
        env, state = env_obs_found_data
        parameters = {"target_host":components.IP('213.47.23.195'), "data":components.Data("User1", "DatabaseData"), "source_host":components.IP("192.168.1.3")}
        action = components.Action(components.ActionType.ExfiltrateData, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state != new_state
        assert components.Data("User1", "DatabaseData") in new_state.known_data[components.IP('213.47.23.195')]

    def test_exfiltrate_data_to_host_nowin(self, env_obs_found_data):
        """
        Exfiltrate found data to controlled host.
        The exfiltration succeeds but it is not the correct host.
        """
        env, state = env_obs_found_data
        parameters = {"target_host":components.IP('192.168.2.2'), "data":components.Data("User1", "DatabaseData"), "source_host":components.IP("192.168.1.3")}
        action = components.Action(components.ActionType.ExfiltrateData, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state != new_state
        assert components.Data("User1", "DatabaseData") in new_state.known_data[components.IP('192.168.2.2')]

    def test_exfiltrate_data_to_host_nowin2(self, env_obs_found_data2):
        """
        Exfiltrate data that exist from a host we control but are not the goal data.
        The exfiltration succeeds but it the game does not end.
        """
        env, state = env_obs_found_data2
        parameters = {"target_host":components.IP('213.47.23.195'), "data":components.Data("User2", "WebServerData"), "source_host":components.IP("192.168.1.4")}
        action = components.Action(components.ActionType.ExfiltrateData, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state != new_state
        assert components.Data("User2", "WebServerData") in new_state.known_data[components.IP('213.47.23.195')]

    def test_exfiltrate_data_wrong_data(self, env_obs_found_data):
        """Exfiltrate wrong data to the target"""
        env, state = env_obs_found_data
        parameters = {"target_host":components.IP('192.168.2.4'), "data":components.Data("User2", "DatabaseData"), "source_host":components.IP("192.168.1.3")}
        action = components.Action(components.ActionType.ExfiltrateData, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state == new_state

    def test_exfiltrate_data_wrong_source(self, env_obs_found_data):
        """Try to exfiltrate data to a host we don't control"""
        env, state = env_obs_found_data
        parameters = {"target_host":components.IP('192.168.2.4'), "data":components.Data("User1", "DatabaseData"), "source_host":components.IP("192.168.1.4")}
        action = components.Action(components.ActionType.ExfiltrateData, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state == new_state

    def test_exfiltrate_data_wrong_target(self, env_obs_found_data):
        """Try to exfiltrate data to a host we don't control"""
        env, state = env_obs_found_data
        parameters = {"target_host":components.IP('192.168.2.5'), "data":components.Data("User1", "DatabaseData"), "source_host":components.IP("192.168.1.4")}
        action = components.Action(components.ActionType.ExfiltrateData, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state == new_state

    def test_exfiltrate_data_not_found(self, env_obs_exploited_service):
        """
        Try to exfiltrate data that was not found before. 
        Data is winning data, but it should not matter
        Source host is the correct host that has this data.
        Target host is correct CC host
        Test should fail.
        """
        env, state = env_obs_exploited_service
        parameters = {"target_host":components.IP('213.47.23.195'), "data":components.Data("User1", "DatabaseData"), "source_host":components.IP("192.168.1.3")}
        action = components.Action(components.ActionType.ExfiltrateData, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state == new_state

    def test_exploit_service_witout_find_service_in_host(self, env_obs_scan):
        """Try to exploit service without running FindServices first"""
        env, state = env_obs_scan
        parameters = {"target_host":components.IP('192.168.1.3'),
                       "target_service":components.Service('postgresql', 'passive', '14.3.0', False),
                       "source_host":components.IP('192.168.2.2')}
        action = components.Action(components.ActionType.ExploitService, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert state == new_state
        assert components.IP('192.168.1.3') not in new_state.known_services

    def test_block_ip_same_host(self, env_obs_exploited_service):
        env, state = env_obs_exploited_service
        target_host = components.IP('192.168.2.2')
        blocked_host = components.IP("1.1.1.1")
        parameters = {
            "target_host":target_host,
            "source_host":target_host,
            "blocked_host": blocked_host}
        action = components.Action(components.ActionType.BlockIP, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert target_host in new_state.known_blocks.keys()
        assert blocked_host in new_state.known_blocks[target_host]

    def test_block_ip_same_different_source(self, env_obs_exploited_service):
        env, state = env_obs_exploited_service
        source_host = components.IP('192.168.2.2')
        target_host = components.IP("192.168.1.3")
        blocked_host = components.IP("1.1.1.1")
        parameters = {
            "target_host":target_host,
            "source_host":source_host,
            "blocked_host": blocked_host}
        action = components.Action(components.ActionType.BlockIP, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert target_host in new_state.known_blocks.keys()
        assert blocked_host in new_state.known_blocks[target_host]

    def test_block_ip_self_block(self, env_obs_exploited_service):
        env, state = env_obs_exploited_service
        target_host = components.IP('192.168.2.2')
        parameters = {
            "target_host":target_host,
            "source_host":components.IP('192.168.2.2'),
            "blocked_host": target_host}
        action = components.Action(components.ActionType.BlockIP, parameters)
        new_state = env.step(state=state, action=action, agent_id=None)
        assert target_host not in new_state.known_blocks.keys()
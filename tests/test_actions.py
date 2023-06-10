import sys
from os import path
sys.path.append( path.dirname(path.dirname( path.abspath(__file__) ) ))
from env.network_security_game import Network_Security_Environment
import env.game_components as components
import netaddr
from env.scenarios import scenario_configuration
from env.scenarios import smaller_scenario_configuration
from env.scenarios import tiny_scenario_configuration

goal = {
    "known_networks":set(),
    "known_hosts":set(),
    "controlled_hosts":set(),
    "known_services":{},
    "known_data":{components.IP("213.47.23.195"):{components.Data("User1", "Data1FromServer1")}}
}
attacker_start = {
    "known_networks":set(),
    "known_hosts":set(),
    "controlled_hosts":{components.IP("213.47.23.195"), components.IP("192.168.2.4")},
    "known_services":{},
    "known_data":{}
}

env = Network_Security_Environment(random_start=False, verbosity=0)
observation = env.initialize(win_conditons=goal, defender_positions=None, attacker_start_position=attacker_start, max_steps=500, agent_seed=42, cyst_config=scenario_configuration.configuration_objects)

class TestActionsNoDefender:
    def test_scan_network_not_exists(self):
       current_state = observation.state
       parameters = {"target_network":components.Network('192.168.5.0', 24)}
       action = components.Action(components.ActionType.ScanNetwork, parameters)
       obs = env.step(action)
       assert obs.state == current_state

    def test_scan_network_exists(self):
       current_state = observation.state
       parameters = {"target_network":components.Network('192.168.1.0', 24)}
       action = components.Action(components.ActionType.ScanNetwork, parameters)
       obs = env.step(action)
       assert obs.state != current_state
       assert components.IP("192.168.1.3") in obs.state.known_hosts

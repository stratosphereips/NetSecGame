# Tests to see if all actions can be run
# Author sebastian garcia sebastian.garcia@agents.fel.cvut.cz
import sys
from os import path
sys.path.append( path.dirname(path.dirname( path.abspath(__file__) ) ))
from env.network_security_game import Network_Security_Environment
import env.game_components as components
import netaddr
from env.scenarios import scenario_configuration
from env.scenarios import smaller_scenario_configuration
from env.scenarios import tiny_scenario_configuration
import pytest


def test_winning_action():

    random_start = False

    if random_start:
        goal = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{components.IP("213.47.23.195"):"random"}
        }
        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{components.IP("213.47.23.195"), components.IP("192.168.1.9")},
            "known_services":{},
            "known_data":{}
        }
    else:
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

    env = Network_Security_Environment(random_start=random_start, verbosity=0)

    # Do we have a defender?
    defender = None

    # Initialize the game
    observation = env.initialize(win_conditons=goal, defender_positions=defender, attacker_start_position=attacker_start, max_steps=500, agent_seed=42, cyst_config=scenario_configuration.configuration_objects)

    # Test of winning actions only. You need 2
    print(f'Testing the winning action')
    obs = env.step(components.Action(components.ActionType.ExploitService, params={'target_host': components.IP('192.168.1.2'), 'target_service': components.Service(name='remote desktop service', type='passive', version='10.0.19041', is_local=False)}))
    obs = env.step(components.Action(components.ActionType.ExfiltrateData, params={'target_host': components.IP('213.47.23.195'), 'data': components.Data('User1', 'DataFromServer1'), 'source_host': components.IP('192.168.1.2')}))

    assert True

if __name__ == '__main__':
    test_winning_action()

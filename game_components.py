#Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
from asyncio import protocols
from collections import namedtuple

#Transition between nodes
"""
Transition represents generic actions for attacker in the game. Each transition has a default probabilities
for success and detection (if defensive measures are present). Each transition has default cost and reward(if successful).
Net reward can be computed as follows net_reward = sucess*default_reward - default_cost
"""
Transition = namedtuple("Transition", ["type", "default_success_p", "default_detection_p", "default_reward", "default_cost"])

#List of transitions available for attacker with default parameters
transitions = {
    "ScanNetwork": Transition("ScanNetwork",0.9,0.5,1,0.1),
    "FindServices": Transition("FindServices",0.9,0.6,1,0.1),
    "FindData": Transition("FindData",0.5,0.9,2,0.1),
    "ExecuteCodeInService": Transition("ExecuteCodeInService",0.3,0.3,0.1,0.3),
    "ExfiltrateData": Transition("ExfiltrateData",0.8,0.8,1000,0.1),
}

#Actions
"""
Actions are composed of the transition type (see Transition) and additional parameters listed in dictionary
 - ScanNetwork {"target_network": "X.X.X.X/mask" (string)}
 - FindServices {"target_host": "X.X.X.X" (string)}
 - FindData {"target_host": "X.X.X.X" (string)}
 - ExecuteCodeInService {"target_host": "X.X.X.X" (string), "target_service":"service_name" (string)}
 - ExfiltrateData {"target_host": "X.X.X.X" (string), "source_host":"X.X.X.X" (string), "data":"path_to_data" (string)}
"""
Action = namedtuple("Action", ["transition", "parameters"])

#Observation - given to agent after taking an action
"""
Observations are given when making a step in the environment.
 - observation: current state of the environment
 - reward: float  value with immediate reward
 - is_terminal: boolean, True if the game ends the current state
 - done: boolean, True if no further interaction is possible (either terminal state or because of timeout)
 - info: dict, can contain additional information about the state
"""
Observation = namedtuple("Observation", ["observation", "reward", "is_terminal", "done", "info"])

"""
Game state represents the states in the game state space.

"""
class GameState(object):
    def __init__(self, controlled_hosts:list=[], known_hosts:list=[], know_services:dict={},
    known_data:dict={}, known_networks=[]) -> None:
        self._controlled_hosts = controlled_hosts
        self._known_networks = known_networks
        self._known_hosts = known_hosts
        self._known_services = know_services
        self._known_data = known_data
    
    @property
    def controlled_hosts(self):
        return self._controlled_hosts

    @property
    def known_hosts(self):
        return self._known_hosts
    
    @property
    def known_services(self):
        return self._known_services
    
    @property
    def known_networks(self):
        return self._known_networks
    
    @property
    def known_data(self):
        return self._known_data
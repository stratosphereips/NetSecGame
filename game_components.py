#Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
from collections import namedtuple
import deepdiff
from frozendict import frozendict

# Transition between nodes
"""
Transition represents generic actions for attacker in the game. Each transition has a default probabilities
for success and detection (if defensive measures are present). Each transition has default cost and reward (if successful).
Net reward can be computed as follows net_reward = sucess*default_reward - default_cost
"""
Transition = namedtuple("Transition", ["type", "default_success_p", "default_detection_p", "default_reward", "default_cost"])

#List of transitions available for attacker with default parameters
# transitions = {
#     "ScanNetwork": Transition("ScanNetwork",0.9,0.5,1,0.1), #In the beginning we artificially add 3 more networks in both directions
#     "FindServices": Transition("FindServices",0.9,0.6,1,0.1),
#     "FindData": Transition("FindData",0.5,0.9,2,0.1),
#     "ExecuteCodeInService": Transition("ExecuteCodeInService",0.3,0.3,20,0.3),
#     "ExfiltrateData": Transition("ExfiltrateData",0.8,0.8,1000,0.1),
# }
transitions = {
    "ScanNetwork": Transition("ScanNetwork", 0.9, 0.2, 0,1), 
    "FindServices": Transition("FindServices",0.9, 0.3,0,1),
    "FindData": Transition("FindData",0.8, 0.1, 0, 1),
    "ExecuteCodeInService": Transition("ExecuteCodeInService", 0.7, 0.4, 0, 1),
    "ExfiltrateData": Transition("ExfiltrateData",0.8, 0.1, 0, 1),
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
#Action = namedtuple("Action", ["transition", "parameters"])
class Action(object):
    
    def __init__(self, transition:str, params:list) -> None:
        self._transition_name = transition
        self._parameters = params
    
    @property
    def transition(self) -> Transition:
        return transitions[self._transition_name]
    @property
    def parameters(self)->dict:
        return self._parameters
    def __str__(self) -> str:
        return f"Action <{self._transition_name}|{self.parameters}>"
    
    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, Action):
            return self.transition == __o.transition and self.parameters == __o.parameters
        return False
    def __hash__(self) -> int:
        return hash(self.transition) + hash("".join(self.parameters))

#Observation - given to agent after taking an action
"""
Observations are given when making a step in the environment.
 - observation: current state of the environment
 - reward: float  value with immediate reward
 - is_terminal: boolean, True if the game ends the current state
 - done: boolean, True if no further interaction is possible (either terminal state or because of timeout)
 - info: dict, can contain additional information about the state
"""
Observation = namedtuple("Observation", ["observation", "reward", "done", "info"])

#Service - agents representation of service found with "FindServices" action
Service = namedtuple("Service", ["name", "type", "version"])

"""
Game state represents the states in the game state space.

"""
class GameState(object):
    def __init__(self, controlled_hosts:set={}, known_hosts:set={}, know_services:dict={},
    known_data:dict={}, known_networks:set={}) -> None:
        self._controlled_hosts = frozenset(controlled_hosts)
        self._known_networks = frozenset(known_networks)
        self._known_hosts = frozenset(known_hosts)
        self._known_services = frozendict(know_services)
        self._known_data = frozendict({k:frozenset([x for x in v]) for k,v in known_data.items()})
    
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
    
    def __str__(self) -> str:
        return f"State<nets:{self.known_networks}; known:{self.known_hosts}; owned:{self.controlled_hosts}; services:{self._known_services}; data:{self._known_data}>"
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, GameState):
            #known_nets
            if len(self.known_networks) != len(other.known_networks) or len(self.known_networks.difference(other.known_networks)) != 0:
                #print("mismatch in known_nets")
                return False
            #known_hosts
            if len(self.known_hosts) != len(other.known_hosts) or len(self.known_hosts.difference(other.known_hosts)) != 0:
                #print("mismatch in known_hosts")
                return False
            #controlled_hosts
            if len(self.controlled_hosts) != len(other.controlled_hosts) or len(self.controlled_hosts.difference(other.controlled_hosts)) != 0:
                #print("mismatch in owned_nets")
                return False
            #known_services
            if len(deepdiff.DeepDiff(self.known_services, other.known_services, ignore_order=True)) != 0:
                #print("mismatch in known_services")
                return False
            #data
            if len(deepdiff.DeepDiff(self.known_data, other.known_data, ignore_order=True)) != 0:
                #print("mismatch in data")
                return False
            return True
        return False
    
    def __hash__(self) -> int:
        return hash(self.known_hosts) + hash(self.known_networks) + hash(self.controlled_hosts) + hash(self.known_data) + hash(self.known_services)
    
if __name__ == '__main__':
    # Used for tests

    a = Action("FindServices", ["192.168.1.0"])
    a2 = Action("FindServices", ["192.168.1.0"])
    #print(hash(a), hash(a2))
    
    
    
    # # print(a1, a2, a1==a2)
    s1 = GameState({"192.168.1.0"}, {}, {'213.47.23.195': frozenset([Service(name='bash', type='passive', version='5.0.0'), Service(name='listener', type='passive', version='1.0.0')])},{},{})
    #print(hash(s1))
    s2 = GameState({"192.168.1.0"}, {}, {'213.47.23.195': frozenset([Service(name='listener', type='passive', version='1.0.0'), Service(name='bash', type='passive', version='5.0.0')])}, {},{})
    s3 = GameState({"192.168.1.1"}, {}, {}, {},{})
    #print(s1, s2, s1 == s2)
    q = {}
    if (a,s1) not in q.keys():
        print("missing")
    q[(a,s1)] = 0
    q[(a,s2)] = 1
    print(q)
    q[(a,s3)] = 2
    print(q)
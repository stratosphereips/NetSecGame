#Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
from asyncio import protocols
from collections import namedtuple

#Transition between nodes
Transition = namedtuple("Transition", ["type", "default_succes_p", "default_detection_p", "default_reward", "default_cost"])

#Action
Action = namedtuple("Action", ["transition", "parameters"])

#Observation - given to agent after taking an action
Observation = namedtuple("Observation", ["observation", "rewards", "is_terminal", "done", "info"])

#List of transitions available for attacker with default parameters
transitions = {
    "ScanNetwork": Transition("ScanNetwork",0.9,0.5,1,0.1),
    "FindServices": Transition("FindServices",0.9,0.6,1,0.1),
    "FindData": Transition("FindData",0.5,0.9,2,0.1),
    "ExecuteCodeInService": Transition("ExecuteCodeInService",0.3,0.3,0.1,0.3),
    "ExfiltrateData": Transition("ExfiltrateData",0.8,0.8,1000,0.1),
}

"""
Game state represents the states in the game state space.

"""
class GameState(object):
    def __init__(self, id:float, controlled_hosts:list=[], known_hosts:list=[], know_services:dict={},
    known_data:dict={}, known_networks=[], defender_nodes:list=[]) -> None:
        self._id = id
        self._controlled_hosts = controlled_hosts
        self._known_networks = known_networks
        self._known_hosts = known_hosts
        self._known_services = know_services
        self._known_data = known_data
        self._is_terminal = False
    
    def str(self) ->str:
        return "Node {self._id}"
    
    @property
    def controlled_hosts(self):
        return self._controlled_hosts
    
    @property
    def id(self):
        return self._id
    
    @property
    def is_terminal(self):
        return self._is_terminal
    
    @property
    def known_hosts(self):
        return self._known_hosts
    
    @property
    def known_services(self):
        return self._known_services
    
    @property
    def known_networks(self):
        return self._known_networks
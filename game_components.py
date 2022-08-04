#Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
from asyncio import protocols
from collections import namedtuple

#Transition between nodes
Transition = namedtuple("Transition", ["id", "action", "default_succes_p", "default_detection_p", "default_reward", "default_cost"])

#List of transitions available for attacker with default parameters
Actions = [
    Transition(0, "Wait", 1,0,0,0),
    Transition(1, "ScanNetwork",0.9,0.5,1,0.1),
    Transition(2, "FindServices",0.9,0.6,1,0.1),
    Transition(3, "FindData",0.5,0.9,2,0.1),
    Transition(4, "ExecuteCodeInService",0.3,0.3,0.1,0.3),
    Transition(5, "ExfiltrateData",0.8,0.8,1000,0.1),
]

"""
Game state represents the states in the game state space.

"""
class GameState(object):
    def __init__(self, id:float, controled_hosts:list=[], known_hosts:list=[], know_services:dict={}, defender_nodes:list=[]) -> None:
        self._id = id
        self._controled_hosts = controled_hosts
        self._known_hosts = known_hosts
        self._known_services = self.know_services
        self._known_data = self.known_data
        self._defender_nodes = defender_nodes
        self._is_terminal = False
    
    def str(self) ->str:
        return "Node {self._id}"
    
    @property
    def controled_hosts(self):
        return self._controled_hosts
    
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
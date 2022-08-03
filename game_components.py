#Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
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
    Transition(6, "LeaveHost",None,None,None,None)
]

"""
Game state represents the states in the game state space.

"""
class GameState(object):
    def __init__(self, id:float, controled_hosts:list=[], known_hosts:list=[], know_services:dict={}, defender_nodes:list=[]) -> None:
        self.id = id
        self.controled_hosts = controled_hosts
        self.known_hosts = known_hosts
        self.know_services = self.know_services
        self.defender_nodes = defender_nodes
        self.is_terminal = False
    
    def str(self) ->str:
        return "Node {self.id}"
    
    def get_actions(self):
        raise NotImplementedError
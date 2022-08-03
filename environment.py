from multiprocessing import connection
from tkinter.tix import Tree
from game_components import *
import yaml

class Player(object):
    def __init__(self, type:str) -> None:
        if type in "attacker":
            self.is_attacker=True
        elif type in "defender":
            self.is_defender=True
        
    def move(self,state:GameState):
        raise NotImplementedError

class Environment(object):
    def __init__(self) -> None:
        self.defener_placements = {}
    
    def register_attacker(self, attacker:Player):
        self.attacker = attacker
    
    def register_defender(self, defender:Player):
        self.defender = defender

    def defender_move(self, defender_placements:dict) -> None:
        #Played only ones at the begining of the game
        self.defener_placements = self.defender.move()

    def process_topology(self, filename) -> None:
        """
        Method to process YAML file with congifuration from CYST and build a state space of the environment with possible transitions.
        """
        nodes = {}
        connections = {}
        with open(filename, "r") as stream:
            try:
                data = yaml.safe_load(stream)
                print(type(data))
                for k,v in data.items():
                    if v['cls_type'] in ["NodeConfig", "RouterConfig"]: #new node or router in the network
                        nodes[v['id']] = v
                        connections[v['id']] = []
                    elif v['cls_type'] in "ConnectionConfig": # TODO
                        connections[v["src_id"]].append(v["dst_id"])
                        connections[v["dst_id"]].append(v["src_id"])
                    #print(k, v)
                print(nodes)
                print(connections)
            except yaml.YAMLError as e:
                print(e)
                
    def initialize(self, attacker_start_host):
        self.attacker_start = GameState(0, [attacker_start_host], [attacker_start_host],{})

    def get_attacker_actions(self, state:GameState)->list:
        valid_actions = []
        
        raise NotImplementedError
    
    def get_next_state(self, state:GameState, action)-> GameState:
        raise NotImplementedError

if __name__ == "__main__":
    env = Environment()
    env.process_topology("test.yaml")
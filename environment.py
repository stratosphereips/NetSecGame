from game_components import *

class Player(object):
    def __init__(self) -> None:
        pass

    def move(self, ):
        return NotImplementedError

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

    def initialize(self, attacker_start_host):
        self.attacker_start = GameState(0, [attacker_start_host], [attacker_start_host],{})

    def get_attacker_actions(self, state:GameState)->list:
        raise NotImplementedError
    
    def get_next_state(self, state:GameState, action)-> GameState:
        raise NotImplementedError
# Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
# Template of world to be used in AI Dojo
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import env.game_components as components
import logging
from utils.utils import ConfigParser

"""
Basic class for worlds to be used in the AI Dojo.
Every world (environment) used in AI Dojo should extend this class and implement
all its methods to be compatible with the game server and game coordinator.
"""
class AIDojoWorld(object):
    def __init__(self, task_config_file:str, world_name:str="BasicAIDojoWorld")->None:
        self.task_config = ConfigParser(task_config_file)
        self.logger = logging.getLogger(world_name)

    def step(current_state:components.GameState, action:components.Action, agent_id:tuple)-> components.GameState:
        """
        Executes given action in a current state of the environment and produces new GameState.
        """
        raise NotImplementedError

    def create_state_from_view(self, view:dict, add_neighboring_nets:bool=True)->components.GameState:
        """
        Produces a GameState based on the view of the world.
        """
        raise NotImplementedError
    
    def reset()->None:
        """
        Resets the world to its initial state.
        """
        raise NotImplementedError

    def update_goal_descriptions(self, goal_description:str)->str:
       """
       Takes the existing goal description (text) and updates it with respect to the world.
       """
       raise NotImplementedError
    
    def update_goal_dict(self, goal_dict:dict)->dict:
        """
        Takes the existing goal dict and updates it with respect to the world.
        """
        raise NotImplementedError
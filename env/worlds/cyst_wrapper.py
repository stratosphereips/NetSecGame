# Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import env.game_components as components
from env.worlds.aidojo_world import AIDojoWorld

class CYSTWrapper(AIDojoWorld):
    """
    Class for connection CYST with the coordinator of AI Dojo
    """
    def __init__(self, task_config_file, world_name="CYST") -> None:
        super().__init__(task_config_file, world_name)
        self.logger.info("Initializing CYST environment")


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
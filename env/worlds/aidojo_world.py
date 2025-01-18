# Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
# Template of world to be used in AI Dojo
import sys
import os
import asyncio

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import logging
from utils.utils import ConfigParser
from env.game_components import GameState, Action, GameStatus, ActionType

"""
Basic class for worlds to be used in the AI Dojo.
Every world (environment) used in AI Dojo should extend this class and implement
all its methods to be compatible with the game server and game coordinator.
"""
class AIDojoWorld(object):
    def __init__(self, task_config_file:str,action_queue:asyncio.Queue, response_queue:asyncio.Queue, world_name:str="BasicAIDojoWorld")->None:
        self.task_config = ConfigParser(task_config_file)
        self.logger = logging.getLogger(world_name)
        self._action_queue = action_queue
        self._response_queue = response_queue
        self._world_name = world_name
    
    @property
    def world_name(self)->str:
        return self._world_name

    def step(self, current_state:GameState, action:Action, agent_id:tuple)-> GameState:
        """
        Executes given action in a current state of the environment and produces new GameState.
        """
        raise NotImplementedError

    def create_state_from_view(self, view:dict, add_neighboring_nets:bool=True)->GameState:
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

    async def handle_incoming_action(self)->None:
        """
        Asynchronously handles incoming actions from agents and processes them accordingly.

        This method continuously listens for actions from the `_action_queue`, processes them based on their type,
        and sends the appropriate response to the `_response_queue`. It handles different types of actions such as
        joining a game, quitting a game, and resetting the game. For other actions, it updates the game state by
        calling the `step` method.

        Raises:
            asyncio.CancelledError: If the task is cancelled, it logs the termination message.

        Action Types:
            - ActionType.JoinGame: Creates a new game state and sends a CREATED status.
            - ActionType.QuitGame: Sends an OK status with an empty game state.
            - ActionType.ResetGame: Resets the world if the agent is "world", otherwise resets the game state and sends a RESET_DONE status.
            - Other: Updates the game state using the `step` method and sends an OK status.

        Logging:
            - Logs the start of the task.
            - Logs received actions and game states from agents.
            - Logs the messages being sent to agents.
            - Logs termination due to `asyncio.CancelledError`.
        """
        try:
            self.logger.info(f"\tStaring {self.world_name} task.")
            while True:
                agent_id, action, game_state = await self._action_queue.get()
                self.logger.debug(f"Received from{agent_id}: {action}, {game_state}.")
                match action.type:
                    case ActionType.JoinGame:
                        msg = (agent_id, (self.create_state_from_view(game_state), GameStatus.CREATED))
                    case ActionType.QuitGame:
                        msg = (agent_id, (GameState(),GameStatus.OK))
                    case ActionType.ResetGame:
                        if agent_id == "world": #reset the world
                            self.reset()
                            continue
                        else:
                            msg = (agent_id, (self.create_state_from_view(game_state), GameStatus.RESET_DONE))
                    case _:
                        new_state = self.step(game_state, action,agent_id)
                        msg = (agent_id, (new_state, GameStatus.OK))
                # new_state = self.step(state, action, agent_id)
                self.logger.debug(f"Sending to{agent_id}: {msg}")
                await self._response_queue.put(msg)
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            self.logger.info(f"\t{self.world_name} Terminating by CancelledError")
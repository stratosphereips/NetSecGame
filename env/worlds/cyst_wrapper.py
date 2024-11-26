# Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz

import sys
import os
import asyncio

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from game_components import GameState, Action, ActionType, GameStatus
from worlds.aidojo_world import AIDojoWorld

class CYSTWrapper(AIDojoWorld):
    """
    Class for connection CYST with the coordinator of AI Dojo
    """
    def __init__(self, task_config_file, action_queue, response_queue, cyst_agent_ids:dict ,world_name="CYST-wrapper") -> None:
        super().__init__(task_config_file, action_queue, response_queue, world_name)
        self.logger.info("Initializing CYST wrapper environment")
        self._id_to_cystid = {}
        self._cystid_to_id  = {}
        self._known_agents = {}
        self._availabe_cyst_agents = cyst_agent_ids



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
    
    def map_to_cyst(self, agent_id, agent_role):
        try:
            cyst_id = self._availabe_cyst_agents[agent_role].pop()
        except KeyError:
            cyst_id = None
        return cyst_id


    async def handle_incoming_action(self)->None:
        try:
            self.logger.info(f"\tStaring {self.world_name} task.")
            while True:
                agent_id, action, game_state = await self._action_queue.get()
                self.logger.debug(f"Received from{agent_id}: {action}, {game_state}.")
                match action.type:
                    case ActionType.JoinGame:
                        agent_role = ...
                        cyst_id = self.map_to_cyst(agent_id, agent_role)
                        if cyst_id:
                            self._cystid_to_id[cyst_id] = agent_id
                            self._id_to_cystid[agent_id] = cyst_id
                            self._known_agents[agent_id] = agent_role
                            msg = (agent_id, (GameState(), GameStatus.CREATED))
                        else:
                            msg = (agent_id, (GameState(), GameStatus.FORBIDDEN))
                    case ActionType.QuitGame:
                        try:
                            agent_role = self._known_agents[agent_id]
                            cyst_id = self._id_to_cystid[agent_id]
                            # remove agent's IDs
                            self._known_agents.pop(agent_id)
                            self._id_to_cystid.pop(agent_id)
                            self._cystid_to_id.pop(cyst_id)
                            # make cyst_agent avaiable ag
                            self._availabe_cyst_agents[agent_role].add(cyst_id)

                        except KeyError:
                            msg = (agent_id, (GameState(),GameStatus.BAD_REQUEST))
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


if __name__ == "__main__":
    cyst_wrapper = CYSTWrapper("env/netsecenv_conf.yaml")
   
# Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz

import sys
import os
import asyncio

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from game_components import GameState, Action, ActionType, GameStatus
from worlds.aidojo_world import AIDojoWorld
from cyst.api.environment.environment import Environment
from cyst.api.environment.platform_specification import PlatformSpecification, PlatformType
from utils.utils import get_starting_position_from_cyst_config

class CYSTWrapper(AIDojoWorld):
    """
    Class for connection CYST with the coordinator of AI Dojo
    """
    def __init__(self, task_config_file, action_queue, response_queue, cyst_objects, world_name="CYST-wrapper") -> None:
        super().__init__(task_config_file, action_queue, response_queue, world_name,)
        self.logger.info("Initializing CYST wrapper environment")
        self._id_to_cystid = {}
        self._cystid_to_id  = {}
        self._known_agent_roles = {}
        self._availabe_cyst_agents = {}
        self._last_state_per_agent = {}
        self._last_action_per_agent = {}
        self._last_msg_per_agent = {}
        self._starting_positions = get_starting_position_from_cyst_config(cyst_objects)



    async def step(self, current_state:GameState, action:Action, agent_id:tuple)-> GameState:
        """
        Executes given action in a current state of the environment and produces new GameState.
        """
        self._last_state_per_agent[agent_id] = current_state
        self._last_action_per_agent[agent_id] = action
        cyst_msg = self.action_to_cyst_message(action)
        cyst_rsp = self._call_cyst(cyst_msg)
        new_state = self.cyst_response_to_game_state(cyst_rsp)
        msg = (agent_id, (new_state, GameStatus.OK))
        self.logger.debug(f"Sending to{agent_id}: {msg}")
        await self._response_queue.put(msg)


    def create_state_from_view(self, view:dict, add_neighboring_nets:bool=True)->GameState:
        """
        Produces a GameState based on the view of the world.
        """
        # TODO: Send reset signal to cyst

    
    def reset()->None:
        """
        Resets the world to its initial state.
        """
        raise NotImplementedError

    def update_goal_descriptions(self, goal_description:str)->str:
       """
       Takes the existing goal description (text) and updates it with respect to the world.
       """
       return goal_description
    
    def update_goal_dict(self, goal_dict:dict)->dict:
        """
        Takes the existing goal dict and updates it with respect to the world.
        """
        return goal_dict
    
    def map_to_cyst(self, agent_id, agent_role):
        try:
            cyst_id = self._availabe_cyst_agents[agent_role].pop()
        except KeyError:
            cyst_id = None
        return cyst_id
    
    def action_to_cyst_message(self, action:Action)->dict:
        raise NotImplementedError
    
    def cyst_response_to_game_state(self, str)->GameState:
        raise NotImplementedError

    def _call_cyst(self, msg)->dict:
        # TODO: 
        return {}
        
    async def _process_join_game(self, agent_id, join_action)->None:
        self.logger.debug(f"Processing {str(join_action)} from {agent_id}")
        agent_role = "Attacker"
        cyst_id = self.map_to_cyst(agent_id, agent_role)
        if cyst_id:
            self._cystid_to_id[cyst_id] = agent_id
            self._id_to_cystid[agent_id] = cyst_id
            self._known_agent_roles[agent_id] = agent_role
            msg = (agent_id, (GameState(), GameStatus.CREATED))
        else:
            msg = (agent_id, (GameState(), GameStatus.FORBIDDEN))
        self.logger.debug(f"Sending to{agent_id}: {msg}")
        await self._response_queue.put(msg)

    async def _process_quit_game(self, agent_id, quit_action)->None:
        try:
            agent_role = self._known_agent_roles[agent_id]
            cyst_id = self._id_to_cystid[agent_id]
            # remove agent's IDs
            self._known_agent_roles.pop(agent_id)
            self._id_to_cystid.pop(agent_id)
            self._cystid_to_id.pop(cyst_id)
            # make cyst_agent avaiable ag
            self._availabe_cyst_agents[agent_role].add(cyst_id)
        except KeyError:
            msg = (agent_id, (GameState(),GameStatus.BAD_REQUEST))
        msg = (agent_id, (GameState(),GameStatus.OK))
        self.logger.debug(f"Sending to{agent_id}: {msg}")
        await self._response_queue.put(msg)

    async def _process_reset(self, agent_id, game_state)->None:
        if agent_id == "world": #reset the world
            self.reset()
        else:
            msg = (agent_id, (self.create_state_from_view(game_state), GameStatus.RESET_DONE))
            self.logger.debug(f"Sending to{agent_id}: {msg}")
            await self._response_queue.put(msg)

    async def handle_incoming_action(self)->None:
        try:
            self.logger.info(f"\tStaring {self.world_name} task.")
            while True:
                agent_id, action, game_state = await self._action_queue.get()
                self.logger.debug(f"Received from{agent_id}: {action},{action.type}, {game_state}.")
                match action.type:
                    case ActionType.JoinGame:
                        self.logger.debug("going to the join game action")
                        await self._process_join_game(agent_id, action)
                    case ActionType.QuitGame:
                        await self._process_quit_game(agent_id, action)
                    case ActionType.ResetGame:
                       await self._process_reset(agent_id, game_state)
                    case _:
                        await self.step(game_state, action, agent_id)
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            self.logger.info(f"\t{self.world_name} Terminating by CancelledError")


if __name__ == "__main__":
    req_q = asyncio.Queue()
    req_q.put_nowait(("test_agent", Action(action_type=ActionType.JoinGame, params={}), {}))
    res_q = asyncio.Queue()

    cyst_wrapper = CYSTWrapper("env/netsecenv_conf.yaml", req_q, response_queue=res_q)
    asyncio.run(cyst_wrapper.handle_incoming_action())
   
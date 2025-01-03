# Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz

import sys
import os
import asyncio
import requests
import json
import copy
import ast
import logging
import argparse
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from game_components import GameState, Action, ActionType, GameStatus, IP
from coordinator_v3 import GameCoordinator
from cyst.api.environment.environment import Environment
from cyst.api.environment.platform_specification import PlatformSpecification, PlatformType

from utils.utils import get_starting_position_from_cyst_config, get_logging_level

class CYSTCoordinator(GameCoordinator):

    def __init__(self, game_host, game_port, service_host, service_port, world_type, allowed_roles=["Attacker", "Defender", "Benign"]):
        super().__init__(game_host, game_port, service_host, service_port, world_type, allowed_roles)
        self._id_to_cystid = {}
        self._cystid_to_id  = {}
        self._known_agent_roles = {}
        self._last_state_per_agent = {}
        self._last_action_per_agent = {}
        self._last_msg_per_agent = {}
        self._starting_positions = None
        self._availabe_cyst_agents = None

    def _map_to_cyst(self, agent_id, agent_role):
        try:
            cyst_id = self._availabe_cyst_agents[agent_role].pop()
        except KeyError:
            cyst_id = None
        return cyst_id
    
    async def register_agent(self, agent_id, agent_role, agent_initial_view)->GameState:
        self.logger.debug(f"Registering agent {agent_id} in the world.")
        agent_role = "Attacker"
        if not self._starting_positions:
            self._starting_positions = get_starting_position_from_cyst_config(self._cyst_objects)
            self._availabe_cyst_agents = {"Attacker":set([k for k in self._starting_positions.keys()])}
        async with self._agents_lock:
            cyst_id = self._map_to_cyst(agent_id, agent_role)
            if cyst_id:
                self._cystid_to_id[cyst_id] = agent_id
                self._id_to_cystid[agent_id] = cyst_id
                self._known_agent_roles[agent_id] = agent_role
                kh = self._starting_positions[cyst_id]["known_hosts"]
                kn = self._starting_positions[cyst_id]["known_networks"]
                return GameState(controlled_hosts=kh, known_hosts=kh, known_networks=kn)
            else:
                return None
    
    async def remove_agent(self, agent_id, agent_state)->bool:
        print(f"Removing agent {agent_id} from the CYST World")
        async with self._agents_lock:
            try:
                agent_role = self._known_agent_roles[agent_id]
                cyst_id = self._id_to_cystid[agent_id]
                # remove agent's IDs
                self._id_to_cystid.pop(agent_id)
                self._cystid_to_id.pop(cyst_id)
                # make cyst_agent avaiable again
                self._availabe_cyst_agents[agent_role].add(cyst_id)
                return True
            except KeyError:
                self.logger.error(f"Unknown agent ID: {agent_id}!")
                return False
        
    async def step(self, agent_addr, agent_state):
        return super().step(agent_addr, agent_state)
    
    async def reset_agent(self, agent_id)->GameState:
        cyst_id = self._id_to_cystid[agent_id]
        kh = self._starting_positions[cyst_id]["known_hosts"]
        kn = self._starting_positions[cyst_id]["known_networks"]
        return GameState(controlled_hosts=kh, known_hosts=kh, known_networks=kn)

    async def reset(self)->bool:
        return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CYST-NetSecGame Coordinator Server Author: Ondrej Lukas ondrej.lukas@aic.fel.cvut.cz",
        usage="%(prog)s [options]",
    )
  
    parser.add_argument(
        "-l",
        "--debug_level",
        help="Define the debug level for the logs. DEBUG, INFO, WARNING, ERROR, CRITICAL",
        action="store",
        required=False,
        type=str,
        default="DEBUG",
    )
    
    parser.add_argument(
        "-w",
        "--world_type",
        help="Define the world which is used as backed. Default NSE",
        action="store",
        required=False,
        type=str,
        default="cyst",
    )
    
    parser.add_argument(
        "-gh",
        "--game_host",
        help="host where to run the game server",
        action="store",
        required=False,
        type=str,
        default="127.0.0.1",
    )
    
    parser.add_argument(
        "-gp",
        "--game_port",
        help="Port where to run the game server",
        action="store",
        required=False,
        type=int,
        default="9000",
    )
    
    parser.add_argument(
        "-sh",
        "--service_host",
        help="Host where to run the config server",
        action="store",
        required=False,
        type=str,
        default="127.0.0.1",
    )
    
    parser.add_argument(
        "-sp",
        "--service_port",
        help="Port where to listen for cyst config",
        action="store",
        required=False,
        type=int,
        default="9009",
    )


    args = parser.parse_args()
    print(args)
    # Set the logging
    log_filename = Path("CYST_coordinator.log")
    if not log_filename.parent.exists():
        os.makedirs(log_filename.parent)

    # Convert the logging level in the args to the level to use
    pass_level = get_logging_level(args.debug_level)

    logging.basicConfig(
        filename=log_filename,
        filemode="w",
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=pass_level,
    )
  
    game_server = CYSTCoordinator(args.game_host, args.game_port, args.service_host , args.service_port, args.world_type)
    # Run it!
    game_server.run()
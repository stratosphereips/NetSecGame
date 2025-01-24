# Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz

import sys
import os
import requests
import json
import copy
import ast
import logging
import argparse
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from env.game_components import GameState, Action, ActionType,  IP, Service
from coordinator_v3 import GameCoordinator

from utils.utils import get_starting_position_from_cyst_config, get_logging_level

class CYSTCoordinator(GameCoordinator):

    def __init__(self, game_host:str, game_port:int, service_host:str, service_port:int, allowed_roles=["Attacker", "Defender", "Benign"]):
        super().__init__(game_host, game_port, service_host, service_port, allowed_roles)
        self._id_to_cystid = {}
        self._cystid_to_id  = {}
        self._known_agent_roles = {}
        self._last_state_per_agent = {}
        self._last_action_per_agent = {}
        self._last_msg_per_agent = {}
        self._starting_positions = None
        self._availabe_cyst_agents = None

    def get_cyst_id(self, agent_role:str):
        """
        Returns ID of the CYST agent based on the agent's role.
        """
        try:
            cyst_id = self._availabe_cyst_agents[agent_role].pop()
        except KeyError:
            cyst_id = None
        return cyst_id
    
    async def register_agent(self, agent_id:tuple, agent_role:str, agent_initial_view:dict)->GameState:
        self.logger.debug(f"Registering agent {agent_id} in the world.")
        agent_role = "Attacker"
        if not self._starting_positions:
            self._starting_positions = get_starting_position_from_cyst_config(self._cyst_objects)
            self._availabe_cyst_agents = {"Attacker":set([k for k in self._starting_positions.keys()])}
        async with self._agents_lock:
            cyst_id = self.get_cyst_id(agent_role)
            if cyst_id:
                self._cystid_to_id[cyst_id] = agent_id
                self._id_to_cystid[agent_id] = cyst_id
                self._known_agent_roles[agent_id] = agent_role
                kh = self._starting_positions[cyst_id]["known_hosts"]
                kn = self._starting_positions[cyst_id]["known_networks"]
                return GameState(controlled_hosts=kh, known_hosts=kh, known_networks=kn)
            else:
                return None
    
    async def remove_agent(self, agent_id, agent_state:GameState)->bool:
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
        
    async def step(self, agent_id:tuple, agent_state:GameState, action:Action)->GameState:
        self.logger.info(f"Processing {action} from {agent_id}({self._id_to_cystid[agent_id]})")
        next_state = None
        match action.type:
            case ActionType.ScanNetwork:
                next_state = await self._execute_scan_network_action(agent_id, agent_state, action)
            case ActionType.FindServices:   
                next_state = await self._execute_find_services_action(agent_id, agent_state, action)
            case ActionType.FindData:
                next_state = await self._execute_find_data_action(agent_id, agent_state, action)
            case ActionType.ExploitService:
                next_state = await self._execute_exploit_service_action(agent_id, agent_state, action)
            case ActionType.ExfiltrateData:
                next_state = await self._execute_exfiltrate_data_action(agent_id, agent_state, action)
            case ActionType.BlockIP:
                next_state = await self._execute_block_ip_action(agent_id, agent_state, action)
            case _:
                raise ValueError(f"Unknown Action type or other error: '{action.type}'")
        return next_state
    
    async def _cyst_request(self, cyst_id:str, msg:dict)->tuple:
        url = f"http://localhost:8282/execute/{cyst_id}/" # Replace with your server's URL
        data = msg        # The JSON data you want to send
        self.logger.info(f"Sedning request {msg} to {url}")
        try:
            # Send the POST request with JSON data
            response = requests.post(url, json=data)

            # Print the response from the server
            self.logger.debug(f'Status code:{response.status_code}')
            self.logger.debug(f'Response body:{response.text}')
            return int(response.status_code), json.loads(response.text)
        except requests.exceptions.RequestException as e:
            print(f'An error occurred: {e}')

    async def _execute_scan_network_action(self, agent_id:tuple, agent_state: GameState, action:Action)->GameState:
        action_dict = {
            "action":"dojo:scan_network",
            "params":
                {
                    "dst_ip":str(action.parameters["source_host"]),
                    "dst_service":"",
                    "to_network":str(action.parameters["target_network"])
                }
        }
        cyst_rsp_status, cyst_rsp_data = await self._cyst_request(self._id_to_cystid[agent_id], action_dict)
        extended_kh = copy.deepcopy(agent_state.known_hosts)
        extended_kn = copy.deepcopy(agent_state.known_networks)
        extended_ch = copy.deepcopy(agent_state.controlled_hosts)
        extended_ks = copy.deepcopy(agent_state.known_services)
        extended_kd = copy.deepcopy(agent_state.known_data)
        extended_kb = copy.deepcopy(agent_state.known_blocks)
        
        if cyst_rsp_status == 200:
            self.logger.debug("Valid response from CYST")
            data = ast.literal_eval(cyst_rsp_data["result"][1]["content"])
            for ip_str in data:
                ip = IP(ip_str)
                self.logger.debug(f"Adding {ip} to known_hosts")
                extended_kh.add(ip)
            return GameState(extended_ch, extended_kh, extended_ks, extended_kd, extended_kn, extended_kb)
    
    async def _execute_find_services_action(self, agent_id:tuple, agent_state: GameState, action:Action)->GameState:
        action_dict = {
            "action":"dojo:find_services",
            "params":
                {
                    "dst_ip":str(action.parameters["target_host"]),
                    "dst_service":""
                }
        }
        cyst_rsp_status, cyst_rsp_data = await self._cyst_request(self._id_to_cystid[agent_id], action_dict)
        extended_kh = copy.deepcopy(agent_state.known_hosts)
        extended_kn = copy.deepcopy(agent_state.known_networks)
        extended_ch = copy.deepcopy(agent_state.controlled_hosts)
        extended_ks = copy.deepcopy(agent_state.known_services)
        extended_kd = copy.deepcopy(agent_state.known_data)
        extended_kb = copy.deepcopy(agent_state.known_blocks)
        
        if cyst_rsp_status == 200:
            self.logger.debug("Valid response from CYST")
            data = ast.literal_eval(cyst_rsp_data["result"][1]["content"])
            self.logger.warning(data)
            for item in data:
                ip = IP(item["ip"])
                # Add IP in case it was discovered by the scan
                extended_kh.add(ip)
                if len(item["services"]) > 0:
                    if ip not in extended_ks.keys():
                        extended_ks[ip] = set()
                for service_dict in item["services"]:
                    service = Service.from_dict(service_dict)
                    extended_ks[ip].add(service)
            return GameState(extended_ch, extended_kh, extended_ks, extended_kd, extended_kn, extended_kb)
    
    async def _execute_find_data_action(self, agent_id:tuple, agent_state: GameState, action:Action)->GameState:
        raise NotImplementedError
    
    async def _execute_exploit_service_action(self, agent_id:tuple, agent_state: GameState, action:Action)->GameState:
        raise NotImplementedError
    
    async def _execute_exfiltrate_data_action(self, agent_id:tuple, agent_state: GameState, action:Action)->GameState:
        raise NotImplementedError

    async def _execute_block_ip_action(self, agent_id:tuple, agent_state: GameState, action:Action)->GameState:
        raise NotImplementedError

    async def reset_agent(self, agent_id:tuple, agent_role:str, agent_initial_view:dict)->GameState:
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
  
    game_server = CYSTCoordinator(args.game_host, args.game_port, args.service_host , args.service_port)
    # Run it!
    game_server.run()
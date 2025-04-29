# Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz

import os
import requests
import json
import copy
import ast
import logging
import argparse
from pathlib import Path
from AIDojoCoordinator.game_components import GameState, Action, ActionType,  IP, Service, Data
from AIDojoCoordinator.coordinator import GameCoordinator
from cyst.api.environment.environment import Environment

from AIDojoCoordinator.utils.utils import get_starting_position_from_cyst_config, get_logging_level, get_starting_position_from_cyst_config_dicts, ConfigParser, get_file_hash

class CYSTCoordinator(GameCoordinator):

    def __init__(self, game_host:str, game_port:int, service_host:str, service_port:int, task_config_file, cyst_config_file, allowed_roles=["Attacker", "Defender", "Benign"]):
        super().__init__(game_host, game_port, service_host, service_port, allowed_roles)
        self._id_to_cystid = {}
        self._cystid_to_id  = {}
        self._known_agent_roles = {}
        self._last_state_per_agent = {}
        self._last_action_per_agent = {}
        self._last_msg_per_agent = {}
        self._starting_positions = None
        self._availabe_cyst_agents = None
        self._sessions_per_agent = {}
        self._authorizations_per_agent = {}
        self._task_config_file = task_config_file
        self._cyst_config_file = cyst_config_file

        self._exploit_map = {"ssh":"exploit_1", "python3":"phishing_exploit", "vsftpd":"exploit_0"}

    def get_cyst_id(self, agent_role:str):
        """
        Returns ID of the CYST agent based on the agent's role.
        """
        try:
            cyst_id = self._availabe_cyst_agents[agent_role].pop()
        except KeyError:
            cyst_id = None
        return cyst_id
    
    def _load_initialization_objects(self):
        """
        Load the initialization objects from the CYST config file and the task config file.
        The CYST config file is used to create the CYST environment and the task config file is used to create the task environment.
        This method overrides the _load_initialization_objects method from the GameCoordinator class.
        """
        self.logger.info(f"Loading CYST config file: {self._cyst_config_file}")
        try:
            # load the CYST config file
            with open(self._cyst_config_file, "r") as f:
                self.logger.debug("Loading JSON CYST config file")
                cyst_objects_str = f.read()
                self.logger.debug("Create CYST environment")
                env = Environment.create()
                self.logger.debug("Loading cyst obejects")
                self._cyst_objects = env.configuration.general.load_configuration(cyst_objects_str)
        except FileNotFoundError:
            self.logger.error(f"CYST config file not found: {self._task_config_file}")
            raise
        except Exception as e:
            self.logger.error(f"Error loading CYST config file: {e}")
            raise
        # load task config file
        self.logger.info(f"Loading task config file: {self._task_config_file}")
        self.task_config = ConfigParser(self._task_config_file)
        self._CONFIG_FILE_HASH = get_file_hash(self._task_config_file)
    
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
                # TODO FIX LATER
                # add differentiation for other types than attacker
                # discover the session id from the cyst config
                self._sessions_per_agent[agent_id] = {}
                self._authorizations_per_agent[agent_id] = {}
                for h in kh:
                    self._sessions_per_agent[agent_id][h] = set({"phishing_session"})
                return GameState(controlled_hosts=kh, known_hosts=kh, known_networks=kn)
            else:
                return None
    
    async def remove_agent(self, agent_id, agent_state:GameState)->bool:
        self.logger.debug(f"Removing agent {agent_id} from the CYST World")
        async with self._agents_lock:
            try:
                agent_role = self._known_agent_roles[agent_id]
                cyst_id = self._id_to_cystid[agent_id]
                # remove agent's IDs
                self._id_to_cystid.pop(agent_id)
                self._cystid_to_id.pop(cyst_id)
                # make cyst_agent avaiable again
                self._availabe_cyst_agents[agent_role].add(cyst_id)
                self.logger.debug(f"\tRemoval successful, was cyst_id:{cyst_id}")
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
        extended_kh = copy.deepcopy(agent_state.known_hosts)
        extended_kn = copy.deepcopy(agent_state.known_networks)
        extended_ch = copy.deepcopy(agent_state.controlled_hosts)
        extended_ks = copy.deepcopy(agent_state.known_services)
        extended_kd = copy.deepcopy(agent_state.known_data)
        extended_kb = copy.deepcopy(agent_state.known_blocks)
        if action.parameters["source_host"] in self._sessions_per_agent[agent_id].keys():
            session_id = list(self._sessions_per_agent[agent_id][action.parameters["source_host"]])[0]
            # Agent has session in the source host and can do actions
            action_dict = {
                "action":"dojo:scan_network",
                "params":
                    {
                        "session":session_id,
                        "to_network":str(action.parameters["target_network"]),
                    }
            }
            response_status, cyst_rsp_data = await self._cyst_request(self._id_to_cystid[agent_id], action_dict)
            if response_status == 200:
                cyst_status, cyst_rsp_content = cyst_rsp_data["result"][0],ast.literal_eval(cyst_rsp_data["result"][1]["content"])
                self.logger.debug(f"CYST status: {cyst_status}")
                for ip_str in cyst_rsp_content:
                    ip = IP(ip_str)
                    self.logger.debug(f"Adding {ip} to known_hosts")
                    extended_kh.add(ip)
        return GameState(extended_ch, extended_kh, extended_ks, extended_kd, extended_kn, extended_kb)
    
    async def _execute_find_services_action(self, agent_id:tuple, agent_state: GameState, action:Action)->GameState:
        extended_kh = copy.deepcopy(agent_state.known_hosts)
        extended_kn = copy.deepcopy(agent_state.known_networks)
        extended_ch = copy.deepcopy(agent_state.controlled_hosts)
        extended_ks = copy.deepcopy(agent_state.known_services)
        extended_kd = copy.deepcopy(agent_state.known_data)
        extended_kb = copy.deepcopy(agent_state.known_blocks)
        if action.parameters["source_host"] in self._sessions_per_agent[agent_id].keys():
            session_id = list(self._sessions_per_agent[agent_id][action.parameters["source_host"]])[0]
            # Agent has session in the source host and can do actions
            action_dict = {
                "action":"dojo:find_services",
                "params":
                    {
                        "dst_ip":str(action.parameters["target_host"]),
                        "session":session_id
                    }
            }
            response_status, cyst_rsp_data = await self._cyst_request(self._id_to_cystid[agent_id], action_dict)
            if response_status == 200:
                cyst_status, cyst_rsp_content = cyst_rsp_data["result"][0],ast.literal_eval(cyst_rsp_data["result"][1]["content"])
                self.logger.debug(f"CYST status: {cyst_status}")
                for item in cyst_rsp_content:
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
        if action.parameters["source_host"] == action.parameters["target_host"]:
            # search is done by the existing session in the target host
            return await self._execute_find_data_with_session(agent_id, agent_state, action)
        else:
            # search is done by the existing authorization in the target host
            extended_kh = copy.deepcopy(agent_state.known_hosts)
            extended_kn = copy.deepcopy(agent_state.known_networks)
            extended_ch = copy.deepcopy(agent_state.controlled_hosts)
            extended_ks = copy.deepcopy(agent_state.known_services)
            extended_kd = copy.deepcopy(agent_state.known_data)
            extended_kb = copy.deepcopy(agent_state.known_blocks)
            # Agent has session in the source host and can do actions
            if action.parameters["source_host"] in self._sessions_per_agent[agent_id].keys():
                # Agent has authorization in the target host
                if action.parameters["target_host"] in self._authorizations_per_agent[agent_id]:
                    authorization = self._authorizations_per_agent[agent_id].get(action.parameters["target_host"], None)
                    session_id = list(self._sessions_per_agent[agent_id][action.parameters["source_host"]])[0]
                    if authorization:
                        authorization = authorization[0]
                        # Agent has authorization to access the target host
                        action_dict = {
                            "action": "dojo:find_data",
                            "params":
                                {
                                    "dst_ip":str(action.parameters["target_host"]),
                                    "session":session_id,
                                    "dst_service": authorization["service"],
                                    "auth": authorization["id"],
                                    "directory": "/"
                                }
                        }
                        cyst_rsp_status, cyst_rsp_data = await self._cyst_request(self._id_to_cystid[agent_id], action_dict)          
                        if cyst_rsp_status == 200:
                            self.logger.debug("Valid response from CYST")
                            data = ast.literal_eval(cyst_rsp_data["result"][1]["content"])
                            for item in data:
                                if action.parameters["target_host"] not in extended_kd:
                                    extended_kd[action.parameters["target_host"]] = set()
                                # register the new host (if not already known)
                                extended_kh.add(action.parameters["target_host"])
                                # register new control over the host
                                extended_ch.add(action.parameters["target_host"])
                                # register the new service (if not already known)
                                extended_kd[action.parameters["target_host"]].add(Data("unknown", item))
                    else:
                        self.logger.debug("Agent does not have authorization to access the target host")
            return GameState(extended_ch, extended_kh, extended_ks, extended_kd, extended_kn, extended_kb)

    async def _execute_find_data_with_session(self, agent_id:tuple, agent_state: GameState, action:Action)->GameState:
        """
        Implementation of FindData action when source and target hosts are the same.
        """
        self.logger.debug(f"Executing FindData locally for {agent_id}")
        extended_kh = copy.deepcopy(agent_state.known_hosts)
        extended_kn = copy.deepcopy(agent_state.known_networks)
        extended_ch = copy.deepcopy(agent_state.controlled_hosts)
        extended_ks = copy.deepcopy(agent_state.known_services)
        extended_kd = copy.deepcopy(agent_state.known_data)
        extended_kb = copy.deepcopy(agent_state.known_blocks)
        # Only possible if there is an active session in the source host (= target host)
        if action.parameters["source_host"] == action.parameters["target_host"]:
            if action.parameters["source_host"] in self._sessions_per_agent[agent_id].keys():
                self.logger.debug(f"Available session in {action.parameters["source_host"]}:{self._sessions_per_agent[agent_id][action.parameters["source_host"]]}")
                session_id = list(self._sessions_per_agent[agent_id][action.parameters["source_host"]])[0]              
                # Agent has authorization to access the target host
                action_dict = {
                    "action": "dojo:find_data",
                    "params":
                        {
                            "dst_ip":str(action.parameters["target_host"]),
                            "session":session_id,
                            "dst_service":"",
                            "auth": "",
                            "directory": "/"
                        }
                }
                
                cyst_rsp_status, cyst_rsp_data = await self._cyst_request(self._id_to_cystid[agent_id], action_dict)          
                if cyst_rsp_status == 200:
                    self.logger.debug("Valid response from CYST")
                    data = ast.literal_eval(cyst_rsp_data["result"][1]["content"])
                    for item in data:
                        if action.parameters["target_host"] not in extended_kd:
                            extended_kd[action.parameters["target_host"]] = set()
                        # register the new host (if not already known)
                        extended_kh.add(action.parameters["target_host"])
                        # register new control over the host
                        extended_ch.add(action.parameters["target_host"])
                        # register the new service (if not already known)
                        extended_kd[action.parameters["target_host"]].add(Data("unknown", item))
            else:
                self.logger.debug(f"Agent does not have a valid session to access the target host:{self._sessions_per_agent[agent_id]}")
        return GameState(extended_ch, extended_kh, extended_ks, extended_kd, extended_kn, extended_kb)
    
    async def _execute_exfiltrate_data_with_session(self, agent_id:tuple, agent_state: GameState, action:Action)->GameState:
        """
        Implementation of FindData action when source and target hosts are the same.
        """
        self.logger.debug(f"Executing FindData with session for {agent_id}")
        extended_kh = copy.deepcopy(agent_state.known_hosts)
        extended_kn = copy.deepcopy(agent_state.known_networks)
        extended_ch = copy.deepcopy(agent_state.controlled_hosts)
        extended_ks = copy.deepcopy(agent_state.known_services)
        extended_kd = copy.deepcopy(agent_state.known_data)
        extended_kb = copy.deepcopy(agent_state.known_blocks)
        # Only possible if there is an active session in the source host (= target host)
        if action.parameters["source_host"] == action.parameters["target_host"]:
            if action.parameters["source_host"] in self._sessions_per_agent[agent_id].keys():
                self.logger.debug(f"Available session in {action.parameters["source_host"]}:{self._sessions_per_agent[agent_id][action.parameters["source_host"]]}")
                session_id = list(self._sessions_per_agent[agent_id][action.parameters["source_host"]])[0]
                # Agent has authorization to access the target host
                action_dict = {
                    "action": "dojo:find_data",
                    "params":
                        {
                            "dst_ip":str(action.parameters["target_host"]),
                            "session":session_id,
                            "dst_service":"",
                            "auth": "",
                            "directory": "/"
                        }
                }

                action_dict = {
                    "action": "dojo:exfiltrate_data",
                    "params":
                        {
                            "dst_ip":str(action.parameters["source_host"]),
                            "session":self._sessions_per_agent[agent_id][action.parameters["target_host"]],
                            "dst_service":"ssh", # TODO
                            "auth": "authorization_0", # TODO
    	                    "path": action.parameters["data"].id
                        }
                }

                cyst_rsp_status, cyst_rsp_data = await self._cyst_request(self._id_to_cystid[agent_id], action_dict)          
                if cyst_rsp_status == 200:
                    self.logger.debug("Valid response from CYST")
                    data = ast.literal_eval(cyst_rsp_data["result"][1]["content"])
                    for item in data:
                        if action.parameters["target_host"] not in extended_kd:
                            extended_kd[action.parameters["target_host"]] = set()
                        # register the new host (if not already known)
                        extended_kh.add(action.parameters["target_host"])
                        # register new control over the host
                        extended_ch.add(action.parameters["target_host"])
                        # register the new service (if not already known)
                        extended_kd[action.parameters["target_host"]].add(Data("unknown", item))
            else:
                self.logger.debug(f"Agent does not have a valid session to access the target host:{self._sessions_per_agent[agent_id]}")
        return GameState(extended_ch, extended_kh, extended_ks, extended_kd, extended_kn, extended_kb)
    
    async def _execute_exploit_service_action(self, agent_id:tuple, agent_state: GameState, action:Action)->GameState:
        extended_kh = copy.deepcopy(agent_state.known_hosts)
        extended_kn = copy.deepcopy(agent_state.known_networks)
        extended_ch = copy.deepcopy(agent_state.controlled_hosts)
        extended_ks = copy.deepcopy(agent_state.known_services)
        extended_kd = copy.deepcopy(agent_state.known_data)
        extended_kb = copy.deepcopy(agent_state.known_blocks)
        if action.parameters["source_host"] in self._sessions_per_agent[agent_id].keys():
            session_id = list(self._sessions_per_agent[agent_id][action.parameters["source_host"]])[0]
            # Agent has session in the source host and can do actions
            if action.parameters["target_service"].name in self._exploit_map.keys():
                # There is existing exploit for the service
                action_dict = {
                    "action":"dojo:exploit_server",
                    "params":
                        {
                            "dst_ip":str(action.parameters["target_host"]),
                            "session":session_id,
                            "dst_service":action.parameters["target_service"].name,
                            "exploit":self._exploit_map[action.parameters["target_service"].name]
                        }
                }
                cyst_rsp_status, cyst_rsp_data = await self._cyst_request(self._id_to_cystid[agent_id], action_dict)          
                if cyst_rsp_status == 200:
                    self.logger.debug("Valid response from CYST")
                    data = cyst_rsp_data["result"][1]
                    # add new session and authorization
                    new_session_id = data.get("new_session_id", None)
                    if new_session_id:
                        if action.parameters["target_host"] not in self._sessions_per_agent[agent_id].keys():
                            self._sessions_per_agent[agent_id][action.parameters["target_host"]] = set()
                        # store the newnly accuired session
                        self._sessions_per_agent[agent_id][action.parameters["target_host"]].add(new_session_id)
                        self.logger.info(f"Adding new session for {agent_id} in {action.parameters['target_host']}: {new_session_id}")
                    new_auth_id = data.get("new_auth_id", None)
                    if new_auth_id:
                        creds = ast.literal_eval(data["content"])[0]
                        username = creds["username"]
                        password = creds["password"]
                        if action.parameters["target_host"] not in self._authorizations_per_agent[agent_id].keys():
                            self._authorizations_per_agent[agent_id][action.parameters["target_host"]] = []
                        new_auth = {"id":new_auth_id, "service":action.parameters["target_service"].name, "username":username, "password":password}
                        self._authorizations_per_agent[agent_id][action.parameters["target_host"]].append(new_auth)
                        self.logger.info(f"Adding new autorization for {agent_id} in {action.parameters['target_host']}: {new_auth}")
                        # register the new host (if not already known)
                        extended_kh.add(action.parameters["target_host"])
                        # register new control over the host
                        extended_ch.add(action.parameters["target_host"])
                        # register the new service (if not already known)
                        extended_ks[action.parameters["target_host"]].add(action.parameters["target_service"])
        return GameState(extended_ch, extended_kh, extended_ks, extended_kd, extended_kn, extended_kb)
    
    async def _execute_exfiltrate_data_action(self, agent_id:tuple, agent_state: GameState, action:Action)->GameState:
        """
        for now the exfiltration is done by the attacker from the source host to the target host (the attacker's host).
        In order to succeed, the attacker must have control over the target host (have session there) 
        and have authorization to access the source host (where the data is).

        In other words, the action brings the data from the source host to the target host.
        """
        extended_kh = copy.deepcopy(agent_state.known_hosts)
        extended_kn = copy.deepcopy(agent_state.known_networks)
        extended_ch = copy.deepcopy(agent_state.controlled_hosts)
        extended_ks = copy.deepcopy(agent_state.known_services)
        extended_kd = copy.deepcopy(agent_state.known_data)
        extended_kb = copy.deepcopy(agent_state.known_blocks)
        if action.parameters["source_host"] in self._sessions_per_agent[agent_id].keys():
            self.logger.debug("Agent has session in the source host")
            # Agent has session in the source host and can do actions
            session_id = list(self._sessions_per_agent[agent_id][action.parameters["source_host"]])[0]
            action_dict = {
                "action": "dojo:exfiltrate_data",
                "params":
                    {
                        "dst_ip":str(action.parameters["source_host"]),
                        "session":session_id,
                        "dst_service":"",  
                        "auth": "",
                        "path": action.parameters["data"].id
                    }
            }
            cyst_rsp_status, cyst_rsp_data = await self._cyst_request(self._id_to_cystid[agent_id], action_dict)          
            if cyst_rsp_status == 200:
                self.logger.debug("Valid response from CYST")
                data = cyst_rsp_data["result"][1]["content"]
                if len(data) > 0:
                    # there is some data transferred, add it to the known data in the target host
                    if action.parameters["target_host"] not in extended_kd:
                        extended_kd[action.parameters["target_host"]] = set()
                    extended_kd[action.parameters["target_host"]].add(action.parameters["data"])
            else:
                self.logger.debug("Agent does not have authorization to access the target host")
        # there is not valid session for the source_host,try authorizations
        elif action.parameters["source_host"] in self._authorizations_per_agent[agent_id].keys():
            self.logger.debug("Agent does not have session in the source host, using authorization")
            # Agent has authorization in the source host
            session_id = list(self._sessions_per_agent[agent_id][action.parameters["target_host"]])[0]
            authorization = self._authorizations_per_agent[agent_id][action.parameters["source_host"]]
            authorization = authorization[0]
            # Agent has authorization to access the target host
            action_dict = {
                "action": "dojo:exfiltrate_data",
                "params":
                    {
                        "dst_ip":str(action.parameters["source_host"]),
                        # Use the initial session
                        "session":session_id,
                        "dst_service": authorization["service"],
                        "auth": authorization["id"],
                        "path": action.parameters["data"].id
                    }
            }
            cyst_rsp_status, cyst_rsp_data = await self._cyst_request(self._id_to_cystid[agent_id], action_dict)          
            if cyst_rsp_status == 200:
                self.logger.debug("Valid response from CYST")
                data = cyst_rsp_data["result"][1]["content"]
                if len(data) > 0:
                    # there is some data transferred, add it to the known data in the target host
                    if action.parameters["target_host"] not in extended_kd:
                        extended_kd[action.parameters["target_host"]] = set()
                    extended_kd[action.parameters["target_host"]].add(action.parameters["data"])
        else:
            self.logger.debug("Agent does not have authorization to access the target")
        return GameState(extended_ch, extended_kh, extended_ks, extended_kd, extended_kn, extended_kb)

    async def _execute_block_ip_action(self, agent_id:tuple, agent_state: GameState, action:Action)->GameState:
        raise NotImplementedError

    async def reset_agent(self, agent_id:tuple, agent_role:str, agent_initial_view:dict)->GameState:
        cyst_id = self._id_to_cystid[agent_id]
        kh = self._starting_positions[cyst_id]["known_hosts"]
        kn = self._starting_positions[cyst_id]["known_networks"]
        return GameState(controlled_hosts=kh, known_hosts=kh, known_networks=kn)

    async def reset(self)->bool:
        return True

    async def report_episode_results(self)->bool:
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
        default="8000",
    )
    
    parser.add_argument(
        "-c",
        "--cyst_config",
        help="Path to the CYST config file",
        action="store",
        required=False,
        type=str,
        default="cyst_config.json",
    )

    parser.add_argument(
        "-t",
        "--task_config",
        help="File with the task configuration",
        action="store",
        required=True,
        type=str,
        default="netsecenv_conf_cyst_integration.yaml",
    )


    args = parser.parse_args()
    print(args)
    # Set the logging
    log_filename = Path("logs/CYST_coordinator.log")
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
  
    game_server = CYSTCoordinator(args.game_host, args.game_port, args.service_host , args.service_port, args.task_config, args.cyst_config)
    # Run it!
    game_server.run()
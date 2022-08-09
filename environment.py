import ipaddress
from multiprocessing import connection
from random import random
from tkinter.tix import Tree

from pytz import NonExistentTimeError
from game_components import *
import yaml
import itertools
from random import random

class Environment(object):
    def __init__(self, max_steps=0) -> None:
        self._nodes = {}
        self._connections = {}
        self._networks = {}
        self._ips = {}

        self._defender_placements = None
        self.current_state = None
        self._done = False
        self._step_counter = 0
        self._timeout = max_steps

    def place_defences(self, placements:list):
        assert self._defender_placements ==  None
        self._defender_placements = placements
    
    def read_topology(self, filename) -> None:
        """
        Method to process YAML file with congifuration from CYST and build a state space of the environment with possible transitions.
        """
        with open(filename, "r") as stream:
            try:
                data = yaml.safe_load(stream)
                for k,v in data.items():
                    if v['cls_type'] in ["NodeConfig", "RouterConfig"]: #new node or router in the network
                        self._nodes[v['id']] = v
                        self._connections[v['id']] = []
                        #add network information
                        for item in v["interfaces"]:
                            if item["cls_type"] == "InterfaceConfig":
                                if item["net"]["cls_type"] == "IPNetwork":
                                    if item["net"]["value"] not in self._networks.keys():
                                        self._networks[item["net"]["value"]] = []
                                self._networks[item["net"]["value"]].append((item["ip"]["value"], v['id']))
                                #add IP-> host name mapping
                                self._ips[item["ip"]["value"]] = v['id']  
                    elif v['cls_type'] in "ConnectionConfig": # TODO
                        self._connections[v["src_id"]].append(v["dst_id"])
                        self._connections[v["dst_id"]].append(v["src_id"])
            except yaml.YAMLError as e:
                print(e)
        self._attacker_start = "attacker_node"
    
    def get_all_states(self)->list:
        states = sum([list(map(list, itertools.combinations(self._nodes.keys(), i))) for i in range(1, len(self._nodes.keys()) + 1)], [])
        if self._attacker_start:
            #remove all states where the initial attacker state is not present
            states = [x for x in states if self._attacker_start in x]
        return states
    
    def get_valid_actions(self, state:GameState, transitions:dict):
        actions = []
        #scan network actions
        for network in state.known_networks:
            actions.append(Action(transitions["ScanNetwork"], network))
        #scan services
        for host in state.known_hosts-state.controlled_hosts:
            pass
    
    def get_services_from_host(self, host_ip):
        #check if IP is correct
        try:
            ipaddress.ip_address(host_ip)
            if host_ip in self._ips:
                host = self._ips[host_ip]
                services = {"passive":[], "active":[]}
                for s in self._nodes[host]["active_services"]:
                    services["active"].append(s["type"])
                for s in self._nodes[host]["passive_services"]:
                    if s["authentication_providers"][0]["ip"]["value"] == host_ip: #TODO DO this better!
                        services["passive"].append((s["type"], s["version"]))
                return {host: services}
            return None
        except ValueError:
            print("HostIP is invalid")
            return None
    
    def _get_networks_from_host(self, host_ip):
        try:
            host = self._ips[host_ip]
        except KeyError:
            print(f"Given host IP '{host_ip}' is unknown!")
        networks = set()
        for interface in self._nodes[host]["interfaces"]:
            if interface["cls_type"] == "InterfaceConfig" and interface["net"]["cls_type"] == "IPNetwork":
                networks.add(interface["net"]["value"])
        return networks
    
    def execute_action(self, current:GameState, action:Action)-> GameState:
        if action.transition.type == "ScanNetwork":
            extended_hosts = current.known_hosts + [host[0] for host in self._networks[action.parameters["target_network"]]]
            return GameState(current.controlled_hosts, extended_hosts, current.known_services, current.known_data, current.known_networks)
        elif action.transition.type == "FindServices":
            extended_services = current.known_services.update(self.get_services_from_host(action.parameters["target_host"]))
            return GameState(current.controlled_hosts, current.known_hosts, extended_services, current.known_data, current.known_networks)
        elif action.transition.type == "FindData":
            extended_data = current.known_data
            extended_data.update({action.parameters["target_host"]:self.get_data_in_host(action.parameters["target_host"])})
            return GameState(current.controlled_hosts, current.known_hosts, current.known_services, extended_data, current.known_networks)
        elif action.transition.type == "ExecuteCodeInService":
            extended_controlled_hosts = current.controlled_hosts + [action.parameters["target_host"]]
            extended_networks = set(current.known_networks) + self._get_networks_from_host(action.parameters["target_host"])
            return GameState(extended_controlled_hosts, current.known_hosts, current.known_services, current.known_data, list(extended_networks))
        elif action.transition.type == "ExfiltrateData":
            extended_data = current.known_data()
            extended_data.update({action.parameters["target_host"]:action.parameters["data"]})
            return GameState(current.controlled_hosts, current.known_hosts, current.known_services, extended_data, current.known_networks)
        else:
            raise ValueError(f"Unknown Action type: '{action.transition.type}'")
    
    def reset(self):
        raise NotImplementedError
    
    def step(self, action:Action)-> Observation:
        #check if action is valid
        if self.validate_action(self.current_state, action): #TODO
            self._step_counter +=1
            #Roll the dice on success
            successful = random() <= action.transition.default_success_p
            
            #Action is valid execute it
            if successful:
                next_state = self.execute_action(self.current_state, action)
                reward = action.transition.default_reward - action.transition.default_cost
            else: #unsuccessful - pay the cost but no reward, no change in game state
                next_state = self.current_state
                reward = - action.transition.default_cost
            
            is_terminal = env.is_goal(next_state)
            
            self._done = self._step_counter >= self._timeout or is_terminal

            return Observation(next_state, reward, is_terminal, self._done, {})
        else:
            raise ValueError(f"Invalid action {action}")


if __name__ == "__main__":
    env = Environment()
    env.read_topology("test.yaml")
    #print(env.get_services_from_host("192.168.0.2"))
    print(env._networks)
    print(env._ips)
    print(env._get_networks_from_host("192.168.0.1"))
    #for x in env.get_all_states():
    #    print(x)
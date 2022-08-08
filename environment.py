import ipaddress
from multiprocessing import connection
from random import random
from tkinter.tix import Tree

from pytz import NonExistentTimeError
from game_components import *
import yaml
import itertools
from random import random


class Player(object):
    def __init__(self, type:str) -> None:
        if type in "attacker":
            self.is_attacker=True
        elif type in "defender":
            self.is_defender=True
        
    def move(self,state:GameState):
        raise NotImplementedError


class Environment(object):
    def __init__(self) -> None:
        self._nodes = {}
        self._connections = {}
        self._networks = {}
        self._ips = {}
        
        self._defender = None
        self._attacker = None

        self._defener_placements = {}
        self.current_state = None

    def register_attacker(self, attacker:Player):
        self.attacker = attacker
    
    def register_defender(self, defender:Player):
        self.defender = defender

    def read_topology(self, filename) -> None:
        """
        Method to process YAML file with congifuration from CYST and build a state space of the environment with possible transitions.
        """
        nodes = {}
        connections = {}
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
    
    def execute_action(self, current:GameState, action:Action)-> GameState:
        if current.valid_action(action):
            if action.transition.type == "ScanNetwork":
                extended_hosts = current.known_hosts + [host[0] for host in self._networks[action.parameters["target_network"]]]
                return GameState(current.controlled_hosts, extended_hosts,current.known_services, current.known_data, current.known_networks)
            elif action.transition.type == "FindServices":
                extended_services = current.known_services.update(self.get_services_from_host(action.parameters["target_host"]))
                return GameState(current.controlled_hosts, current.known_hosts, extended_services, current.known_data, current.known_networks)
            elif action.transition.type == "FindData":
                raise NotImplementedError
            elif action.transition.type == "ExecuteCodeInService":
                raise NotImplementedError
            elif action.transition.type == "ExfiltrateData":
                raise NotImplementedError
        else:
            print("Error - invalid action!")
            return current

    def reset(self):
        raise NotImplementedError
    
    def step(self, action)-> Observation:
        
        raise NotImplementedError


if __name__ == "__main__":
    env = Environment()
    env.read_topology("test.yaml")
    print(env.get_services_from_host("192.168.0.21"))
    #for x in env.get_all_states():
    #    print(x)
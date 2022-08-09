import ipaddress
from random import random
from xml.sax.handler import property_dom_node

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
        self._current_state = None
        self._done = False
        self._src_file = None
    @property
    def current_state(self):
        return self._current_state

    def initialize(self, win_conditons:dict, defender_positions:dict, attacker_start_position:dict, max_steps=10)-> GameState:
        if self._src_file:
            self._win_conditions = win_conditons
            self._attacker_start = attacker_start_position
            self._timeout = max_steps
            #position defensive measure
            self._place_defences(defender_positions)
            return self.reset()
        else:
            print("Please load a topology file before initializing the environment!")
            return None
    
    def _create_starting_state(self):
        l = [self._get_networks_from_host(h) for h in self._attacker_start["controlled_hosts"]]
        return GameState(self._attacker_start["controlled_hosts"], self._attacker_start["known_hosts"],{},{},list(set().union(*l)))
    
    def _place_defences(self, placements:dict)->None:
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
        self._src_file = filename
    
    def get_all_states(self)->list:
        states = sum([list(map(list, itertools.combinations(self._nodes.keys(), i))) for i in range(1, len(self._nodes.keys()) + 1)], [])
        if self._attacker_start:
            #remove all states where the initial attacker state is not present
            states = [x for x in states if self._attacker_start in x]
        return states
    
    def get_valid_actions(self, state:GameState, transitions:dict)->list:
        actions = []
        #scan network actions
        for network in state.known_networks:
            actions.append(Action(transitions["ScanNetwork"], network))
        #scan services
        for host in state.known_hosts-state.controlled_hosts:
            pass
    
    def _get_services_from_host(self, host_ip)-> dict:
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
    
    def _get_networks_from_host(self, host_ip)->set:
        try:
            host = self._ips[host_ip]
        except KeyError:
            print(f"Given host IP '{host_ip}' is unknown!")
        networks = set()
        for interface in self._nodes[host]["interfaces"]:
            if interface["cls_type"] == "InterfaceConfig" and interface["net"]["cls_type"] == "IPNetwork":
                networks.add(interface["net"]["value"])
        return networks
    
    def _execute_action(self, current:GameState, action:Action)-> GameState:
        if action.transition.type == "ScanNetwork":
            extended_hosts = current.known_hosts + [host[0] for host in self._networks[action.parameters["target_network"]]]
            return GameState(current.controlled_hosts, extended_hosts, current.known_services, current.known_data, current.known_networks)
        elif action.transition.type == "FindServices":
            extended_services = current.known_services.update(self._get_services_from_host(action.parameters["target_host"]))
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
    
    def valid_action(self, state:GameState, action:Action)-> bool:
        if action.transition.type == "ScanNetwork":
            return action.parameters["target_network"] in self._networks
        elif action.transition.type == "FindServices":
            target = ipaddress.ip_address(action.parameters["target_host"])
            accessible = [target in ipaddress.ip_network(n) for n in state.known_networks]
            return action.parameters["target_host"] in self._ips and accessible.any()
        elif action.transition.type == "FindData":
            return action.parameters["target_host"] in state.controlled_hosts or action.parameters["target_host"] in state.known_hosts
        elif action.transition.type == "ExecuteCodeInService":
            return action.parameters["target_host"] in state.known_services and action.parameters["target_service"] in [x["name"] for x in state.known_services[action.parameters["target_host"]]]
        elif action.transition.type == "ExfiltrateData":
            if action.parameters["source_host"] in state.controlled_hosts or action.parameters["source_host"] in state.known_hosts:
                try:
                    data_accessible = action.parameters["data"] in state.known_data[action.parameters["source_host"]]
                    target = ipaddress.ip_address(action.parameters["target_host"])
                    target_acessible = [target in ipaddress.ip_network(n) for n in state.known_networks].any()
                    return data_accessible and target_acessible
                except KeyError as e:
                    print(e)
                    return False
            else:
                return False #for now we don't support this option TODO
        else:
            print(f"Unknown transition type '{action.transition.type}'")
            return False
    
    def is_goal(self, state:GameState)->bool:
        #check if all netoworks are known
        networks = set(self._win_conditions["known_networks"]).issubset(set(state.known_networks))
        known_hosts = set(self._win_conditions["known_hosts"]).issubset(set(state.known_hosts))
        controlled_hosts = set(self._win_conditions["controlled_hosts"]).issubset(set(state.controlled_hosts))
        try:
            services = [(k,v) for k,v in self._win_conditions["known_services"].items() if state.known_services[k]!=v]
            services = len(services) == 0
        except KeyError:
            services = False
        try:
            data = [(k,v) for k,v in self._win_conditions["known_data"].items() if state.known_data[k]!=v]
            data = len(data) == 0
        except KeyError:
            data = False
        return networks and known_hosts and controlled_hosts and services and data
    
    def _is_detected(state, action:Action)->bool:
        return False #TODO
        raise NotImplementedError
    
    def reset(self)->GameState:
        self._current_state = self._create_starting_state()
        self._step_counter = 0
        return self.current_state
    
    def step(self, action:Action)-> Observation:
        if not self._done:
            #check if action is valid
            if self.validate_action(self._current_state, action):
                self._step_counter +=1
                #Roll the dice on success
                successful = random() <= action.transition.default_success_p         
                #Action is valid execute it
                if successful:
                    next_state = self._execute_action(self._current_state, action)
                    reward = action.transition.default_reward - action.transition.default_cost
                else: #unsuccessful - pay the cost but no reward, no change in game state
                    next_state = self._current_state
                    reward = - action.transition.default_cost
                
                is_terminal = self.is_goal(next_state) or self._is_detected(self._current_state, action)
                
                self._done = self._step_counter >= self._timeout or is_terminal
                #move environment to the next stae
                self._current_state = next_state
                return Observation(next_state, reward, is_terminal, self._done, {})
            else:
                raise ValueError(f"Invalid action {action}")
        else:
            print("Interaction over! No more steps can be made in the environment")


if __name__ == "__main__":
    #create environment
    env = Environment(max_steps=10)
    #read topology from the dummy file
    env.read_topology("test.yaml")
    #goal condition
    goal = {"known_networks":[], "known_hosts":[], "controlled_hosts":["192.168.0.4"], "known_services":{}, "known_data":{}}
    attacker_start = {"known_networks":[], "known_hosts":["192.168.0.5"], "controlled_hosts":["192.168.0.5"], "known_services":{}, "known_data":{}}
    #initialize the game
    env.initialize(goal,{},attacker_start)
    print("Current state", env.current_state, env.is_goal(env.current_state))
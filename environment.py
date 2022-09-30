
import netaddr
from random import random
from game_components import *
import yaml
from random import random, choice
import copy
import sys
sys.path.append("..\scenarios\scenario_1")
from cyst.api.configuration import *
from scenario_configuration import * 

import numpy as np
from frozendict import frozendict
from basic_agent import BasicQLearningAgent

class Environment(object):
    def __init__(self, verbosity=0) -> None:
        self._nodes = {}
        self._connections = {}
        self._ips = {}
        self._exploits = {}
        self._fw_rules = []

        self._defender_placements = None
        self._current_state = None
        self._done = False
        self._src_file = None
        self.verbosity = verbosity
        self._detected = False
    
    @property
    def current_state(self) -> GameState:
        return self._current_state

    @property
    def timestamp(self)->int:
        return self._step_counter

    @property
    def done(self):
        return self._done
    
    @property
    def detected(self):
        if self.done: #Only tell if detected when the interaction ends
            return self._detected
        else: return False
        
    def initialize(self, win_conditons:dict, defender_positions:dict, attacker_start_position:dict, max_steps=10,topology=False)-> Observation:
        """
        Initializes the environment with start and goal configuraions.
        Entities in the environment are either read from CYST objects directly or from the serialization file.
        TODO Firewall rules processing
        """
        if topology:
            if self._src_file:
                self._win_conditions = win_conditons
                self._attacker_start = self._create_starting_state(attacker_start_position)
                self._timeout = max_steps
                
                #position defensive measure
                self._place_defences(defender_positions)
                return self.reset()
            else:
                print("Please load a topology file before initializing the environment!")
                return None
        else:
            self._win_conditions = win_conditons
            self._attacker_start = self._create_starting_state(attacker_start_position)
            self._timeout = max_steps
            if not defender_positions:
                self._defender_placements = False
            else:
                self._place_defences(defender_positions)
            return self.reset()
    
    def _create_starting_state(self, attacker_start_position:dict) -> GameState:
        """
        Builds the starting GameState. Currently, we artificially extend the knonw_networks with +- 1 in the third octet.
        """
        known_networks = set()
        #Exted the networks with the neighbouring networks
        for h in attacker_start_position["controlled_hosts"]:
            for net in self._get_networks_from_host(h): #TODO
                known_networks.add(str(net))
                if net.is_private(): #TODO
                    net.value += 256
                    if net.is_private():
                        known_networks.add(str(net))
                    net.value -= 2*256
                    if net.is_private():
                        known_networks.add(str(net))
        known_hosts = attacker_start_position["known_hosts"].union(attacker_start_position["controlled_hosts"])
        return GameState(attacker_start_position["controlled_hosts"], known_hosts,{},{},known_networks)
    
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
                                # if item["net"]["cls_type"] == "IPNetwork":
                                #     if item["net"]["value"] not in self._networks.keys():
                                #         self._networks[item["net"]["value"]] = []
                                # self._networks[item["net"]["value"]].append((item["ip"]["value"], v['id']))
                                # #add IP-> host name mapping
                                self._ips[item["ip"]["value"]] = v['id']  
                    elif v['cls_type'] in "ConnectionConfig": # TODO
                        self._connections[v["src_id"]].append(v["dst_id"])
                        self._connections[v["dst_id"]].append(v["src_id"])
            except yaml.YAMLError as e:
                print(e)
        self._src_file = filename

    def process_cyst_config(self, configuration_objects:list)->None:
        nodes = []
        node_to_id = {}
        routers = []
        connections = []
        exploits = []
        
        #sort objects into categories
        for o in configuration_objects:
            if isinstance(o, NodeConfig):
                nodes.append(o)
            elif isinstance(o, RouterConfig):
                routers.append(o)    
            elif isinstance(o, ConnectionConfig):
                connections.append(o)
            elif isinstance(o, ExploitConfig):
                exploits.append(o)
        #process Nodes
        for n in nodes:
            #print(n)
            self._nodes[n.id] = n
            node_to_id[n.id] = len(node_to_id)
            for i in n.interfaces:
                self._ips[str(i.ip)] = n.id
        #process routers
        for r in routers:
            self._nodes[r.id] = r
            node_to_id[r.id] = len(node_to_id)
            for i in r.interfaces:
                self._ips[str(i.ip)] = r.id
            #add Firewall rules
            for tp in r.traffic_processors:
                for chain in tp.chains:
                    for rule in chain.rules:
                        if rule.policy == FirewallPolicy.ALLOW:
                            self._fw_rules.append(rule)
        #connections
        self._connections = np.zeros([len(node_to_id),len(node_to_id)])
        for c in connections:
            self._connections[node_to_id[c.src_id],node_to_id[c.dst_id]] = 1
        #exploits
        self._exploits = exploits   
    
    def get_valid_actions(self, state:GameState)->list:
        """
        Returns list of valid actions in a given state.
        """
        actions = []
        #Scan network
        for net in state.known_networks:
            actions.append(Action("ScanNetwork",{"target_network":net}))
        #Find services
        for host in state.known_hosts:
            actions.append(Action("FindServices", {"target_host":host}))
        #Find Data
        for host in state.known_hosts.union(state.controlled_hosts):
            a = Action("FindData", {"target_host":host})
            if a not in actions:
                actions.append(a)
        #ExecuteCodeInService
        for host, services in state.known_services.items():
            for s in services:
                actions.append(Action("ExecuteCodeInService", {"target_host":host, "target_service":s.name}))
        #ExfiltrateData
        for source, data in state.known_data.items():
            for target in state.known_hosts:
                if source != target and len(data) > 0:
                    for d in data:
                        actions.append(Action("ExfiltrateData", {"target_host":target, "data":d, "source_host":source}))
        return actions

    def _get_services_from_host(self, host_ip)-> set:
        """
        Returns set of Service tuples from given hostIP
        TODO active services
        """
        #check if IP is correct
        try:
            netaddr.IPAddress(host_ip)
            if host_ip in self._ips:
                host = self._nodes[self._ips[host_ip]]
                services = set()
                if isinstance(host, NodeConfig):
                    for service in host.passive_services:
                        if service.local:
                            if host_ip in self.current_state.controlled_hosts:
                                services.add(Service(service.type, "passive", service.version))
                        else:
                            services.add(Service(service.type, "passive", service.version))
                return services
            return {}
        except ValueError:
            print("HostIP is invalid")
            return {}
    
    def _get_networks_from_host(self, host_ip)->set:
        try:
            host = self._ips[host_ip]
        except KeyError:
            print(f"Given host IP '{host_ip}' is unknown!")
        networks = set()
        for interface in self._nodes[host].interfaces:
            if isinstance(interface, InterfaceConfig):
                networks.add(interface.net)
        return networks
    
    def _get_data_in_host(self, host_ip)->list:
        data = set()
        try:
            if host_ip in self._ips:
                host = self._nodes[self._ips[host_ip]]
                for d in host.private_data:
                    data.add((d.owner, d.description))
        except AttributeError:
            if self.verbosity >= 1:
                print(f"Host {host_ip} has no 'private_data' attribute")
            pass #host has no data attribute
        return data

    def _execute_action(self, current:GameState, action:Action)-> GameState:
        if action.transition.type == "ScanNetwork":
            #does the network exist?
            new_ips = set()
            for ip in netaddr.IPNetwork(action.parameters["target_network"]):
                if str(ip) in self._ips.keys():
                    new_ips.add(str(ip))
            extended_hosts = current.known_hosts.union(new_ips)
            return GameState(current.controlled_hosts, extended_hosts, current.known_services, current.known_data, current.known_networks)
        elif action.transition.type == "FindServices":
            found_services =  self._get_services_from_host(action.parameters["target_host"])
            extended_services = {k:v for k,v in current.known_services.items()}
            if len(found_services) > 0:
                if action.parameters["target_host"] not in extended_services.keys():
                    extended_services[action.parameters["target_host"]] = frozenset(found_services)
                else:
                    extended_services[action.parameters["target_host"]] = frozenset(extended_services[action.parameters["target_host"]]).union(found_services)
            return GameState(current.controlled_hosts, current.known_hosts, extended_services, current.known_data, current.known_networks)
        elif action.transition.type == "FindData":
            extended_data = {k:v for k,v in current.known_data.items()}
            new_data = self._get_data_in_host(action.parameters["target_host"])
            if len(new_data) > 0:
                if action.parameters["target_host"] not in extended_data.keys():
                    extended_data[action.parameters["target_host"]] = new_data
                else:
                    extended_data[action.parameters["target_host"]].union(new_data)
            return GameState(current.controlled_hosts, current.known_hosts, current.known_services, extended_data, current.known_networks)
        
        elif action.transition.type == "ExecuteCodeInService":
            extended_controlled_hosts = set([x for x in current.controlled_hosts])
            if action.parameters["target_host"] not in current.controlled_hosts:
                extended_controlled_hosts.add(action.parameters["target_host"])
            new_networks = self._get_networks_from_host(action.parameters["target_host"])
            extended_networks = current.known_networks.union(new_networks)
            return GameState(extended_controlled_hosts, current.known_hosts, current.known_services, current.known_data, extended_networks)
        
        elif action.transition.type == "ExfiltrateData":
            extended_data = set([x for x in current.known_data()])
            if len(action.parameters["data"]) > 0:
                if action.parameters["target_host"] not in current.known_data.keys():
                    extended_data[action.parameters["target_host"]] = [action.parameters["data"]]
                else:
                    extended_data[action.parameters["target_host"]] += [action.parameters["data"]]
            return GameState(current.controlled_hosts, current.known_hosts, current.known_services, extended_data, current.known_networks)
        else:
            raise ValueError(f"Unknown Action type: '{action.transition.type}'")
    
    def is_valid_action(self, state:GameState, action:Action)-> bool:
        if action.transition.type == "ScanNetwork":
            try:
                net = netaddr.IPNetwork(action.parameters["target_network"])
                return True
            except netaddr.core.AddrFormatError:
                return False
        elif action.transition.type == "FindServices":
            target = action.parameters["target_host"]
            accessible = [target in netaddr.IPNetwork(n) for n in state.known_networks] #TODO Add check for FW rules
            return action.parameters["target_host"] in self._ips and any(accessible)
        elif action.transition.type == "FindData":
            return action.parameters["target_host"] in state.controlled_hosts or action.parameters["target_host"] in state.known_hosts
        elif action.transition.type == "ExecuteCodeInService":
            return action.parameters["target_host"] in state.known_services and action.parameters["target_service"] in [x.name for x in state.known_services[action.parameters["target_host"]]]
        elif action.transition.type == "ExfiltrateData":
            if action.parameters["source_host"] in state.controlled_hosts or action.parameters["source_host"] in state.known_hosts:
                try:
                    data_accessible = action.parameters["data"] in state.known_data[action.parameters["source_host"]]
                    target = action.parameters["target_host"]
                    target_accessible = [target in netaddr.IPNetwork(n) for n in state.known_networks] #TODO Add check for FW rules
                    return data_accessible and target_accessible  and len(action.parameters["data"]) > 0
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
    
    def _is_detected(self, state, action:Action)->bool:
        if self._defender_placements:
            return random() < action.transition.default_detection_p
        else: #no defender
            return False 
    def reset(self)->Observation:
        self._done = False
        self._current_state = copy.deepcopy(self._attacker_start)
        self._step_counter = 0
        self._detected = False
        return Observation(self.current_state, 0, self.is_goal(self.current_state), self._done, {})
    
    def step(self, action:Action)-> Observation:
        if not self._done:
            #check if action is valid
            if self.is_valid_action(self._current_state, action):
                self._step_counter +=1
                #Roll the dice on success
                if random() <= action.transition.default_success_p:
                    next_state = self._execute_action(self._current_state, action)
                    reward = action.transition.default_reward - action.transition.default_cost
                    if self.is_goal(next_state):
                        if self.verbosity >=1:
                            print("Goal Reached")
                        reward += 100
                else: #unsuccessful - pay the cost but no reward, no change in game state
                    next_state = self._current_state
                    reward = - action.transition.default_cost
                    if self.verbosity >=1:
                        print("Action unsuccessful")
                detected = self._is_detected(self._current_state, action)
                is_terminal = self.is_goal(next_state) or detected
                if detected:
                    reward -= 50
                    self._detected = True
                done = self._step_counter >= self._timeout or is_terminal
                self._done = done
                #move environment to the next stae
                self._current_state = next_state
                return Observation(next_state, reward, is_terminal, done, {})
            else:
                raise ValueError(f"Invalid action {action}")
        else:
            raise ValueError("Interaction over! No more steps can be made in the environment")


if __name__ == "__main__":
    
    #create environment
    env = Environment(verbosity=1)
    
    #read topology from the dummy file
    #env.read_topology("test.yaml")
    env.process_cyst_config(configuration_objects)

    #define winning conditions and starting position
    goal = {"known_networks":{}, "known_hosts":{"192.168.1.4"}, "controlled_hosts":{}, "known_services":{}, "known_data":{}}
    attacker_start = {"known_networks":{}, "known_hosts":set(), "controlled_hosts":{"213.47.23.195", "192.168.1.2"}, "known_services":{}, "known_data":{}}
    defender = False
    alpha = 0.2
    gamma = 0.9
    epsilon = 0.75

    #initialize the game
    state = env.initialize(win_conditons=goal, defender_positions=defender, attacker_start_position=attacker_start, max_steps=50)
    
    # actions = env.get_valid_actions(state.observation, transitions)
    # for a in actions:
    #     print(a)
    # next_state = env.step(actions[4])
    # print(next_state.observation)
    
    #Dummy RANDOM attacker
    # reward = 0
    # length = 0
    # iterations = 100
    # for _ in range(iterations):
    #     state = env.reset()
    #     #print("Cleared state:", state)
    #     while not state.done:
    #         #print(state.observation)
    #         reward += state.reward
    #         actions = env.get_valid_actions(state.observation, transitions)
    #         a = choice(actions)
    #         print(a)
    #         state = env.step(a)
    #     length += env.timestamp
    #     print("-------------------------------")
    #     #print(f"Finished in {env.timestamp} steps")
    # print(f"Average rewards per game={reward/iterations}")
    # print(f"Average game length={length/iterations}")  
    
    
    #env.process_cyst_config(configuration_objects)
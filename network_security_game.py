#Author: Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import netaddr
from random import random
from game_components import *
import yaml
from random import random, choice, seed
import copy
from cyst.api.configuration import *
import numpy as np

#from scenarios.scenario_configuration import *
import scenarios.scenario_configuration
import scenarios.smaller_scenario_configuration
import scenarios.tiny_scenario_configuration
import logging



# Set the logging
logger = logging.getLogger('Net-sec-env')

class Network_Security_Environment(object):
    def __init__(self, random_start=True, verbosity=0, seed=42) -> None:
        self._random_start = random_start
        self._defender_placements = None
        self._current_state = None
        self._done = False
        self._src_file = None
        self.verbosity = verbosity
        self._detected = False
        self._current_state = None
    
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
        else: return None
    
    @property
    def num_actions(self):
        return len(transitions)
    
    def get_all_actions(self):
        actions = {}
        for net,ips in self._networks.items():
            #network scans
            actions[len(actions)] = Action("ScanNetwork",{"target_network":net})
            for ip in ips:
                if ip in "0.0.0.0":
                    continue
                #service scans
                actions[len(actions)] = Action("FindServices", {"target_host":ip})
                #data scans
                actions[len(actions)] = Action("FindData", {"target_host":ip})
                #data exfiltration
                for trg_ip in ips:
                    if ip == trg_ip:
                        continue
                    for data_list in self._data.values():
                        for data in data_list:
                            actions[len(actions)] = Action("ExfiltrateData", {"target_host":trg_ip, "data":data, "source_host":ip})
        for host_id, services in self._services.items():
             for service in services:
                for ip, host in self._ips.items():
                    if host_id == host:
                        actions[len(actions)] = Action("ExecuteCodeInService", {"target_host":ip, "target_service":service.name})
        return actions

    def initialize(self, win_conditons:dict, defender_positions:dict, attacker_start_position:dict, max_steps=10, topology=False, cyst_config=None)-> Observation:
        """
        Initializes the environment with start and goal configuraions.
        Entities in the environment are either read from CYST objects directly or from the serialization file.
        TODO Firewall rules processing
        """
        if topology:
            logger.info(f"Initializing the NetSecGame environment from topology {self._src_file}.")
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
        elif cyst_config:
            logger.info(f"Initializing the NetSecGame environment from CYST configuration:")
            self.process_cyst_config(cyst_config)
            #check if win condition
            self._attacker_start_position = attacker_start_position
            logger.info(f"\tSetting timeout (max steps) to {max_steps}")
            self._timeout = max_steps
            self._place_defences(defender_positions)
            self._win_conditions = win_conditons
            
            #check if position of data is randomized #TODO TEMPORAL - FIX ASAP
            for k,v in win_conditons["known_data"].items():
                if isinstance(v, str) and v.lower() == "random":
                    #pick the goal data randomly 
                    available_data = []
                    for n in self._nodes.values():
                        try:                   
                            for service in n.passive_services:
                                for d in service.private_data:
                                    available_data.append((d.owner, d.description))
                        except AttributeError:
                            pass
                    self._win_conditions["known_data"][k] = {choice(available_data)}
                    if self.verbosity > 0:
                        print(f"Winning condition of `known_data` randomly set to {self._win_conditions['known_data']}")
            logger.info(f"\tSetting win conditions{win_conditons}")
            return self.reset()
        else:
            print("CYST confiuration or serialized topology file has to be provided for envrionment initialization!")
            logger.error(f"CYST confiuration or serialized topology file has to be provided for envrionment initialization!")
            raise ValueError("Expected either CYST config object list or topology file for environment initialization!")
    def _create_starting_state(self) -> GameState:
        """
        Builds the starting GameState. Currently, we artificially extend the knonw_networks with +- 1 in the third octet.
        """
        logger.info("Creating the starting state")
        if self._random_start:
            logger.info("\tChoosing random start of the attacker")
            controlled_hosts = set()
            for h in self._attacker_start_position["controlled_hosts"]:
                if "/" in h: #possible network
                    hosts = [str(ip) for ip in netaddr.IPNetwork(h) if (str(ip) in self._ips.keys() and isinstance(self._nodes[self._ips[str(ip)]], NodeConfig))]
                    controlled_hosts.add(choice(hosts))
                else:
                    controlled_hosts.add(h)
        else:
            logger.info("\tUsing pre-defined attacker starting position")
            controlled_hosts = self._attacker_start_position["controlled_hosts"]
        known_networks = set()
        #Exted the networks with the neighbouring networks
        for h in controlled_hosts:
            for net in self._get_networks_from_host(h): #TODO
                known_networks.add(net)
                net_obj = netaddr.IPNetwork(net)
                if net_obj.is_private(): #TODO
                    net_obj.value += 256
                    if net_obj.is_private():
                        known_networks.add(str(net_obj))
                    net_obj.value -= 2*256
                    if net_obj.is_private():
                        known_networks.add(str(net_obj))
                    #return value back to the original
                    net_obj.value += 256
        known_hosts = self._attacker_start_position["known_hosts"].union(controlled_hosts)
        logger.info("Initial gamestate created.")
        return GameState(controlled_hosts, known_hosts, self._attacker_start_position["known_services"],self._attacker_start_position["known_data"], known_networks)
    
    def _place_defences(self, placements:dict)->None:
        # TODO
        logger.info("\tStoring defender placement")
        if placements:
            logger.info(f"\t\tDefender placed in {self._defender_placements}")
            self._defender_placements = True
        else:
            logger.info(f"\t\tNo defender present in the environment")
            self._defender_placements = False
    
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
                                self._ips[item["ip"]["value"]] = v['id']  
                    elif v['cls_type'] in "ConnectionConfig": # TODO
                        self._connections[v["src_id"]].append(v["dst_id"])
                        self._connections[v["dst_id"]].append(v["src_id"])
            except yaml.YAMLError as e:
                print(e)
                logger.error(f"Error while reading CYST topology from '{filename}!")
        self._src_file = filename

    def process_cyst_config(self, configuration_objects:list)->None:
        
        nodes = []
        node_to_id = {}
        routers = []
        connections = []
        exploits = []
        

        self._networks = {}
        self._hosts = {}
        self._services = {}
        self._data = {}

        self._nodes = {}
        self._connections = {}
        self._ips = {}
        self._exploits = {}
        self._fw_rules = []

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
        


        def process_node_config(node_obj:NodeConfig) -> None:
            logger.info(f"\tProcessing config of node '{node_obj.id}'")
            #save the complete object
            self._nodes[node_obj.id] = node_obj
            node_to_id[node_obj.id] = len(node_to_id)
            
            #examine interfaces
            logger.info(f"\t\tProcessing interfaces in node '{node_obj.id}'")
            for interface in node_obj.interfaces:
                net = str(interface.net)
                ip = str(interface.ip)
                self._ips[ip] = node_obj.id            
                self._hosts[ip] = node_obj
                if net not in self._networks:
                    self._networks[net] = []
                self._networks[net].append(ip)

            #services
            logger.info(f"\t\tProcessing services & data in node '{node_obj.id}'")
            for service in node_obj.passive_services:
                if node_obj.id not in self._services:
                    self._services[node_obj.id] = []
                self._services[node_obj.id].append(Service(service.type, "passive", service.version, service.local))
                #data
                logger.info(f"\t\t\tProcessing data in node '{node_obj.id}':'{service.type}' service")
                try:
                    for data in service.private_data:
                        if node_obj.id not in self._data:
                            self._data[node_obj.id] = []
                        self._data[node_obj.id].append((data.owner, data.description))
                    
                except AttributeError:
                    pass
                    #service does not contain any data

        def process_router_config(router_obj:RouterConfig)->None:
            logger.info(f"\tProcessing config of router '{router_obj.id}'")
            self._nodes[router_obj.id] = router_obj
            node_to_id[router_obj.id] = len(node_to_id)
            logger.info(f"\t\tProcessing interfaces in router '{router_obj.id}'")
            for interface in r.interfaces:
                net = str(interface.net)
                ip = str(interface.ip)
                self._ips[ip] = router_obj.id
                self._hosts[ip] = router_obj
                if net not in self._networks:
                    self._networks[net] = []
                self._networks[net].append(ip)
        
            #add Firewall rules
            logger.info(f"\t\tProcessing FW rules in router '{router_obj.id}'")
            for tp in router_obj.traffic_processors:
                for chain in tp.chains:
                    for rule in chain.rules:
                        if rule.policy == FirewallPolicy.ALLOW:
                            self._fw_rules.append(rule)
        #process Nodes
        for n in nodes:
            process_node_config(n)
        #process routers
        for r in routers:
            process_router_config(r)
        
        #connections
        logger.info(f"\tProcessing connections in the network")
        self._connections = np.zeros([len(node_to_id),len(node_to_id)])
        for c in connections:
            self._connections[node_to_id[c.src_id],node_to_id[c.dst_id]] = 1
        
        logger.info(f"\tProcessing available exploits")
        #exploits
        self._exploits = exploits
    
    def get_valid_actions(self, state:GameState)->list:
        """
        Returns list of valid actions in a given state.
        """
        raise DeprecationWarning
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
            for target in state.controlled_hosts:
                if source != target and len(data) > 0:
                    for d in data:
                        actions.append(Action("ExfiltrateData", {"target_host":target, "data":d, "source_host":source}))
        return actions

    def _get_services_from_host(self, host_ip:str, controlled_hosts:set)-> set:
        """
        Returns set of Service tuples from given hostIP

        TODO Differentiate between active and passive services
        """
        found_services = {}
        if host_ip in self._ips: #is it existing IP?
            if self._ips[host_ip] in self._services: #does it have any services?
                if host_ip in controlled_hosts: # Shoul  local services be included ?
                    found_services = {s for s in self._services[self._ips[host_ip]]}
                else:
                    found_services = {s for s in self._services[self._ips[host_ip]] if not s.is_local}
        return found_services
    
    def _get_networks_from_host(self, host_ip)->set:
        """
        Returns set of IPs the host has access to
        """
        networks = set()
        for net, values in self._networks.items():
            if host_ip in values:
                networks.add(net)
        return networks
    
    def _get_data_in_host(self, host_ip:str, controlled_hosts:set)->set:
        """
        Returns set of Data tuples from given host IP
        """
        data = set()
        if host_ip in controlled_hosts: #only return data if the agent controls the host
            if host_ip in self._ips:
                if self._ips[host_ip] in self._data:
                    data = set(self._data[self._ips[host_ip]])
        return data
  
    def _execute_action(self, current:GameState, action:Action)-> GameState:
        try:
            next_known_networks = copy.deepcopy(current.known_networks)
            next_known_hosts = copy.deepcopy(current.known_hosts)
            next_controlled_hosts = copy.deepcopy(current.controlled_hosts)
            next_known_services = copy.deepcopy(current.known_services)
            next_known_data = copy.deepcopy(current.known_data)
            
            if action.transition.type == "ScanNetwork":
                logger.info(f"\t\tScanning {action.parameters['target_network']}")
                new_ips = set()
                for ip in self._ips.keys(): #check if IP exists
                    logger.info(f"\t\tChecking if {ip} in {action.parameters['target_network']}")
                    if ip in netaddr.IPNetwork(action.parameters["target_network"]):
                        logger.info(f"\t\t\tAdding {ip} to new_ips")
                        new_ips.add(ip)
                next_known_hosts.union(new_ips)
            
            elif action.transition.type == "FindServices":
                #get services for current states in target_host
                logger.info(f"\t\tSearching for services in {action.parameters['target_host']}")
                found_services = self._get_services_from_host(action.parameters["target_host"], current.controlled_hosts)
                logger.info(f"\t\t\t Found {len(found_services)}: {found_services}")
                if len(found_services) > 0:
                    if action.parameters["target_host"] not in next_known_services.keys():
                        next_known_services[action.parameters["target_host"]] = found_services
                    else:
                        next_known_services[action.parameters["target_host"]] = next_known_services[action.parameters["target_host"]].union(found_services)

                    #if host was not known, add it to the known_hosts ONLY if there are some found services
                    if action.parameters["target_host"] not in next_known_hosts:
                        logger.info(f"\t\tAdding {action.parameters['target_host']} to known_hosts")
                        next_known_hosts.add(action.parameters["target_host"])
                        next_known_networks = next_known_networks.union({net for net, values in self._networks.items() if action.parameters["target_host"] in values})

            elif action.transition.type == "FindData":
                logger.info(f"\t\tSearching for data in {action.parameters['target_host']}")
                new_data = self._get_data_in_host(action.parameters["target_host"], current.controlled_hosts)
                logger.info(f"\t\t\t Found {len(new_data)}: {new_data}")
                if len(new_data) > 0:
                    if action.parameters["target_host"] not in next_known_data.keys():
                        next_known_data[action.parameters["target_host"]] = new_data
                    else:
                        next_known_data[action.parameters["target_host"]] = next_known_data[action.parameters["target_host"]].union(new_data)
                        
            elif action.transition.type == "ExecuteCodeInService":
                logger.info(f"\t\tAttempting to Execute {action.parameters['target_service']} in {action.parameters['target_host']}")
                if action.parameters["target_host"] in self._ips: #is it existing IP?
                    logger.info(f"\t\t\tValid host")
                    if self._ips[action.parameters["target_host"]] in self._services: #does it have any services?
                        if action.parameters["target_service"] in self._services[self._ips[action.parameters["target_host"]]]: #does it have the service in question?
                            logger.info(f"\t\t\tValid service")
                            if action.parameters["target_host"] not in next_controlled_hosts:
                                next_controlled_hosts.add(action.parameters["target_host"])
                                logger.info(f"\t\tAdding to controlled_hosts")
                            if action.parameters["target_host"] not in next_known_hosts:
                                next_known_hosts.add(action.parameters["target_host"])
                                logger.info(f"\t\tAdding to known_hosts")
                            logger.info(f"\t\tSearching for new networks in host {action.parameters['target_host']}")      
                            new_networks = self._get_networks_from_host(action.parameters["target_host"])
                            logger.info(f"\t\t\tFound {len(new_networks)}: {new_networks}") 
                            next_known_networks = next_known_networks.union(new_networks)

            elif action.transition.type == "ExfiltrateData":
                logger.info(f"\t\tAttempting to Exfiltrate {action.parameters['data']} from {action.parameters['source_host']} to {action.parameters['target_host']}")
                if len(action.parameters["data"]) > 0 and action.parameters["target_host"] in current.controlled_hosts and action.parameters["source_host"] in current.controlled_hosts:
                    if action.parameters["target_host"] not in next_known_data.keys():
                        next_known_data[action.parameters["target_host"]] = {action.parameters["data"]}
                    else:
                        next_known_data[action.parameters["target_host"]] = next_known_data[action.parameters["target_host"]].union(action.parameters["data"])
            
            else:
                raise ValueError(f"Unknown Action type: '{action.transition.type}'")
            
            return GameState(next_controlled_hosts, next_known_hosts, next_known_services, next_known_data, next_known_networks)
        except Exception as e:
            print(f"Error occured when executing action:{action} in  {current}: {e}")
            logger.error(f"Error occured when executing action:{action} in  {current}: {e}")
            exit()
    
    def is_valid_action(self, state:GameState, action:Action)-> bool:
        raise DeprecationWarning
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
                    #print(e)
                    return False
            else:
                return False #for now we don't support this option TODO
        else:
            print(f"Unknown transition type '{action.transition.type}'")
            return False
    
    def is_goal(self, state:GameState)->bool:
        #check if all netoworks are known
        networks = set(self._win_conditions["known_networks"]) <= set(state.known_networks) 
        known_hosts = set(self._win_conditions["known_hosts"]) <= set(state.known_hosts)
        controlled_hosts = set(self._win_conditions["controlled_hosts"]) <= set(state.controlled_hosts)
        try:
            services = True
            missing_keys_services = [k for k in self._win_conditions["known_services"].keys() if k not in state.known_services]
            if len(missing_keys_services) == 0:
                for ip in self._win_conditions["known_services"].keys():
                    for service in self._win_conditions["known_services"][ip]:
                        if service not in state.known_services[ip]:
                            services = False
                            break
            else:
                services = False
        except KeyError:
            services = False
        
        try:
            data = True
            missing_keys_data = [k for k in self._win_conditions["known_data"].keys() if k not in state.known_data]
            if len(missing_keys_data) == 0:
                for k in self._win_conditions["known_data"].keys():
                    if not set(self._win_conditions["known_data"][k]) <= set(state.known_data[k]):
                        data = False
                        break
            else:
                data = False
        except KeyError:
            data = False
        if self.verbosity > 1:
            print("networks", networks)
            print("known", known_hosts)
            print("controlled", controlled_hosts)
            print("services", services)
            print("data", data)
        return networks and known_hosts and controlled_hosts and services and data
    
    def _is_detected(self, state, action:Action)->bool:
        if self._defender_placements:
            value = random() < action.transition.default_detection_p     
            logger.info(f"\tAction detected?: {value}")
            return value
        else: #no defender
            logger.info(f"\tNo defender present")
            return False 
    
    def reset(self)->Observation:
        logger.info(f'--- Reseting env to its initial state ---')
        self._done = False
        self._step_counter = 0
        self._detected = False  
        self._current_state = self._create_starting_state()
        return Observation(self.current_state, 0, self._done, {})
    
    def step(self, action:Action)-> Observation:
        
        """
        Take a step in the environment given an action

        in:
        - action
        out:
        - observation of the state of the env
        """
        if not self._done:
            logger.info(f"Agent's action: {action}")
            self._step_counter += 1
            reason = {}

            # 1. Check if the action was successful or not
            if random() <= action.transition.default_success_p:
                # The action was successful
                logger.info(f"\tAction sucessful")

                # Get the next state given the action
                next_state = self._execute_action(self._current_state, action)
                # Reard for making an action
                reward = -1    
            else: 
                # The action was not successful
                logger.info(f"\tAction NOT sucessful")

                # State does not change
                next_state = self._current_state

                # Reward for taking an action
                reward = -1

                if self.verbosity >=1:
                    print("Action unsuccessful")

            # 2. Check if the new state is the goal state
            is_goal = self.is_goal(next_state)
            logger.info(f"\tGoal reached?: {is_goal}")
            if is_goal:
                # It is the goal
                # Give reward
                reward += 100
                # Game ended
                self._done = True
                logger.info(f'Game ended: Goal')
                reason = {'end_reason':'goal_reached'}

            # 3. Check if the action was detected
            detected = self._is_detected(self._current_state, action)
            if detected:
                # Reward should be negative
                reward -= 50
                # Mark the environment as detected
                self._detected = True
                reason = {'end_reason':'detected'}
                self._done = True
                logger.info(f'Game ended: Detection')

            # Make the state we just got into, our current state
            self._current_state = next_state

            # 4. Check if the max number of steps of the game passed already
            if self._step_counter >= self._timeout:
                logger.info(f'Game timeout - exceeded max number of steps ({self._timeout})!')
                self._done = True
                logger.info(f'Game ended')
                reason = {'end_reason':'timeout'}
            # Return an observation
            return Observation(self._current_state, reward, self._done, reason)
        else:
            raise ValueError("Interaction over! No more steps can be made in the environment")

    def set_timeout(self, timeout):
        self._timeout = timeout

    @property
    def get_current_state(self)->Observation:
        return Observation(self.current_state, 0, self._done, {})

if __name__ == "__main__":

    logging.basicConfig(filename='NetSecGameEvn.log', filemode='w', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.INFO)
    # Create the network security environment
    env = Network_Security_Environment(random_start=False, verbosity=0)
    
    # Read network setup from predefined CYST configuration
    #env.process_cyst_config(scenarios.scenario_configuration.configuration_objects)

    # Define winning conditions and starting position
    goal = {
        "known_networks":set(),
        "known_hosts":{},
        "controlled_hosts":{},
        "known_services":{},
        "known_data":{"213.47.23.195":{("User1", "DataFromServer1"),("User1", "DatabaseData")}}
    }

    # Define where the attacker will start
    attacker_start = {
        "known_networks":set(),
        "known_hosts":set(),
        "controlled_hosts":{"192.168.2.2", "213.47.23.195"},
        "known_services":{'213.47.23.195': {Service(name='listener', type='passive', version='1.0.0', is_local=False), Service(name='bash', type='passive', version='5.0.0', is_local=True)}    },
        "known_data":{}
    }

    # Do we have a defender? 
    defender = {"defender": True}

    # Initialize the game
    
    
    state = env.initialize(win_conditons=goal, defender_positions=defender, attacker_start_position=attacker_start, max_steps=100, cyst_config=scenarios.scenario_configuration.configuration_objects)
    actions = env.get_all_actions()
    current = state
    a = choice(actions)
    next_s = env.step(a)
    states = []
    for _ in range(50):
        a = choice(actions)
        states.append(current.observation)
        next_s = env.step(a)
        print(a)
        current = next_s
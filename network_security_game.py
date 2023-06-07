#Author: Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import netaddr
from game_components import *
import yaml
from random import choice, seed
import random
import copy
from cyst.api.configuration import *
import numpy as np
import scenarios.scenario_configuration
import scenarios.smaller_scenario_configuration
import scenarios.tiny_scenario_configuration
import logging


# Set the logging
logging.basicConfig(filename='netsecenv.log', filemode='w', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.INFO)
logger = logging.getLogger('Net-sec-env')

class Network_Security_Environment(object):
    def __init__(self, random_start=True, verbosity=0, seed=42) -> None:
        """
        Class to manage the whole network security game
        It uses some Cyst libraries for the network topology
        It presents a env environment to play
        """
        # Dictionary of all the nodes in environment
        # All the nodes in the game. Node are hosts, attackers, etc (but not router, connections or exploits)
        self._nodes = {}
        # Connections are how can connect to whom.
        self._connections = {}
        # A dict of all ips in the env, ordered by IP as str() and the object is the id in the _nodes dictionary
        self._ips = {}
        # A dict of the networks present in the game. These are NOT the known networks by the agents
        # self._networks has as key the str of the network and as values a list of the object ids contained in this network.
        self._networks = {}
        # A list of all the hosts where the attacker can start in a random start
        self.hosts_to_start = []
        # All the exploits in the game
        self._exploits = {}
        # If the game starts randomly or not
        self._random_start = random_start
        # Place of the defender
        self._defender_placements = None
        # Current state of the game
        self._current_state = None
        # If the game finished
        self._done = False
        # ?
        self._src_file = None
        # Verbosity. 
        # If the episode/action was detected by the defender
        self.detected = False
        self.verbosity = verbosity
    
    @property
    def timestamp(self)->int:
        """
        Property used to show an interface to agents about what timestamp it is
        """
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
        actions = set()
        for net,ips in self._networks.items():
            #network scans
            actions.add(Action("ScanNetwork",{"target_network":net}))
            for ip in ips:
                if ip in "0.0.0.0":
                    continue
                #service scans
                actions.add(Action("FindServices", {"target_host":ip}))
                #data scans
                actions.add(Action("FindData", {"target_host":ip}))
        # #data exfiltration
        for src_ip in self._ips:
            for trg_ip in self._ips:
                if src_ip != trg_ip and src_ip not in "0.0.0.0" and trg_ip not in "0.0.0.0":
                    for data_list in self._data.values():
                        for data in data_list:
                            actions.add(Action("ExfiltrateData", {"target_host":trg_ip, "data":data, "source_host":src_ip}))
        for host_id, services in self._services.items():
             for service in services:
                for ip, host in self._ips.items():
                    if host_id == host:
                        actions.add(Action("ExecuteCodeInService", {"target_host":ip, "target_service":service}))
        return {k:v for k,v in enumerate(actions)}

    def initialize(self, win_conditons:dict, defender_positions:dict, attacker_start_position:dict, max_steps=10, agent_seed=42, cyst_config=None)-> Observation:
        """
        Initializes the environment with start and goal configuraions.
        Entities in the environment are either read from CYST objects directly or from the serialization file.
        It ALSO resets the environment, so it returns a full state. This is different from other gym envs.
        
        """
        self._networks = {}
        self._hosts = {}
        self._services = {}
        self._data = {}

        self._nodes = {}
        self._connections = {}
        self._ips = {}
        self._exploits = {}
        self._fw_rules = []

        # Process parameters
        self._attacker_start_position = attacker_start_position
        logger.info(f"\tSetting max steps to {max_steps}")
        self.max_steps = max_steps

        self._place_defences(defender_positions)

        # check if win condition
        self._win_conditions = win_conditons

        # Set the seed if passed by the agent
        if agent_seed:
            np.random.seed(agent_seed)
            random.seed(agent_seed)
            logger.info(f'Agent passed a seed, setting to {agent_seed}')
        
        if cyst_config:
            logger.info(f"Initializing the NetSecGame environment from CYST configuration:")
            self.process_cyst_config(cyst_config)

            # Check if position of data is randomized 
            # This code should be moved into create_starting_state()
            logger.info(f"Checking if we need to set the data to win in a random location.")
            # For each known data point in the conditions to win
            for key, value in win_conditons["known_data"].items():
                # Was the position defined as random?
                if isinstance(value, str) and value.lower() == "random":
                    logger.info(f"\tYes we do.")
                    # Load all the available data from all hosts
                    available_data = []
                    for node in self._nodes.values():
                        # For each node, independent of what type of node they are...
                        try:                   
                            # Search for passive services, since this is where the 'DataConfig' is
                            for service in node.passive_services:
                                # Search for private data
                                for dataconfig in service.private_data:
                                    # Store all places where we can put the data
                                    available_data.append((dataconfig.owner, dataconfig.description))
                        except AttributeError:
                            pass
                    # From all available data, randomly pick the one that is going to be used to win the game
                    # It seems there can be only one data to win for now
                    self._win_conditions["known_data"][key] = {choice(available_data)}
            
            logger.info(f"\tWinning condition of `known_data` set to {self._win_conditions['known_data']}")
            logger.info(f"CYST configuration processed successfully")
            
            #save self_data original state so we can go back to it in reset
            self._data_original = copy.deepcopy(self._data)
            
            # Return an observation
            return self.reset()
        else:
            logger.error(f"CYST configuration or serialized topology file has to be provided for envrionment initialization!")
            raise ValueError("Expected either CYST config object list or topology file for environment initialization!")
    
    def _create_starting_state(self) -> GameState:
        """
        Builds the starting GameState. Currently, we artificially extend the knonw_networks with +- 1 in the third octet.
        """
        known_networks = set()
        controlled_hosts = set()

        logger.info('Creating the starting state')

        if self._random_start:
            # Random start
            logger.info('Start position of agent is random')
            logger.info(f'Choosing from {self.hosts_to_start}')
            controlled_hosts.add(str(choice(self.hosts_to_start)))
            logger.info(f'\t\tMaking agent start in {controlled_hosts}')
        else:
            # Not random start
            logger.info('Start position of agent is fixed in a host')

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
        """

        # Be careful. These lines must go outside the 'not random' part of the loop. Because it should be possible
        # to have a random start position, but simultaneously to 'force' a controlled host
        # for the case of controlling a command and controll server to exfiltrate.
        for controlled_host in self._attacker_start_position["controlled_hosts"]:
            if controlled_host.find('/') < 0:
                # This is not a network, so add as controlling host
                controlled_hosts.add(controlled_host)
                # Add the controlled hosts to the list of known hosts
                known_hosts = self._attacker_start_position["known_hosts"].union(controlled_hosts)
        
        # Extend the known networks with the neighbouring networks
        # This is to solve in the env (and not in the agent) the problem
        # of not knowing other networks appart from the one the agent is in
        # This is wrong and should be done by the agent, not here
        # TODO remove this!
        for controlled_host in controlled_hosts:
            for net in self._get_networks_from_host(controlled_host): #TODO
                if net.is_private(): #TODO
                    known_networks.add(str(net))
                    net.value += 256
                    if net.is_private():
                        # Check that the extended network is in our list of networks in the game
                        logger.info(f'net1 keys: {self._networks} . net {net}')
                        if str(net) in self._networks.keys():
                            logger.info(f'Adding {net} to agent')
                            known_networks.add(str(net))
                            # If we add it to the agent, also add it in the official list of nets in the env
                            if str(net) not in self._networks:
                                logger.info(f'Adding {net} to known nets')
                                self._networks[str(net)] = []
                    net.value -= 2*256
                    if net.is_private():
                        # Check that the extended network is in our list of networks in the game
                        logger.info(f'net2 keys: {self._networks} . net {net}')
                        if str(net) in self._networks.keys():
                            logger.info(f'Adding {net} to agent')
                            known_networks.add(str(net))
                            # If we add it to the agent, also add it in the official list of nets in the env
                            if str(net) not in self._networks:
                                logger.info(f'Adding {net} to known nets')
                                self._networks[str(net)] = []
                    #return value back to the original
                    net.value += 256


        game_state = GameState(controlled_hosts, known_hosts, self._attacker_start_position["known_services"], self._attacker_start_position["known_data"], known_networks)
        return game_state
    
    def _place_defences(self, placements:dict)->None:
        """
        Place the defender
        For now only if it is present
        """
        logger.info("\tStoring defender placement")
        if placements:
            logger.info(f"\t\tDefender placed in {self._defender_placements}")
            self._defender_placements = True
        else:
            logger.info(f"\t\tNo defender present in the environment")
            self._defender_placements = False
   


    def process_cyst_config(self, configuration_objects:list)->None:
        """
        Process the cyst configuration file
        """

        nodes = []
        node_to_id = {}
        routers = []
        connections = []
        exploits = []
        #sort objects into categories (nodes and routers MUST be processed before connections!)
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
            logger.info(f'\tAdded {str(node.id)} to the list of available nodes.')
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
                logger.info(f'\tAdded network {str(interface.net)} to the list of available nets, with node {node.id}.')


            #services
            logger.info(f"\t\tProcessing services & data in node '{node_obj.id}'")
            for service in node_obj.passive_services:
                # Check if it is a candidate for random start
                # Becareful, it will add all the IPs for this node
                if service.type == "can_attack_start_here":
                    self.hosts_to_start.append(str(interface.ip))

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
            # Process a router
            # Add the router to the list of nodes. This goes
            # against CYST definition. Check if we can modify it in CYST
            if router.id.lower() == 'internet':
                # Ignore the router called 'internet' because it is not a router
                # in our network
                logger.info(f"\t\tSkipping the internet router'")
                return False

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
        Check if the host is in the list of controlled hosts
        """
        data = set()
        if host_ip in controlled_hosts: #only return data if the agent controls the host
            if host_ip in self._ips:
                if self._ips[host_ip] in self._data:
                    data = set(self._data[self._ips[host_ip]])
        return data
  
    def _execute_action(self, current:GameState, action:Action)-> GameState:
        """
        Execute the action and update the values in the state
        Before this function it was checked if the action was successful
        So in here all actions were already successful.
        """

        """
        final merge version
        """

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
                logger.info(f"\t\tAttempting to ExecuteCode in '{action.parameters['target_host']}':'{action.parameters['target_service']}'")
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
            elif action.transition.type == "ExecuteCodeInService":
                # Beer bet. No bugs in this code. Pinky-swear
                logger.info(f"\t\tAttempting to ExecuteCode in '{action.parameters['target_host']}':'{action.parameters['target_service']}'")
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
            else:
                raise ValueError(f"Unknown Action type: '{action.transition.type}'")
            
            return GameState(next_controlled_hosts, next_known_hosts, next_known_services, next_known_data, next_known_networks)
        except Exception as e:
            print(f"Error occured when executing action:{action} in  {current}: {e}")
            logger.error(f"Error occured when executing action:{action} in  {current}: {e}")
            exit()

    def is_goal(self, state:GameState)->bool:
        """
        Check if the goal was reached for the game
        """
        # For each part of the state of the game, check if the conditions are met

        # Networks
        if set(self._win_conditions["known_networks"]) <= set(state.known_networks):
            networks_goal = True
        
        # Known hosts
        if set(self._win_conditions["known_hosts"]) <= set(state.known_hosts):
            known_hosts_goal = True

        # Controlled hosts
        if set(self._win_conditions["controlled_hosts"]) <= set(state.controlled_hosts):
            controlled_hosts_goal = True

        # Services
        try:
            services_goal = True
            missing_keys_services = [k for k in self._win_conditions["known_services"].keys() if k not in state.known_services]
            if len(missing_keys_services) == 0:
                for ip in self._win_conditions["known_services"].keys():
                    for service in self._win_conditions["known_services"][ip]:
                        if service not in state.known_services[ip]:
                            services_goal = False
                            break
            else:
                services_goal = False
        except KeyError:
            services_goal = False


        try:
            logger.info(f'Checking the goal of data')
            logger.info(f'\tData needed to win {self._win_conditions["known_data"]}')
            known_data_goal = True
            keys_data = [k for k in self._win_conditions["known_data"].keys() if k not in state.known_data]
            if len(keys_data) == 0:
                for ip_win in self._win_conditions["known_data"].keys():
                    logger.info(f'\t\tChecking data in ip {ip_win}')
                    logger.info(f'\t\t\tData in state: {state.known_data[ip_win]}')
                    logger.info(f'\t\t\tnot set(self._win_conditions["known_data"][ip_win]) <= set(state.known_data[ip_win]): {not set(self._win_conditions["known_data"][ip_win]) <= set(state.known_data[ip_win])}')
                    if not set(self._win_conditions["known_data"][ip_win]) <= set(state.known_data[ip_win]):
                        known_data_goal = False
                        break
            else:
                known_data_goal = False
        except KeyError:
            known_data_goal = False

        goal_reached = networks_goal and known_hosts_goal and controlled_hosts_goal and known_services_goal and known_data_goal

        return goal_reached

    def _is_detected(self, state, action:Action)->bool:
        """
        Check if this action was detected by the global defender
        based on the probabilitiy distribution in the action configuration
        """
        if self._defender_placements:
            value = random() < action.transition.default_detection_p     
            logger.info(f"\tAction detected?: {value}")
            return value
        else: #no defender
            logger.info(f"\tNo defender present")
            return False 

    def reset(self)->Observation:
        """
        Function to reset the state of the game 
        and play a new episode
        """
        logger.info(f'--- Reseting env to its initial state ---')
        self._done = False
        self._step_counter = 0
        self.detected = False  
        #reset self._data to orignal state
        self._data = copy.deepcopy(self._data_original)
        self._current_state = self._create_starting_state()

        logger.info(f'Current state: {self._current_state} ')
        initial_reward = 0
        info = {}
        # An observation has inside ["state", "reward", "done", "info"]
        return Observation(self._current_state, initial_reward, self._done, info)

    def step(self, action:Action)-> Observation:
        
        """
        Take a step in the environment given an action

        in:
        - action
        out:
        - observation of the state of the env
        """
        if not self._done:
            logger.info(f'Step taken: {self._step_counter}')
            logger.info(f"Agent's action: {action}")
            self._step_counter += 1
            reason = {}

            # 1. Check if the action was successful or not
            if random.random() <= action.transition.default_success_p:
                # The action was successful
                logger.info(f'\tAction sucessful')

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
                # Give reward
                reward += 100  
                # Game ended
                self._done = True
                reason = {'end_reason':'goal_reached'}
                logger.info(f'Episode ended. Reason: {reason}')

            # 3. Check if the action was detected
            # Be sure that if the action was detected the game ends with the
            # correct penalty, even if the action was successfully executed.
            # This means defender wins if both defender and attacker are successful
            # simuntaneously in the same step
            detected = self._is_detected(self._current_state, action)
            if detected:
                # Reward should be negative
                reward -= 50
                # Mark the environment as detected
                self.detected = True
                self._done = True
                reason = {'end_reason':'detected'}
                logger.info(f'Episode ended. Reason: {reason}')

            # Make the state we just got into, our current state
            self._current_state = next_state
            logger.info(f'Current state: {self._current_state} ')

            # 4. Check if the max number of steps of the game passed already
            if self._step_counter >= self._max_steps:
                self._done = True
                reason = {'end_reason':'max_steps'}
                logger.info(f'Episode ended: Exceeded max number of steps ({self._max_steps})')
            
            # Return an observation
            return Observation(self._current_state, reward, self._done, reason)
        else:
            logger.warning(f"Interaction over! No more steps can be made in the environment")
            raise ValueError("Interaction over! No more steps can be made in the environment")


if __name__ == "__main__":
    # Create the network security environment
    # Test normal winning conditions and starting position
    # Test random data and start position
    random_start = False

    if random_start:
        goal = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{"213.47.23.195":"random"}
        }
        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{"213.47.23.195", "192.168.1.9"},
            "known_services":{},
            "known_data":{}
        }
    else:
        goal = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{"213.47.23.195":{("User2", "Data2FromServer1")}}
        }
        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{"213.47.23.195", "192.168.2.4"},
            "known_services":{},
            "known_data":{}
        }

    env = Network_Security_Environment(random_start=random_start, verbosity=0)
    
    # Do we have a defender? 
    defender = None

    # Initialize the game
    observation = env.initialize(win_conditons=goal, defender_positions=defender, attacker_start_position=attacker_start, max_steps=500, agent_seed=42, cyst_config=scenarios.tiny_scenario_configuration.configuration_objects)
    print(f'The complete observation is: {observation}')
    print(f'The state is: {observation.state}')
    print(f'Networks in the env: {env._networks}')
    print(f'\tContr hosts: {observation.state._controlled_hosts}')
    print(f'\tKnown nets: {observation.state._known_networks}')
    print(f'\tKnown host: {observation.state._known_hosts}')
    print(f'\tKnown serv:')
    for ip_service in observation.state._known_services:
        print(f'\t\t{observation.state._known_services[ip_service]}:{ip_service}')
    print(f'\tKnown data: {observation.state._known_data}')

    print()
    print('Start testing rounds of all actions')

    num_iterations = 200
    break_loop = False
    for i in range(num_iterations + 1):
        if break_loop:
            break
        actions = env.get_valid_actions(observation.state)
        print(f'\t- Iteration: {i}')
        for action in actions:
            print(f'\t- Taking Valid action from this state: {action}')
            try:
                observation = env.step(action)
            except ValueError as e:
                print(f'Game ended. {e}')
                break_loop = True
                break
            print(f'\t\tContr hosts: {observation.state._controlled_hosts}')
            print(f'\t\tKnown nets: {observation.state._known_networks}')
            print(f'\t\tKnown host: {observation.state._known_hosts}')
            print(f'\t\tKnown serv:')
            for ip_service in observation.state._known_services:
                print(f'\t\t\t{ip_service}')
                for serv in observation.state._known_services[ip_service]:
                    print(f'\t\t\t\t{serv.name}')
            print(f'\t\tKnown data: {observation.state._known_data}')
            for ip_data in observation.state._known_data:
                if observation.state._known_data[ip_data]:
                    print(f'\t\t\t{ip_data}')
                    for data in observation.state._known_data[ip_data]:
                        print(f'\t\t\t\t{data}')
    print(f'The {num_iterations} iterations of test actions ended.')



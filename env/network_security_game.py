#Author: Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import netaddr
import env.game_components as components
#from random import choice, seed
import random
import copy
from cyst.api.configuration import *
import numpy as np
import env.scenarios.scenario_configuration
import env.scenarios.smaller_scenario_configuration
import env.scenarios.tiny_scenario_configuration
import logging
import os
from pathlib import Path


# Set the logging
log_filename=Path('env/logs/netsecenv.log')
if not log_filename.parent.exists():
    os.makedirs(log_filename.parent)
logging.basicConfig(filename=log_filename, filemode='w', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.INFO)
logger = logging.getLogger('Netsecenv')

class Network_Security_Environment(object):
    def __init__(self, random_start=True, verbosity=0, seed=42) -> None:
        """
        Class to manage the whole network security game
        It uses some Cyst libraries for the network topology
        It presents a env environment to play
        """
        # Dictionary of all the nodes in environment
        # All the nodes in the game. Node are hosts, attackers, etc (but not router, connections or exploits)
        self._node_objects = {}
        # Connections are how can connect to whom.
        self._connections = {}
        # A dict of all ips in the env, ordered by IP as str() and the object is the id in the _node_objects dictionary
        self._ip_to_hostname = {}
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
        self._detected = False
        # To hold all the services we know
        self._services = {}
        self._data = {}
        self._fw_rules = []

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
        return len(components.ActionType)

    def get_all_actions(self):
        actions = set()
        # Get Network scans, Service Find and Data Find
        for net,ips in self._networks.items():
            #network scans
            actions.add(components.Action(components.ActionType.ScanNetwork,{"target_network":net}))
            for ip in ips:
                # ServiceFind
                actions.add(components.Action(components.ActionType.FindServices, {"target_host":ip}))
                # DataFind
                actions.add(components.Action(components.ActionType.FindData, {"target_host":ip}))
        # Get Data exfiltration
        for src_ip in self._ip_to_hostname:
            for trg_ip in self._ip_to_hostname:
                if src_ip != trg_ip:
                    for data_list in self._data.values():
                        for data in data_list:
                            actions.add(components.Action(components.ActionType.ExfiltrateData, {"target_host":trg_ip, "data":data, "source_host":src_ip}))
        # Get Execute services
        for host_id, services in self._services.items():
             for service in services:
                for ip, host in self._ip_to_hostname.items():
                    if host_id == host:
                        actions.add(components.Action(components.ActionType.ExploitService, {"target_host":ip, "target_service":service}))
        return {k:v for k,v in enumerate(actions)}

    def initialize(self, win_conditions:dict, defender_positions:dict, attacker_start_position:dict, max_steps=10, agent_seed=42, cyst_config=None)-> components.Observation:
        """
        Initializes the environment with start and goal configuraions.
        Entities in the environment are either read from CYST objects directly or from the serialization file.
        It ALSO resets the environment, so it returns a full state. This is different from other gym envs.

        """
        logger.info(f"Initializing NetSetGame environment")

        # Process parameters
        self._attacker_start_position = attacker_start_position
        logger.info(f"\tSetting max steps to {max_steps}")
        self._max_steps = max_steps

        self._place_defences(defender_positions)

        # check if win condition
        self._win_conditions = win_conditions

        # Set the seed if passed by the agent
        if agent_seed:
            np.random.seed(agent_seed)
            random.seed(agent_seed)
            logger.info(f'Agent passed a seed, setting to {agent_seed}')

        if cyst_config:
            logger.info(f"Reading from CYST configuration:")
            self.process_cyst_config(cyst_config)

            # Check if position of data is randomized
            # This code should be moved into create_starting_state()
            logger.info(f"Checking if we need to set the data to win in a random location.")
            # For each known data point in the conditions to win

            for key, value in win_conditions["known_data"].items():
                # Was the position defined as random?
                if isinstance(value, str) and value.lower() == "random":
                    logger.info(f"\tData was requested to be put in a random location.")
                    # Load all the available data from all hosts
                    available_data = []
                    for node in self._node_objects.values():
                        # For each node, independent of what type of node they are...
                        try:
                            # Search for passive services, since this is where the 'DataConfig' is
                            for service in node.passive_services:
                                # Search for private data
                                for dataconfig in service.private_data:
                                    # Store all places where we can put the data
                                    available_data.append(components.Data(dataconfig.owner, dataconfig.description))
                        except AttributeError:
                            pass
                    # From all available data, randomly pick the one that is going to be used to win the game
                    # It seems there can be only one data to win for now
                    self._win_conditions["known_data"][key] = {random.choice(available_data)}
                else:
                    logger.info(f"\tData was not requested to be put in a random location.")

            logger.info(f"\tWinning condition of `known_data` set to {self._win_conditions['known_data']}")
            logger.info(f"CYST configuration processed successfully")

            #save self_data original state so we can go back to it in reset
            self._data_original = copy.deepcopy(self._data)

            # Return an observation
            return self.reset()
        else:
            logger.error(f"CYST configuration has to be provided for envrionment initialization!")
            raise ValueError("CYST configuration has to be provided for envrionment initialization!")

    def _create_starting_state(self) -> components.GameState:
        """
        Builds the starting GameState. Currently, we artificially extend the knonw_networks with +- 1 in the third octet.
        """
        known_networks = set()
        controlled_hosts = set()

        logger.info('Creating the starting state')

        if self._random_start:
            # Random start
            logger.info('\tStart position of agent is random')
            logger.info(f'\tChoosing from {self.hosts_to_start}')
            controlled_hosts.add(random.choice(self.hosts_to_start))
            logger.info(f'\t\tMaking agent start in {controlled_hosts}')
        else:
            # Not random start
            logger.info('\tStart position of agent is not random.')

        # Be careful. These lines must go outside the 'not random' part of the loop. Because it should be possible
        # to have a random start position, but simultaneously to 'force' a controlled host
        # for the case of controlling a command and controll server to exfiltrate.
        for controlled_host in self._attacker_start_position["controlled_hosts"]:
            if isinstance(controlled_host, components.IP):
                # This is not a network, so add as controlling host
                controlled_hosts.add(controlled_host)
                # Add the controlled hosts to the list of known hosts
                known_hosts = self._attacker_start_position["known_hosts"].union(controlled_hosts)
                logger.info(f'\tThe attacker has control of host {str(controlled_host)}.')

        # Extend the known networks with the neighbouring networks
        # This is to solve in the env (and not in the agent) the problem
        # of not knowing other networks appart from the one the agent is in
        # This is wrong and should be done by the agent, not here
        # TODO remove this!
        for controlled_host in controlled_hosts:
            for net in self._get_networks_from_host(controlled_host): #TODO
                net_obj = netaddr.IPNetwork(str(net))
                if net_obj.is_private(): #TODO
                    known_networks.add(net)
                    net_obj.value += 256
                    if net_obj.is_private():
                        ip = components.IP(str(net_obj))
                        logger.info(f'\tAdding {ip} to agent')
                        known_networks.add(ip)
                    net_obj.value -= 2*256
                    if net_obj.is_private():
                        ip = components.IP(str(net_obj))
                        logger.info(f'\tAdding {ip} to agent')
                        known_networks.add(ip)
                    #return value back to the original
                    net_obj.value += 256
        # Be sure the controlled hosts are also known hosts
        known_hosts = self._attacker_start_position["known_hosts"].union(controlled_hosts)
        game_state = components.GameState(controlled_hosts, known_hosts, self._attacker_start_position["known_services"], self._attacker_start_position["known_data"], known_networks)
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



    def process_cyst_config(self, configuration_objects:list)-> None:
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
            self._node_objects[node_obj.id] = node_obj
            logger.info(f'\t\tAdded {node_obj.id} to the list of available nodes.')
            node_to_id[node_obj.id] = len(node_to_id)

            #examine interfaces
            logger.info(f"\t\tProcessing interfaces in node '{node_obj.id}'")
            for interface in node_obj.interfaces:
                net_ip, net_mask = str(interface.net).split("/")
                net = components.Network(net_ip,int(net_mask))
                ip = components.IP(str(interface.ip))
                self._ip_to_hostname[ip] = node_obj.id
                if net not in self._networks:
                    self._networks[net] = []
                self._networks[net].append(ip)
                logger.info(f'\t\tAdded network {str(interface.net)} to the list of available nets, with node {node_obj.id}.')


            #services
            logger.info(f"\t\tProcessing services & data in node '{node_obj.id}'")
            for service in node_obj.passive_services:
                # Check if it is a candidate for random start
                # Becareful, it will add all the IPs for this node
                if service.type == "can_attack_start_here":
                    self.hosts_to_start.append(components.IP(str(interface.ip)))
                    continue

                if node_obj.id not in self._services:
                    self._services[node_obj.id] = []
                self._services[node_obj.id].append(components.Service(service.type, "passive", service.version, service.local))
                #data
                logger.info(f"\t\t\tProcessing data in node '{node_obj.id}':'{service.type}' service")
                try:
                    for data in service.private_data:
                        if node_obj.id not in self._data:
                            self._data[node_obj.id] = set()
                        self._data[node_obj.id].add(components.Data(data.owner, data.description))

                except AttributeError:
                    pass
                    #service does not contain any data


        def process_router_config(router_obj:RouterConfig)->None:
            logger.info(f"\tProcessing config of router '{router_obj.id}'")
            # Process a router
            # Add the router to the list of nodes. This goes
            # against CYST definition. Check if we can modify it in CYST
            if router_obj.id.lower() == 'internet':
                # Ignore the router called 'internet' because it is not a router
                # in our network
                logger.info(f"\t\tSkipping the internet router")
                return False

            self._node_objects[router_obj.id] = router_obj
            node_to_id[router_obj.id] = len(node_to_id)
            logger.info(f"\t\tProcessing interfaces in router '{router_obj.id}'")
            for interface in r.interfaces:
                net_ip, net_mask = str(interface.net).split("/")
                net = components.Network(net_ip,int(net_mask))
                ip = components.IP(str(interface.ip))
                self._ip_to_hostname[ip] = router_obj.id
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
            if c.src_id != "internet" and c.dst_id != "internet":
                self._connections[node_to_id[c.src_id],node_to_id[c.dst_id]] = 1
                #TODO FIX THE INTERNET Node issue in connections
        logger.info(f"\tProcessing available exploits")

        #exploits
        self._exploits = exploits

    def _get_services_from_host(self, host_ip:str, controlled_hosts:set)-> set:
        """
        Returns set of Service tuples from given hostIP
        """
        found_services = {}
        if host_ip in self._ip_to_hostname: #is it existing IP?
            if self._ip_to_hostname[host_ip] in self._services: #does it have any services?
                if host_ip in controlled_hosts: # Shoul  local services be included ?
                    found_services = {s for s in self._services[self._ip_to_hostname[host_ip]]}
                else:
                    found_services = {s for s in self._services[self._ip_to_hostname[host_ip]] if not s.is_local}
            else:
                logger.info(f"\tServices not found because host does have any service.")
        else:
            logger.info(f"\tServices not found because target IP does not exists.")
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
            if host_ip in self._ip_to_hostname:
                if self._ip_to_hostname[host_ip] in self._data:
                    data = self._data[self._ip_to_hostname[host_ip]]
        else:
            logger.info(f"\t\t\tCan't get data in host. The host is not controlled.")
        return data

    def _execute_action(self, current:components.GameState, action:components.Action)-> components.GameState:
        """
        Execute the action and update the values in the state
        Before this function it was checked if the action was successful
        So in here all actions were already successful.
        """

        """
        final merge version
        """

        next_known_networks = copy.deepcopy(current.known_networks)
        next_known_hosts = copy.deepcopy(current.known_hosts)
        next_controlled_hosts = copy.deepcopy(current.controlled_hosts)
        next_known_services = copy.deepcopy(current.known_services)
        next_known_data = copy.deepcopy(current.known_data)

        if action.type == components.ActionType.ScanNetwork:
            logger.info(f"\t\tScanning {action.parameters['target_network']}")
            new_ips = set()
            for ip in self._ip_to_hostname.keys(): #check if IP exists
                logger.info(f"\t\tChecking if {ip} in {action.parameters['target_network']}")
                if str(ip) in netaddr.IPNetwork(str(action.parameters["target_network"])):
                    logger.info(f"\t\t\tAdding {ip} to new_ips")
                    new_ips.add(ip)
            next_known_hosts = next_known_hosts.union(new_ips)

        elif action.type == components.ActionType.FindServices:
            #get services for current states in target_host
            logger.info(f"\t\tSearching for services in {action.parameters['target_host']}")
            found_services = self._get_services_from_host(action.parameters["target_host"], current.controlled_hosts)
            logger.info(f"\t\t\tFound {len(found_services)}: {found_services}")
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

        elif action.type == components.ActionType.FindData:
            logger.info(f"\t\tSearching for data in {action.parameters['target_host']}")
            new_data = self._get_data_in_host(action.parameters["target_host"], current.controlled_hosts)
            logger.info(f"\t\t\t Found {len(new_data)}: {new_data}")
            if len(new_data) > 0:
                if action.parameters["target_host"] not in next_known_data.keys():
                    next_known_data[action.parameters["target_host"]] = new_data
                else:
                    next_known_data[action.parameters["target_host"]] = next_known_data[action.parameters["target_host"]].union(new_data)

        elif action.type == components.ActionType.ExploitService:
            # We don't check if the target is a known_host because it can be a blind attempt to attack
            logger.info(f"\t\tAttempting to ExploitService in '{action.parameters['target_host']}':'{action.parameters['target_service']}'")
            if action.parameters["target_host"] in self._ip_to_hostname: #is it existing IP?
                logger.info(f"\t\t\tValid host")
                if self._ip_to_hostname[action.parameters["target_host"]] in self._services: #does it have any services?
                    if action.parameters["target_service"] in self._services[self._ip_to_hostname[action.parameters["target_host"]]]: #does it have the service in question?
                        logger.info(f"\t\t\tValid service")
                        if action.parameters["target_host"] not in next_controlled_hosts:
                            next_controlled_hosts.add(action.parameters["target_host"])
                            logger.info(f"\t\tAdding to controlled_hosts")
                        if action.parameters["target_host"] not in next_known_hosts:
                            next_known_hosts.add(action.parameters["target_host"])
                            logger.info(f"\t\tAdding to known_hosts")

                        new_networks = self._get_networks_from_host(action.parameters["target_host"])
                        logger.info(f"\t\t\tFound {len(new_networks)}: {new_networks}")
                        next_known_networks = next_known_networks.union(new_networks)
                    else:
                        logger.info(f"\t\t\tCan not exploit. Target host does not the service that was attempted.")
                else:
                    logger.info(f"\t\t\tCan not exploit. Target host does not have any services.")
            else:
                logger.info(f"\t\t\tCan not exploit. Target host does not exist.")
        elif action.type == components.ActionType.ExfiltrateData:
            logger.info(f"\t\tAttempting to Exfiltrate {action.parameters['data']} from {action.parameters['source_host']} to {action.parameters['target_host']}")
            if action.parameters["target_host"] in current.controlled_hosts:
                logger.info(f"\t\t\t {action.parameters['target_host']} is under-control: {current.controlled_hosts}")
                if action.parameters["source_host"] in current.controlled_hosts:
                    logger.info(f"\t\t\t {action.parameters['source_host']} is under-control: {current.controlled_hosts}")
                    if self._ip_to_hostname[action.parameters["source_host"]] in self._data.keys():
                        if action.parameters["data"] in self._data[self._ip_to_hostname[action.parameters["source_host"]]]:
                            logger.info(f"\t\t\t Data present in the source_host")
                            if action.parameters["target_host"] not in next_known_data.keys():
                                next_known_data[action.parameters["target_host"]] = {action.parameters["data"]}
                            else:
                                next_known_data[action.parameters["target_host"]].add(action.parameters["data"])
                            # If the data was exfiltrated to a new host, remember the data in the new nost in the env
                            if self._ip_to_hostname[action.parameters["target_host"]] not in self._data.keys():
                                self._data[self._ip_to_hostname[action.parameters["target_host"]]] = {action.parameters["data"]}
                            else:
                                self._data[self._ip_to_hostname[action.parameters["target_host"]]].add(action.parameters["data"])
                        else:
                            logger.info(f"\t\t\tCan not exfiltrate. Source host does not have this data.")
                    else:
                        logger.info(f"\t\t\tCan not exfiltrate. Source host does not have any data.")
                else:
                    logger.info(f"\t\t\tCan not exfiltrate. Source host is not controlled.")
            else:
                logger.info(f"\t\t\tCan not exfiltrate. Target host is not controlled.")
        else:
            raise ValueError(f"Unknown Action type: '{action.type}'")

        return components.GameState(next_controlled_hosts, next_known_hosts, next_known_services, next_known_data, next_known_networks)


    def is_goal(self, state:components.GameState)->bool:
        """
        Check if the goal was reached for the game
        """
        # For each part of the state of the game, check if the conditions are met
        

        def goal_dict_satistfied(goal_dict:dict, known_dict: dict)-> bool:
            """
            Helper function for checking if a goal dictionary condition is satisfied
            """
            # check if we have all IPs that should have some values (are keys in goal_dict)
            if goal_dict.keys() <= known_dict.keys():
                logger.info(f'\t\tKey comparison OK')
                try:
                    # Check if values (sets) for EACH key (host) in goal_dict are subsets of known_dict, keep matching_keys
                    matching_keys = [host for host in goal_dict.keys() if goal_dict[host]<= known_dict[host]]
                    # Check we have the amount of mathing keys as in the goal_dict
                    logger.info(f"\t\tMathing sets: {len(matching_keys)}, required: {len(goal_dict.keys())}")
                    if len(matching_keys) == len(goal_dict.keys()):
                        return True
                except KeyError:
                    #some keys are missing in the known_dict
                    return False
            return False
        
        
        
        # Networks
        # If empty goal, then should be true for this element
        if set(self._win_conditions["known_networks"]) <= set(state.known_networks):
            networks_goal = True
        else:
            networks_goal = False
        # Known hosts
        # If empty goal, then should be true for this element
        if set(self._win_conditions["known_hosts"]) <= set(state.known_hosts):
            known_hosts_goal = True
        else:
            known_hosts_goal = False
        # Controlled hosts
        # If empty goal, then should be true for this element
        if set(self._win_conditions["controlled_hosts"]) <= set(state.controlled_hosts):
            controlled_hosts_goal = True
        else:
            controlled_hosts_goal = False
        
        # Services
        # If empty goal, then should be true for this element
        logger.info(f'Checking the goal of services')
        logger.info(f'\tServices needed to win {self._win_conditions["known_services"]}')
        services_goal = goal_dict_satistfied(self._win_conditions["known_services"], state.known_services)

        # Data
        logger.info(f'Checking the goal of data')
        logger.info(f'\tData needed to win {self._win_conditions["known_data"]}')
        known_data_goal = goal_dict_satistfied(self._win_conditions["known_data"], state.known_data)

        logger.info(f"\tnets:{networks_goal}, known_hosts:{known_hosts_goal}, controlled_hosts:{controlled_hosts_goal},services:{services_goal}, data:{known_data_goal}")
        goal_reached = networks_goal and known_hosts_goal and controlled_hosts_goal and services_goal and known_data_goal

        return goal_reached

    def _is_detected(self, state, action:components.Action)->bool:
        """
        Check if this action was detected by the global defender
        based on the probabilitiy distribution in the action configuration
        """
        if self._defender_placements:
            value = random.random() < action.type.default_detection_p
            logger.info(f"\tAction detected?: {value}")
            return value
        else: #no defender
            logger.info(f"\tNo defender present")
            return False

    def reset(self)->components.Observation:
        """
        Function to reset the state of the game
        and play a new episode
        """
        logger.info(f'--- Reseting env to its initial state ---')
        self._done = False
        self._step_counter = 0
        self._detected = False
        #reset self._data to orignal state
        self._data = copy.deepcopy(self._data_original)
        self._current_state = self._create_starting_state()

        logger.info(f'Current state: {self._current_state} ')
        initial_reward = 0
        info = {}
        # An observation has inside ["state", "reward", "done", "info"]
        return components.Observation(self._current_state, initial_reward, self._done, info)

    def step(self, action:components.Action)-> components.Observation:

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
            if random.random() <= action.type.default_success_p:
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
                self._detected = True
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
            return components.Observation(self._current_state, reward, self._done, reason)
        else:
            logger.warning(f"Interaction over! No more steps can be made in the environment")
            raise ValueError("Interaction over! No more steps can be made in the environment")


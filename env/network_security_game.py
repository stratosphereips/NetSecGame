#Authors
# Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
# Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz

import netaddr
import env.game_components as components
import random
import itertools
import copy
from cyst.api.configuration import NodeConfig, RouterConfig, ConnectionConfig, ExploitConfig, FirewallPolicy
import numpy as np
import logging
from faker import Faker
import json
from utils.utils import ConfigParser
import subprocess
import xml.etree.ElementTree as ElementTree

# Set the logging
logger = logging.getLogger('Netsecenv')

class SimplisticDefender:
    def __init__(self, config_file) -> None:
        self.task_config = ConfigParser(config_file)
        self.logger = logging.getLogger('Netsecenv-Defender')
        defender_type = self.task_config.get_defender_type()
        self.logger.info(f"Defender set to be of type '{defender_type}'")
        match defender_type:
            case "NoDefender":
                self._defender_type = None
            case 'StochasticDefender':
                # For now there is only one type of defender
                self._defender_type = "Stochastic"
                self.detection_probability = self._read_detection_probabilities()
            case "StochasticWithThreshold":
                self._defender_type = "StochasticWithThreshold"
                self.detection_probability = self._read_detection_probabilities()
                self._defender_thresholds = self.task_config.get_defender_thresholds()
                self._defender_thresholds["tw_size"] = self.task_config.get_defender_tw_size()
                self._actions_played = []
            case _: # Default option - no defender
                self._defender_type = None
    
    def _read_detection_probabilities(self)->dict:
        """
        Method to read detection probabilities from the task config task.
        """
        detection_probability = {}
        detection_probability[components.ActionType.ScanNetwork] = self.task_config.read_defender_detection_prob('scan_network')
        detection_probability[components.ActionType.FindServices] = self.task_config.read_defender_detection_prob('find_services')
        detection_probability[components.ActionType.ExploitService] = self.task_config.read_defender_detection_prob('exploit_service')
        detection_probability[components.ActionType.FindData] = self.task_config.read_defender_detection_prob('find_data')
        detection_probability[components.ActionType.ExfiltrateData] = self.task_config.read_defender_detection_prob('exfiltrate_data')
        self.logger.info(f"Detection probabilities:{detection_probability}")
        return detection_probability

    def detect(self, state:components.GameState, action:components.Action, actions_played):
        """
        Checks if current action was detected based on the defendr type:
        """
        if self._defender_type is not None: # There is a defender present
            match self._defender_type:
                case "Stochastic":
                    detection = self._stochastic_detection(action)
                    self.logger.info(f"\tAction detected?: {detection}")
                    return detection
                case "StochasticWithThreshold":
                    self.logger.info(f"Checking detection based on rules: {action}")
                    detection = self._stochastic_detection_with_thresholds(action, actions_played)
                    self.logger.info(f"\tAction detected?: {detection}")
                    return detection
        else: # No defender in the environment
            logger.info("\tNo defender present")
            return False
    
    def _stochastic_detection_with_thresholds(self, action:components.Action, actions_played)->bool:        
        """ Method used for detection with stochastic defender with minimal thresholds"""
        if len(actions_played) > self._defender_thresholds["tw_size"]: # single action is never detected:
            last_n_actions = actions_played[-self._defender_thresholds["tw_size"]:]
            last_n_action_types = [action.type for action in last_n_actions]
            repeated_action_episode = actions_played.count(action)
            self.logger.info('\tThreshold check')
            # update threh
            match action.type: # thresholds are based on action type
                case components.ActionType.ScanNetwork:
                    tw_ratio = last_n_action_types.count(components.ActionType.ScanNetwork)/self._defender_thresholds["tw_size"]
                    num_consecutive_scans = max(sum(1 for item in grouped if item == components.ActionType.ScanNetwork)
                                                for _,grouped in itertools.groupby(last_n_action_types))
                    if tw_ratio < self._defender_thresholds[components.ActionType.ScanNetwork]["tw_ratio"] and num_consecutive_scans < self._defender_thresholds[components.ActionType.ScanNetwork]["consecutive_actions"]:
                        return False
                    else:
                        self.logger.info(f"\t\t Threshold crossed - TW ratio:{tw_ratio}(T={self._defender_thresholds[components.ActionType.ScanNetwork]['tw_ratio']}), #consecutive actions:{num_consecutive_scans} (T={self._defender_thresholds[components.ActionType.ScanNetwork]['consecutive_actions']})")
                        return self._stochastic_detection(action)
                case components.ActionType.FindServices:
                    tw_ratio = last_n_action_types.count(components.ActionType.FindServices)/self._defender_thresholds["tw_size"]
                    num_consecutive_scans = max(sum(1 for item in grouped if item == components.ActionType.FindServices)
                                                for _,grouped in itertools.groupby(last_n_action_types))
                    if tw_ratio < self._defender_thresholds[components.ActionType.FindServices]["tw_ratio"] and num_consecutive_scans < self._defender_thresholds[components.ActionType.FindServices]["consecutive_actions"]:
                        return False
                    else:
                        self.logger.info(f"\t\t Threshold crossed - TW ratio:{tw_ratio}(T={self._defender_thresholds[components.ActionType.FindServices]['tw_ratio']}), #consecutive actions:{num_consecutive_scans} (T={self._defender_thresholds[components.ActionType.FindServices]['consecutive_actions']})")
                        return self._stochastic_detection(action)
                case components.ActionType.FindData:
                    tw_ratio = last_n_action_types.count(components.ActionType.FindData)/self._defender_thresholds["tw_size"]
                    if tw_ratio < self._defender_thresholds[components.ActionType.FindData]["tw_ratio"] and repeated_action_episode < self._defender_thresholds[components.ActionType.FindData]["repeated_actions_episode"]:
                        return False
                    else:
                        self.logger.info(f"\t\t Threshold crossed - TW ratio:{tw_ratio}(T={self._defender_thresholds[components.ActionType.FindData]['tw_ratio']}), #repeated actions:{repeated_action_episode}")
                        return self._stochastic_detection(action)
                case components.ActionType.ExploitService:
                    tw_ratio = last_n_action_types.count(components.ActionType.ExploitService)/self._defender_thresholds["tw_size"]
                    if tw_ratio < self._defender_thresholds[components.ActionType.ExploitService]["tw_ratio"] and repeated_action_episode < self._defender_thresholds[components.ActionType.ExploitService]["repeated_actions_episode"]:
                        return False
                    else:
                        self.logger.info(f"\t\t Threshold crossed - TW ratio:{tw_ratio}(T={self._defender_thresholds[components.ActionType.ExploitService]['tw_ratio']}), #repeated actions:{repeated_action_episode}")
                        return self._stochastic_detection(action)
                case components.ActionType.ExfiltrateData:
                    tw_ratio = last_n_action_types.count(components.ActionType.ExfiltrateData)/self._defender_thresholds["tw_size"]
                    num_consecutive_scans = max(sum(1 for item in grouped if item == components.ActionType.ExfiltrateData)
                                                for _,grouped in itertools.groupby(last_n_action_types))
                    if tw_ratio < self._defender_thresholds[components.ActionType.ExfiltrateData]["tw_ratio"] and num_consecutive_scans < self._defender_thresholds[components.ActionType.ExfiltrateData]["consecutive_actions"]:
                        return False
                    else:
                        self.logger.info(f"\t\t Threshold crossed - TW ratio:{tw_ratio}(T={self._defender_thresholds[components.ActionType.ExfiltrateData]['tw_ratio']}), #consecutive actions:{num_consecutive_scans} (T={self._defender_thresholds[components.ActionType.ExfiltrateData]['consecutive_actions']})")
                        return self._stochastic_detection(action)
                case _: # default case - No detection
                    return False
        return False
    
    def _stochastic_detection(self, action: components.Action)->bool:
        """ Method stochastic detection based on action default probability"""
        roll = random.random()
        self.logger.info(f"\tRunning stochastic detection. {roll} < {self.detection_probability[action.type]}")
        return roll < self.detection_probability[action.type]
    
    def reset(self)->None:
        self.logger.info("Defender resetted")

class NetworkSecurityEnvironment(object):
    """
    Class to manage the whole network security game
    It uses some Cyst libraries for the network topology
    It presents a env environment to play
    """
    def __init__(self, task_config_file) -> None:
        logger.info("Initializing NetSetGame environment")
        # Prepare data structures for all environment components (to be filled in self._process_cyst_config())
        self._ip_to_hostname = {} # Mapping of `IP`:`host_name`(str) of all nodes in the environment
        self._networks = {} # A `dict` of the networks present in the environment. Keys: `Network` objects, values `set` of `IP` objects.
        self._services = {} # Dict of all services in the environment. Keys: hostname (`str`), values: `set` of `Service` objetcs.
        self._data = {} # Dict of all services in the environment. Keys: hostname (`str`), values `set` of `Service` objetcs.
        self._firewall = {} # dict of all the allowed connections in the environment. Keys `IP` ,values: `set` of `IP` objects.
        self._data_content = {} #content of each datapoint from self._data
        # All exploits in the environment
        self._exploits = {}
        # A list of all the hosts where the attacker can start in a random start
        self.hosts_to_start = []
        # Read the conf file passed by the agent for the rest of values
        self.task_config = ConfigParser(task_config_file)
        # Load CYST configuration
        self._process_cyst_config(self.task_config.get_scenario())
        
        # Set the seed 
        seed = self.task_config.get_seed('env')
        np.random.seed(seed)
        random.seed(seed)
        self._seed = seed
        logger.info(f'Setting env seed to {seed}')
        
        # Set maximum number of steps in one episode
        self._max_steps = self.task_config.get_max_steps()
        logger.info(f"\tSetting max steps to {self._max_steps}")

        # Set rewards for goal/detection/step
        self._rewards = {
            "goal": self.task_config.get_goal_reward(),
            "detection": self.task_config.get_detection_reward(),
            "step": self.task_config.get_step_reward()
        }
        logger.info(f"\tSetting rewards - {self._rewards}")

        # Set the default parameters of all actionss
        # if the values of the actions were updated in the configuration file
        components.ActionType.ScanNetwork.default_success_p = self.task_config.read_env_action_data('scan_network')
        components.ActionType.FindServices.default_success_p = self.task_config.read_env_action_data('find_services')
        components.ActionType.ExploitService.default_success_p = self.task_config.read_env_action_data('exploit_service')
        components.ActionType.FindData.default_success_p = self.task_config.read_env_action_data('find_data')
        components.ActionType.ExfiltrateData.default_success_p = self.task_config.read_env_action_data('exfiltrate_data')

        # Place the defender
        self._defender = SimplisticDefender(task_config_file)
        
        # Get attacker start
        self._attacker_start_position = self.task_config.get_attackers_start_position()

        # should be randomized once or every episode?
        self._randomize_goal_every_episode = self.task_config.get_randomize_goal_every_episode()
        
        # store goal definition
        self._goal_conditions = self.task_config.get_attackers_win_conditions()

        # store goal description
        self._goal_description = self.task_config.get_goal_description()

        # Process episodic randomization of goal position
        if not self._randomize_goal_every_episode:
            # REPLACE 'random' keyword once
            logger.info("Episodic randomization disabled, generating static goal_conditions")
            self._goal_conditions = self._process_win_conditions(self._goal_conditions)
        else:
            logger.info("Episodic randomization enabled, keeping 'random' keyword in the goal description.")

        # At this point all 'random' values should be assigned to something
        # Check if dynamic network and ip adddresses are required
        if self.task_config.get_use_dynamic_addresses():
            logger.info("Dynamic change of the IP and network addresses enabled")
            self._faker_object = Faker()
            Faker.seed(seed)
            self._create_new_network_mapping()

        # read if replay buffer should be store on disc
        if self.task_config.get_store_replay_buffer():
            logger.info("Storing of replay buffer enabled")
            self._episode_replay_buffer = []
            self._trajectories = []
        else:
            logger.info("Storing of replay buffer disabled")
            self._episode_replay_buffer = None

        # Make a copy of data placements so it is possible to reset to it when episode ends
        self._data_original = copy.deepcopy(self._data)
        self._data_content_original = copy.deepcopy(self._data_content)
        
        # CURRENT STATE OF THE GAME - all set to None until self.reset()
        self._current_state = None
        self._current_goal = None
        self._actions_played = []
        # If the game finished. Start with False
        self._end = False
        self._end_reason = None
        # If the episode/action was detected by the defender
        self._detected = None
        logger.info("Environment initialization finished")

    @property
    def seed(self)->int:
        """
        Can be used by agents to use the same random seed as the environment
        """
        return self._seed
    
    @property
    def timestamp(self)->int:
        """
        Property used to show an interface to agents about what timestamp it is
        """
        return self._step_counter

    @property
    def end(self):
        """
        Property used to for indication that
        no more interaction can be done in te currect episode
        """
        return self._end

    @property
    def detected(self):
        """
        Property used to for indication that the attacker has been detected.
        Only returns value when episode is over
        """
        if self.end: #Only tell if detected when the interaction ends
            return self._detected
        else: 
            return None

    @property
    def timeout(self):
        return self._max_steps
    @property
    def num_actions(self):
        return len(self.get_all_actions())
    
    @property
    def goal_description(self):
       return self._goal_description
        
    def get_all_states(self):
        import itertools
        def all_combs(data):
            combs = []
            for i in range(1, len(data)+1):
                els = [x for x in itertools.combinations(data, i)]
                combs += els
            return combs
        combs_nets =  all_combs(self._networks.keys())
        print(combs_nets)
        coms_known_h = all_combs([x for x in self._ip_to_hostname.keys() if x not in [components.IP("192.168.1.1"),components.IP("192.168.2.1")]])
        print(coms_known_h)
        coms_owned_h = all_combs(self._ip_to_hostname.keys())
        all_services = set()
        for service_list in self._services.values():
            for s in service_list:
                if not s.is_local:
                    all_services.add(s)
        coms_services = all_combs(all_services)
        print("\n",coms_services)
        all_data = set()
        for data_list in self._data.values():
            for d in data_list:
                all_data.add(d)
        coms_data = all_combs(all_data)
        print("\n",coms_data)
        return set(itertools.product(combs_nets, coms_known_h, coms_owned_h, coms_services, coms_data))
    
    def get_all_actions(self):
        actions = set()
        
        # Network scans
        for net,ips in self._networks.items():
            for ip in ips:
                actions.add(components.Action(components.ActionType.ScanNetwork,{"target_network":net, "source_host":ip}))

        # Get Network scans, Service Find and Data Find
        for src_ip in self._ip_to_hostname:
            for trg_ip in self._ip_to_hostname:
                if trg_ip != src_ip:
                    # ServiceFind
                    actions.add(components.Action(components.ActionType.FindServices, {"target_host":trg_ip,"source_host":src_ip}))
                    # Data Exfiltration
                    for data_list in self._data.values():
                        for data in data_list:
                            actions.add(components.Action(components.ActionType.ExfiltrateData, {"target_host":trg_ip, "data":data, "source_host":src_ip}))
                # DataFind
                actions.add(components.Action(components.ActionType.FindData, {"target_host":ip, "source_host":src_ip}))
            # Get Execute services
            for host_id, services in self._services.items():
                for service in services:
                    for ip, host in self._ip_to_hostname.items():
                        if host_id == host:
                            actions.add(components.Action(components.ActionType.ExploitService, {"target_host":ip, "target_service":service, "source_host":src_ip}))
        return {k:v for k,v in enumerate(actions)}
    
    def _create_starting_state(self) -> components.GameState:
        """
        Builds the starting GameState from 'self._attacker_start_position'.
        If there is a keyword 'random' used, it is replaced by a valid option at random.

        Currently, we artificially extend the knonw_networks with +- 1 in the third octet.
        """
        known_networks = set()
        controlled_hosts = set()
        logger.info('Generating starting state')
        for controlled_host in self._attacker_start_position['controlled_hosts']:
            if isinstance(controlled_host, components.IP):
                controlled_hosts.add(controlled_host)
                logger.info(f'\tThe attacker has control of host {str(controlled_host)}.')
            elif controlled_host == 'random':
                # Random start
                logger.info('\tAdding random starting position of agent')
                logger.info(f'\t\tChoosing from {self.hosts_to_start}')
                controlled_hosts.add(random.choice(self.hosts_to_start))
                logger.info(f'\t\tMaking agent start in {controlled_hosts}')
            else:
                logger.error(f"Unsupported value encountered in start_position['controlled_hosts']: {controlled_host}")

        # Add all controlled hosts to known_hosts
        known_hosts = self._attacker_start_position["known_hosts"].union(controlled_hosts)
        
        # Extend the known networks with the neighbouring networks
        # This is to solve in the env (and not in the agent) the problem
        # of not knowing other networks appart from the one the agent is in
        # This is wrong and should be done by the agent, not here
        # TODO remove this!
        for controlled_host in controlled_hosts:
            for net in self._get_networks_from_host(controlled_host): #TODO
                net_obj = netaddr.IPNetwork(str(net))
                if net_obj.ip.is_ipv4_private_use(): #TODO
                    known_networks.add(net)
                    net_obj.value += 256
                    if net_obj.ip.is_ipv4_private_use():
                        ip = components.Network(str(net_obj.ip), net_obj.prefixlen)
                        logger.info(f'\tAdding {ip} to agent')
                        known_networks.add(ip)
                    net_obj.value -= 2*256
                    if net_obj.ip.is_ipv4_private_use():
                        ip = components.Network(str(net_obj.ip), net_obj.prefixlen)
                        logger.info(f'\tAdding {ip} to agent')
                        known_networks.add(ip)
                    #return value back to the original
                    net_obj.value += 256
       
        game_state = components.GameState(controlled_hosts, known_hosts, self._attacker_start_position["known_services"], self._attacker_start_position["known_data"], known_networks)
        return game_state

    def _process_win_conditions(self, win_conditions)->dict:
        """
        Method which analyses win_conditions and randomizes parts if required
        """
        logger.info("Processing win conditions")
        updated_win_conditions = {}
        
        # networks
        if win_conditions["known_networks"] == "random":
            updated_win_conditions["known_networks"] = {random.choice(list(self._networks.keys()))}
            logger.info("\t\tRadnomizing known_networks")
        else:
            updated_win_conditions["known_networks"] = copy.deepcopy(win_conditions["known_networks"])
        logger.info(f"\tGoal known_networks: {updated_win_conditions['known_networks']}")
        # known_hosts
        if win_conditions["known_hosts"] == "random":
            logger.info("\t\tRandomizing known_host")
            updated_win_conditions["known_hosts"] = {random.choice(list(self._ip_to_hostname.keys()))}
        else:
            updated_win_conditions["known_hosts"] = copy.deepcopy(win_conditions["known_hosts"])
        logger.info(f"\tGoal known_hosts: {updated_win_conditions['known_hosts']}")
        
        # controlled_hosts
        if win_conditions["controlled_hosts"] == "random":
            logger.info("\tRandomizing controlled_hots")
            updated_win_conditions["controlled_hosts"] = {random.choice(list(self._ip_to_hostname.keys()))}
        else:
            updated_win_conditions["controlled_hosts"] = copy.deepcopy(win_conditions["controlled_hosts"])
        logger.info(f"\tGoal controlled_hosts: {updated_win_conditions['controlled_hosts']}")
        
        # services
        updated_win_conditions["known_services"] = {}
        for host, service_list in win_conditions["known_services"].items():
            # Was the position defined as random?
            if isinstance(service_list, str) and service_list.lower() == "random":
                available_services = []
                for service in self._services[self._ip_to_hostname[host]]:
                    available_services.append(components.Service(service.name, service.type, service.version, service.is_local))
                logger.info(f"\tRandomizing known_services in {host}")
                updated_win_conditions["known_services"][host] = random.choice(available_services)
            else:
                updated_win_conditions["known_services"][host] = copy.deepcopy(win_conditions["known_services"][host])
        logger.info(f"\tGoal known_services: {updated_win_conditions['known_services']}")
        
        # data
        # prepare all available data if randomization is needed
        available_data = set()
        for data in self._data.values():
            for datapoint in data:
                available_data.add(components.Data(datapoint.owner, datapoint.id))
        
        updated_win_conditions["known_data"] = {}
        for host, data_set in win_conditions["known_data"].items():
            # Was random data required in this host?
            if isinstance(data_set, str) and data_set.lower() == "random":
                # From all available data, randomly pick the one that is going to be requested in this host
                updated_win_conditions["known_data"][host] = {random.choice(list(available_data))}
                logger.info(f"\tRandomizing known_data in {host}")
            else:
                updated_win_conditions["known_data"][host] = copy.deepcopy(win_conditions["known_data"][host])
        logger.info(f"\tGoal known_data: {updated_win_conditions['known_data']}")
        return updated_win_conditions

    def _process_cyst_config(self, configuration_objects:list)-> None:
        """
        Process the cyst configuration file
        """
        nodes = []
        node_to_id = {}
        routers = []
        connections = []
        exploits = []
        node_objects = {}
        fw_rules = []
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
            node_objects[node_obj.id] = node_obj
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
                        datapoint = components.Data(data.owner, data.description)
                        self._data[node_obj.id].add(datapoint)
                        # add content
                        self._data_content[node_obj.id, datapoint.id] = f"Content of {datapoint.id}"
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
                logger.info("\t\tSkipping the internet router")
                return False

            node_objects[router_obj.id] = router_obj
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
            logger.info(f"\t\tReading FW rules in router '{router_obj.id}'")
            for tp in router_obj.traffic_processors:
                for chain in tp.chains:
                    for rule in chain.rules:
                        fw_rules.append(rule)
        
        def process_firewall()->dict:
            # process firewall rules
            all_ips = set()
            for ips in self._networks.values():
                all_ips.update(ips)
            firewall = {ip:set() for ip in all_ips}
            if self.task_config.get_use_firewall():
                logger.info("Firewall enabled - processing FW rules")
                # LOCAL NETWORKS
                for net, ips in self._networks.items():
                    # IF net is local, allow connection between all nodes in it
                    if netaddr.IPNetwork(str(net)).ip.is_ipv4_private_use():
                        for src in ips:
                            for dst in ips:
                                firewall[src].add(dst)
                
                # LOCAL TO INTERNET
                for net, ips in self._networks.items():
                    # IF net is local, allow connection between all nodes in it
                    if netaddr.IPNetwork(str(net)).ip.is_ipv4_private_use():
                        for public_net, public_ips in self._networks.items():
                            if not netaddr.IPNetwork(str(public_net)).ip.is_ipv4_private_use():
                                for src in ips:
                                    for dst in public_ips:
                                        firewall[src].add(dst)
                                        #add self loop:
                                        firewall[dst].add(dst)
                # FW RULES FROM CONFIG
                for rule in fw_rules:
                    if rule.policy == FirewallPolicy.ALLOW:
                        src_net = netaddr.IPNetwork(rule.src_net)
                        dst_net = netaddr.IPNetwork(rule.dst_net)
                        logger.info(f"\t{rule}")
                        for src_ip in all_ips:
                            if str(src_ip) in src_net:
                                for dst_ip in all_ips:
                                    if str(dst_ip) in dst_net:
                                        firewall[src_ip].add(dst_ip)
                                        logger.info(f"\t\tAdding {src_ip} -> {dst_ip}")
            else:
                logger.info("Firewall disabled, allowing all connections")
                for src_ip in all_ips:
                    for dst_ip in all_ips:
                        firewall[src_ip].add(dst_ip)
            return firewall
        
        #process Nodes
        for n in nodes:
            process_node_config(n)
        #process routers
        for r in routers:
            process_router_config(r)

        # process firewall rules
        self._firewall = process_firewall()
        
        logger.info("\tProcessing available exploits")

        #exploits
        self._exploits = exploits
        logger.info("CYST configuration processed successfully")
    
    def _create_new_network_mapping(self):
        """ Method that generates random IP and Network addreses
          while following the topology loaded in the environment.
         All internal data structures are updated with the newly generated addresses."""
        fake = self._faker_object
        mapping_nets = {}
        mapping_ips = {}
        
        # generate mapping for networks
        private_nets = []
        for net in self._networks.keys():
            if netaddr.IPNetwork(str(net)).ip.is_ipv4_private_use():
                private_nets.append(net)
            else:
                mapping_nets[net] = components.Network(fake.ipv4_public(), net.mask)
        
        # for private networks, we want to keep the distances among them
        private_nets_sorted = sorted(private_nets)
        valid_valid_network_mapping = False
        counter_iter = 0
        while not valid_valid_network_mapping:
            try:
                # find the new lowest networks
                new_base = netaddr.IPNetwork(f"{fake.ipv4_private()}/{private_nets_sorted[0].mask}")
                # store its new mapping
                mapping_nets[private_nets[0]] = components.Network(str(new_base.network), private_nets_sorted[0].mask)
                base = netaddr.IPNetwork(str(private_nets_sorted[0]))
                is_private_net_checks = []
                for i in range(1,len(private_nets_sorted)):
                    current = netaddr.IPNetwork(str(private_nets_sorted[i]))
                    # find the distance before mapping
                    diff_ip = current.ip - base.ip
                    # find the new mapping 
                    new_net_addr = netaddr.IPNetwork(str(mapping_nets[private_nets_sorted[0]])).ip + diff_ip
                    # evaluate if its still a private network
                    is_private_net_checks.append(new_net_addr.is_ipv4_private_use())
                    # store the new mapping
                    mapping_nets[private_nets_sorted[i]] = components.Network(str(new_net_addr), private_nets_sorted[i].mask)
                if False not in is_private_net_checks: # verify that ALL new networks are still in the private ranges
                    valid_valid_network_mapping = True
            except IndexError as e:
                logger.info(f"Dynamic address sampling failed, re-trying. {e}")
                counter_iter +=1
                if counter_iter > 10:
                    logger.error("Dynamic address failed more than 10 times - stopping.")
                    exit(-1)
                # Invalid IP address boundary
        logger.info(f"New network mapping:{mapping_nets}")
        
        # genereate mapping for ips:
        for net,ips in self._networks.items():
            ip_list = list(netaddr.IPNetwork(str(mapping_nets[net])))[1:]
            # remove broadcast and network ip from the list
            random.shuffle(ip_list)
            for i,ip in enumerate(ips):
                mapping_ips[ip] = components.IP(str(ip_list[i]))
            # Always add random, in case random is selected for ips
            mapping_ips['random'] = 'random'
        logger.info(f"Mapping IPs done:{mapping_ips}")
        
        # update ALL data structure in the environment with the new mappings
        # self._networks
        new_self_networks = {}
        for net, ips in self._networks.items():
            new_self_networks[mapping_nets[net]] = set()
            for ip in ips:
                new_self_networks[mapping_nets[net]].add(mapping_ips[ip])
        self._networks = new_self_networks
        
        #self._firewall
        new_self_firewall = {}
        for ip, dst_ips in self._firewall.items():
            new_self_firewall[mapping_ips[ip]] = set()
            for dst_ip in dst_ips:
                new_self_firewall[mapping_ips[ip]].add(mapping_ips[dst_ip])
        self._firewall = new_self_firewall

        #self._ip_to_hostname
        new_self_ip_to_hostname  = {}
        for ip, hostname in self._ip_to_hostname.items():
            new_self_ip_to_hostname[mapping_ips[ip]] = hostname
        self._ip_to_hostname = new_self_ip_to_hostname

        # Map hosts_to_start
        new_self_host_to_start  = []
        for ip in self.hosts_to_start:
            new_self_host_to_start.append(mapping_ips[ip])
        self.hosts_to_start = new_self_host_to_start
        
        # attacker starting position
        new_attacker_start = {}
        new_attacker_start["known_networks"] = {mapping_nets[net] for net in self._attacker_start_position["known_networks"]}
        new_attacker_start["known_hosts"] = {mapping_ips[ip] for ip in self._attacker_start_position["known_hosts"]}
        new_attacker_start["controlled_hosts"] = {mapping_ips[ip] for ip in self._attacker_start_position["controlled_hosts"]}
        new_attacker_start["known_services"] = {mapping_ips[ip]:service for ip,service in self._attacker_start_position["known_services"].items()}
        new_attacker_start["known_data"] = {mapping_ips[ip]:data for ip,data in self._attacker_start_position["known_data"].items()}
        self._attacker_start_position = new_attacker_start
        logger.info(f"Starting position mapping: {new_attacker_start}")
        # goal definition
        new_goal = {}
        new_goal["known_networks"] = {mapping_nets[net] for net in self._goal_conditions["known_networks"]}
        new_goal["known_hosts"] = {mapping_ips[ip] for ip in self._goal_conditions["known_hosts"]}
        new_goal["controlled_hosts"] = {mapping_ips[ip] for ip in self._goal_conditions["controlled_hosts"]}
        new_goal["known_services"] = {mapping_ips[ip]:service for ip,service in self._goal_conditions["known_services"].items()}
        new_goal["known_data"] = {mapping_ips[ip]:data for ip,data in self._goal_conditions["known_data"].items()}
        logger.info(f"Goal mapping: {new_goal}")
        # update goal mapping
        for old_ip in mapping_ips.keys():
            if str(old_ip) in self._goal_description:
                self._goal_description = self._goal_description.replace(str(old_ip), str(mapping_ips[old_ip]))
                logger.info(f"New goal desc: {self.goal_description}| {old_ip}-> {mapping_ips[old_ip]}")
        self._goal_conditions = new_goal
    
    def _get_services_from_host(self, host_ip:str, controlled_hosts:set)-> set:
        """
        Returns set of Service tuples from given hostIP
        """
        found_services = {}
        if host_ip in self._ip_to_hostname: #is it existing IP?
            if self._ip_to_hostname[host_ip] in self._services: #does it have any services?
                if host_ip in controlled_hosts: # Should  local services be included ?
                    found_services = {s for s in self._services[self._ip_to_hostname[host_ip]]}
                else:
                    found_services = {s for s in self._services[self._ip_to_hostname[host_ip]] if not s.is_local}
            else:
                logger.debug("\tServices not found because host does have any service.")
        else:
            logger.debug("\tServices not found because target IP does not exists.")
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
            logger.debug("\t\t\tCan't get data in host. The host is not controlled.")
        return data

    def _get_data_content(self, host_ip:str, data_id:str)->str:
        """
        Returns content of data identified by a host_ip and data_ip.
        """
        content = None
        if host_ip in self._ip_to_hostname: #is it existing IP?
            hostname = self._ip_to_hostname[host_ip]
            if (hostname, data_id) in self._data_content:
                content = self._data_content[hostname,data_id]
            else:
                logger.info(f"\tData '{data_id}' not found in host '{hostname}'({host_ip})")
        else:
            logger.debug("\Data content not found because target IP does not exists.")
        return content
    
    def _execute_action(self, current:components.GameState, action:components.Action, action_type='netsecenv')-> components.GameState:
        """
        Execute the action and update the values in the state
        Before this function it was checked if the action was successful
        So in here all actions were already successful.

        - actions_type: Define if the action is simulated in netsecenv or in the real world

        Returns: A new GameState
        """
        next_state = None
        match action.type:
            case components.ActionType.ScanNetwork:
                if action_type == "realworld":
                    next_state = self._execute_scan_network_action_real_world(current, action)
                else:
                    next_state = self._execute_scan_network_action(current, action)
            case components.ActionType.FindServices:
                if action_type == "realworld":
                    next_state = self._execute_find_services_real_world(current, action)
                else:
                    next_state = self._execute_find_services_action(current, action)
            case components.ActionType.FindData:
                next_state = self._execute_find_data_action(current, action)
            case components.ActionType.ExploitService:
                next_state = self._execute_exploit_service_action(current, action)
            case components.ActionType.ExfiltrateData:
                next_state = self._execute_exfiltrate_data_action(current, action)
            case _:
                raise ValueError(f"Unknown Action type or other error: '{action.type}'")
        return next_state
        
    def _state_parts_deep_copy(self, current:components.GameState)->tuple:
        next_nets = copy.deepcopy(current.known_networks)
        next_known_h = copy.deepcopy(current.known_hosts)
        next_controlled_h = copy.deepcopy(current.controlled_hosts)
        next_services = copy.deepcopy(current.known_services)
        next_data = copy.deepcopy(current.known_data)
        return next_nets, next_known_h, next_controlled_h, next_services, next_data

    def _firewall_check(self, src_ip:components.IP, dst_ip:components.IP)->bool:
        """Checks if firewall allows connection from 'src_ip to ''dst_ip'"""
        try:
            connection_allowed = dst_ip in self._firewall[src_ip]
        except KeyError:
            connection_allowed = False
        return connection_allowed

    def _execute_scan_network_action(self, current:components.GameState, action:components.Action)->components.GameState:
        """
        Executes the ScanNetwork action in the environment
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data = self._state_parts_deep_copy(current)
        logger.info(f"\t\tScanning {action.parameters['target_network']}")
        if "source_host" in action.parameters.keys() and action.parameters["source_host"] in current.controlled_hosts:
            new_ips = set()
            for ip in self._ip_to_hostname.keys(): #check if IP exists
                logger.info(f"\t\tChecking if {ip} in {action.parameters['target_network']}")
                if str(ip) in netaddr.IPNetwork(str(action.parameters["target_network"])):
                    if self._firewall_check(action.parameters["source_host"], ip):
                        logger.info(f"\t\t\tAdding {ip} to new_ips")
                        new_ips.add(ip)
                    else:
                        logger.info(f"\t\t\tConnection {action.parameters['source_host']} -> {ip} blocked by FW. Skipping")
            next_known_h = next_known_h.union(new_ips)
        else:
            logger.info(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return components.GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets)

    def _execute_find_services_action(self, current:components.GameState, action:components.Action)->components.GameState:
        """
        Executes the FindServices action in the environment
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data = self._state_parts_deep_copy(current)
        logger.info(f"\t\tSearching for services in {action.parameters['target_host']}")
        if "source_host" in action.parameters.keys() and action.parameters["source_host"] in current.controlled_hosts:
            if self._firewall_check(action.parameters["source_host"], action.parameters['target_host']):
                found_services = self._get_services_from_host(action.parameters["target_host"], current.controlled_hosts)
                logger.info(f"\t\t\tFound {len(found_services)}: {found_services}")
                if len(found_services) > 0:
                    next_services[action.parameters["target_host"]] = found_services

                    #if host was not known, add it to the known_hosts ONLY if there are some found services
                    if action.parameters["target_host"] not in next_known_h:
                        logger.info(f"\t\tAdding {action.parameters['target_host']} to known_hosts")
                        next_known_h.add(action.parameters["target_host"])
                        next_nets = next_nets.union({net for net, values in self._networks.items() if action.parameters["target_host"] in values})
            else:
                logger.info(f"\t\t\tConnection {action.parameters['source_host']} -> {action.parameters['target_host']} blocked by FW. Skipping")
        else:
            logger.info(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return components.GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets)
    
    def _execute_find_data_action(self, current:components.GameState, action:components.Action)->components.GameState:
        """
        Executes the FindData action in the environment
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data = self._state_parts_deep_copy(current)
        logger.info(f"\t\tSearching for data in {action.parameters['target_host']}")
        if "source_host" in action.parameters.keys() and action.parameters["source_host"] in current.controlled_hosts:
            if self._firewall_check(action.parameters["source_host"], action.parameters['target_host']):
                new_data = self._get_data_in_host(action.parameters["target_host"], current.controlled_hosts)
                logger.info(f"\t\t\t Found {len(new_data)}: {new_data}")
                if len(new_data) > 0:
                    if action.parameters["target_host"] not in next_data.keys():
                        next_data[action.parameters["target_host"]] = new_data
                    else:
                        next_data[action.parameters["target_host"]] = next_data[action.parameters["target_host"]].union(new_data)
            else:
                logger.info(f"\t\t\tConnection {action.parameters['source_host']} -> {action.parameters['target_host']} blocked by FW. Skipping")
        else:
            logger.info(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return components.GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets)
    
    def _execute_exfiltrate_data_action(self, current:components.GameState, action:components.Action)->components.GameState:
        """
        Executes the ExfiltrateData action in the environment
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data = self._state_parts_deep_copy(current)
        logger.info(f"\t\tAttempting to Exfiltrate {action.parameters['data']} from {action.parameters['source_host']} to {action.parameters['target_host']}")
        # Is the target host controlled?
        if action.parameters["target_host"] in current.controlled_hosts:
            logger.info(f"\t\t\t {action.parameters['target_host']} is under-control: {current.controlled_hosts}")
            # Is the source host controlled?
            if action.parameters["source_host"] in current.controlled_hosts:
                logger.info(f"\t\t\t {action.parameters['source_host']} is under-control: {current.controlled_hosts}")
                # Is the source host in the list of hosts we know data from? (this is to avoid the keyerror later in the if)
                # Does the current state for THIS source already know about this data?
                if self._firewall_check(action.parameters["source_host"], action.parameters['target_host']):
                    if action.parameters['source_host'] in current.known_data.keys() and action.parameters["data"] in current.known_data[action.parameters["source_host"]]:
                        # Does the source host have any data?
                        if self._ip_to_hostname[action.parameters["source_host"]] in self._data.keys():
                            # Does the source host have this data?
                            if action.parameters["data"] in self._data[self._ip_to_hostname[action.parameters["source_host"]]]:
                                logger.info("\t\t\t Data present in the source_host")
                                if action.parameters["target_host"] not in next_data.keys():
                                    next_data[action.parameters["target_host"]] = {action.parameters["data"]}
                                else:
                                    next_data[action.parameters["target_host"]].add(action.parameters["data"])
                                # If the data was exfiltrated to a new host, remember the data in the new nost in the env
                                if self._ip_to_hostname[action.parameters["target_host"]] not in self._data.keys():
                                    self._data[self._ip_to_hostname[action.parameters["target_host"]]] = {action.parameters["data"]}
                                else:
                                    self._data[self._ip_to_hostname[action.parameters["target_host"]]].add(action.parameters["data"])
                            else:
                                logger.info("\t\t\tCan not exfiltrate. Source host does not have this data.")
                        else:
                            logger.info("\t\t\tCan not exfiltrate. Source host does not have any data.")
                    else:
                        logger.info("\t\t\tCan not exfiltrate. Agent did not find this data yet.")
                else:
                    logger.info(f"\t\t\tConnection {action.parameters['source_host']} -> {action.parameters['target_host']} blocked by FW. Skipping")
            else:
                logger.info("\t\t\tCan not exfiltrate. Source host is not controlled.")
        else:
            logger.info("\t\t\tCan not exfiltrate. Target host is not controlled.")
        return components.GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets)
    
    def _execute_exploit_service_action(self, current:components.GameState, action:components.Action)->components.GameState:
        """
        Executes the ExploitService action in the environment
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data = self._state_parts_deep_copy(current)
        # We don't check if the target is a known_host because it can be a blind attempt to attack
        logger.info(f"\t\tAttempting to ExploitService in '{action.parameters['target_host']}':'{action.parameters['target_service']}'")
        if "source_host" in action.parameters.keys() and action.parameters["source_host"] in current.controlled_hosts:
            if action.parameters["target_host"] in self._ip_to_hostname: #is it existing IP?
                if self._firewall_check(action.parameters["source_host"], action.parameters['target_host']):
                    if self._ip_to_hostname[action.parameters["target_host"]] in self._services: #does it have any services?
                        if action.parameters["target_service"] in self._services[self._ip_to_hostname[action.parameters["target_host"]]]: #does it have the service in question?
                            if action.parameters["target_host"] in next_services: #does the agent know about any services this host have?
                                if action.parameters["target_service"] in next_services[action.parameters["target_host"]]:
                                    logger.info("\t\t\tValid service")
                                    if action.parameters["target_host"] not in next_controlled_h:
                                        next_controlled_h.add(action.parameters["target_host"])
                                        logger.info("\t\tAdding to controlled_hosts")
                                    new_networks = self._get_networks_from_host(action.parameters["target_host"])
                                    logger.info(f"\t\t\tFound {len(new_networks)}: {new_networks}")
                                    next_nets = next_nets.union(new_networks)
                                else:
                                    logger.info("\t\t\tCan not exploit. Agent does not know about target host selected service")
                            else:
                                logger.info("\t\t\tCan not exploit. Agent does not know about target host having any service")
                        else:
                            logger.info("\t\t\tCan not exploit. Target host does not the service that was attempted.")
                    else:
                        logger.info("\t\t\tCan not exploit. Target host does not have any services.")
                else:
                    logger.info(f"\t\t\tConnection {action.parameters['source_host']} -> {action.parameters['target_host']} blocked by FW. Skipping")
            else:
                logger.info("\t\t\tCan not exploit. Target host does not exist.")
        else:
            logger.info(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return components.GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets)
    
    def _execute_scan_network_action_real_world(self, current:components.GameState, action:components.Action)->components.GameState:
        """
        Executes the ScanNetwork action in the the real world
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data = self._state_parts_deep_copy(current)
        logger.info(f"\t\tScanning {action.parameters['target_network']} in real world.")
        nmap_file_xml = 'nmap-result.xml'
        command = f"nmap -sn {action.parameters['target_network']} -oX {nmap_file_xml}"
        _ = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        # We ignore the result variable for now
        tree = ElementTree.parse(nmap_file_xml)
        root = tree.getroot()
        new_ips = set()
        for host in root.findall('.//host'):
            status_elem = host.find('./status')
            if status_elem is not None:
                status = host.find('./status').get('state')
            else:
                status = ""
            ip_elem = host.find('./address[@addrtype="ipv4"]')
            if ip_elem is not None:
                ip = components.IP(str(ip_elem.get('addr')))
            else:
                ip = ""
            
            mac_elem = host.find('./address[@addrtype="mac"]')
            if mac_elem is not None:
                mac_address = mac_elem.get('addr', '')
                vendor = mac_elem.get('vendor', '')
            else:
                mac_address = ""
                vendor = ""

            logger.info(f"\t\t\tAdding {ip} to new_ips. {status}, {mac_address}, {vendor}")
            new_ips.add(ip)
        next_known_h = next_known_h.union(new_ips)
        return components.GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets)
    
    def _execute_find_services_action_real_world(self, current:components.GameState, action:components.Action)->components.GameState:
        """
        Executes the FindServices action in the real world
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data = self._state_parts_deep_copy(current)
        logger.info(f"\t\tScanning ports in {action.parameters['target_host']} in real world.")
        nmap_file_xml = 'nmap-result.xml'
        command = f"nmap -sT -n {action.parameters['target_host']} -oX {nmap_file_xml}"
        _ = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        # We ignore the result variable for now
        tree = ElementTree.parse(nmap_file_xml)
        root = tree.getroot()

        # service_dict is a dict. Key=IP(), values= set of Service() objects
        found_services = set()
        port_id = ''
        protocol = ''
        for host in root.findall('.//host'):
            status_elem = host.find('./status')
            if status_elem is not None and status_elem.get('state') == 'up':
                ports_elem = host.find('./ports')
                if ports_elem is not None:
                    for port in root.findall('.//port[@protocol="tcp"]'):
                        state_elem = port.find('./state[@state="open"]')
                        if state_elem is not None:
                            port_id = port.get('portid')
                            protocol = port.get('protocol')
                            service_elem = port.find('./service[@name]')
                            service_name = service_elem.get('name') if service_elem is not None else "Unknown"
                            service_fullname = f'{port_id}/{protocol}/{service_name}'
                            service = components.Service(name=service_fullname, type=service_name, version='', is_local=False)
                            found_services.add(service)

                next_services[action.parameters["target_host"]] = found_services
        
        # If host was not known, add it to the known_hosts and known_networks ONLY if there are some found services
        if action.parameters["target_host"] not in next_known_h:
            logger.info(f"\t\tAdding {action.parameters['target_host']} to known_hosts")
            next_known_h.add(action.parameters["target_host"])
            next_nets = next_nets.union({net for net, values in self._networks.items() if action.parameters["target_host"] in values})
    
        return components.GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets)
    
    def is_goal(self, state:components.GameState)->bool:
        """
        Check if the goal was reached for the game
        """
        def goal_dict_satistfied(goal_dict:dict, known_dict: dict)-> bool:
            """
            Helper function for checking if a goal dictionary condition is satisfied
            """
            # check if we have all IPs that should have some values (are keys in goal_dict)
            if goal_dict.keys() <= known_dict.keys():
                logger.debug('\t\tKey comparison OK')
                try:
                    # Check if values (sets) for EACH key (host) in goal_dict are subsets of known_dict, keep matching_keys
                    matching_keys = [host for host in goal_dict.keys() if goal_dict[host]<= known_dict[host]]
                    # Check we have the amount of mathing keys as in the goal_dict
                    logger.debug(f"\t\tMatching sets: {len(matching_keys)}, required: {len(goal_dict.keys())}")
                    if len(matching_keys) == len(goal_dict.keys()):
                        return True
                except KeyError:
                    #some keys are missing in the known_dict
                    return False
            return False
        # For each part of the state of the game, check if the conditions are met
        goal_reached = {}    
        goal_reached["networks"] = set(self._goal_conditions["known_networks"]) <= set(state.known_networks)
        goal_reached["known_hosts"] = set(self._goal_conditions["known_hosts"]) <= set(state.known_hosts)
        goal_reached["controlled_hosts"] = set(self._goal_conditions["controlled_hosts"]) <= set(state.controlled_hosts)
        goal_reached["services"] = goal_dict_satistfied(self._goal_conditions["known_services"], state.known_services)
        goal_reached["data"] = goal_dict_satistfied(self._goal_conditions["known_data"], state.known_data)
        logger.info(f"Checking goal satisfaction: {goal_reached}")
        return all(goal_reached.values())

    def create_state_from_view(self, view:dict, add_neighboring_nets=True)->components.GameState:
        """
        Builds a GameState from given view.
        If there is a keyword 'random' used, it is replaced by a valid option at random.

        Currently, we artificially extend the knonw_networks with +- 1 in the third octet.
        """
        known_networks = view["known_networks"]
        controlled_hosts = set()
        logger.info(f'Generating state from view:{view}')
        
        # controlled_hosts
        for controlled_host in view['controlled_hosts']:
            if isinstance(controlled_host, components.IP):
                controlled_hosts.add(controlled_host)
                logger.info(f'\tThe attacker has control of host {str(controlled_host)}.')
            elif controlled_host == 'random':
                # Random start
                logger.info('\tAdding random starting position of agent')
                logger.info(f'\t\tChoosing from {self.hosts_to_start}')
                controlled_hosts.add(random.choice(self.hosts_to_start))
                logger.info(f'\t\tMaking agent start in {controlled_hosts}')
            else:
                logger.error(f"Unsupported value encountered in start_position['controlled_hosts']: {controlled_host}")

        # Add all controlled hosts to known_hosts
        known_hosts = view["known_hosts"].union(controlled_hosts)
        if add_neighboring_nets:
            # Extend the known networks with the neighbouring networks
            # This is to solve in the env (and not in the agent) the problem
            # of not knowing other networks appart from the one the agent is in
            # This is wrong and should be done by the agent, not here
            # TODO remove this!
            for controlled_host in controlled_hosts:
                for net in self._get_networks_from_host(controlled_host): #TODO
                    net_obj = netaddr.IPNetwork(str(net))
                    if net_obj.ip.is_ipv4_private_use(): #TODO
                        known_networks.add(net)
                        net_obj.value += 256
                        if net_obj.ip.is_ipv4_private_use():
                            ip = components.Network(str(net_obj.ip), net_obj.prefixlen)
                            logger.info(f'\tAdding {ip} to agent')
                            known_networks.add(ip)
                        net_obj.value -= 2*256
                        if net_obj.ip.is_ipv4_private_use():
                            ip = components.Network(str(net_obj.ip), net_obj.prefixlen)
                            logger.info(f'\tAdding {ip} to agent')
                            known_networks.add(ip)
                        #return value back to the original
                        net_obj.value += 256
       
        game_state = components.GameState(controlled_hosts, known_hosts, view["known_services"], view["known_data"], known_networks)
        return game_state

    def store_trajectories_to_file(self, filename:str)->None:
        if self._trajectories:
            logger.info(f"Saving trajectories to '{filename}'")
            with open(filename, "w") as outfile:
                json.dump(self._trajectories, outfile)
        
    def save_trajectories(self, trajectory_filename=None):
        steps = []
        for state,action,reward,next_state in self._episode_replay_buffer:
            steps.append({"s": state.as_dict, "a":action.as_dict, "r":reward, "s_next":next_state.as_dict})
        goal_state = components.GameState(
            known_hosts=self._goal_conditions["known_hosts"],
            known_networks=self._goal_conditions["known_networks"],
            controlled_hosts=self._goal_conditions["controlled_hosts"],
            known_services=self._goal_conditions["known_services"],
            known_data=self._goal_conditions["known_data"]
        )
        trajectory = {
            "goal": goal_state.as_dict,
            "end_reason":self._end_reason,
            "trajectory":steps
        }
        if not trajectory_filename:
            trajectory_filename = "NSG_trajectories.json"
        if trajectory["end_reason"]:
            self._trajectories.append(trajectory)
            logger.info("Saving trajectories")
            self.store_trajectories_to_file(trajectory_filename)
    
    def reset(self, trajectory_filename=None)->components.Observation: 
        """
        Function to reset the state of the game
        and prepare for a new episode
        """
        # write all steps in the episode replay buffer in the file
        logger.info('--- Reseting env to its initial state ---')
        if self._episode_replay_buffer is not None:
            # Save trajectories to file
            self.save_trajectories(trajectory_filename)
            # reset the replay buffer
            self._episode_replay_buffer = [] 
        # change IPs if needed
        if self.task_config.get_use_dynamic_addresses():
            self._create_new_network_mapping()
        # reset self._data to orignal state
        self._data = copy.deepcopy(self._data_original)
        # reset self._data_content to orignal state
        self._data_content_original = copy.deepcopy(self._data_content_original)
        # create starting state (randomized if needed)
        self._current_state = self._create_starting_state()
        # create win conditions for this episode (randomize if needed)
        self._goal_conditions = copy.deepcopy(self._process_win_conditions(self._goal_conditions))
        logger.info(f'Current state: {self._current_state}')
        
        initial_reward = 0
        info = {}
        self._end = False
        self._end_reason = None
        self._step_counter = 0
        self._detected = False
        
        self._actions_played = []
        self._defender.reset()
        # An observation has inside ["state", "reward", "end", "info"]
        return components.Observation(self._current_state, initial_reward, self._end, info)

    def step(self, action:components.Action, action_type='netsecenv')-> components.Observation:
        """
        Take a step in the environment given an action
        in: action
        out: observation of the state of the env
        """
        if not self._end:
            logger.info(f'Step taken: {self._step_counter}')
            logger.info(f"Agent's action: {action}")
            self._step_counter += 1
            # Reward for taking an action
            reward = self._rewards["step"]
            reason = {}
            self._actions_played.append(action)

            # 1. Perform the action
            self._actions_played.append(action)
            if random.random() <= action.type.default_success_p or action_type == 'realworld':
                next_state = self._execute_action(self._current_state, action, action_type=action_type)
            else:
                logger.info("\tAction NOT sucessful")
                next_state = self._current_state

            # 2. Check if the new state is the goal state
            is_goal = self.is_goal(next_state)
            logger.info(f"\tGoal reached?: {is_goal}")
            if is_goal:
                # Give reward
                reward +=  self._rewards["goal"]
                # Game ended
                self._end = True
                self._end_reason = 'goal_reached'
                reason = {'end_reason': self._end_reason}
                logger.info(f'Episode ended. Reason: {reason}')

            # 3. Check if the action was detected
            # Be sure that if the action was detected the game ends with the
            # correct penalty, even if the action was successfully executed.
            # This means defender wins if both defender and attacker are successful
            # simuntaneously in the same step
            detected = self._defender.detect(self._current_state, action, self._actions_played)
            # Report detection, but not if in this same step the agent won
            if not is_goal and detected:
                # Reward should be negative
                reward += self._rewards["detection"]
                # Mark the environment as detected
                self._detected = True
                self._end = True
                self._end_reason = 'detected'
                reason = {'end_reason':'detected'}
                logger.info(f'Episode ended. Reason: {reason}')

            # Make the state we just got into, our current state
            current_state = self._current_state
            self._current_state = next_state
            logger.info(f'Current state: {self._current_state} ')

            # 4. Check if the max number of steps of the game passed already
            # But if the agent already won in this last step, count the win
            
            # if not is_goal and self._step_counter >= self._max_steps:
            #     self._end = True
            #     self._end_reason = 'max_steps'
            #     reason = {'end_reason':'max_steps'}
            #     logger.info(f'Episode ended: Exceeded max number of steps ({self._max_steps})')

            # Save the transition to the episode replay buffer if there is any
            if self._episode_replay_buffer is not None:
                self._episode_replay_buffer.append((current_state, action, reward, next_state))
            # Return an observation
            return components.Observation(self._current_state, reward, self._end, reason)
        else:
            logger.warning("Interaction over! No more steps can be made in the environment")
            raise ValueError("Interaction over! No more steps can be made in the environment")

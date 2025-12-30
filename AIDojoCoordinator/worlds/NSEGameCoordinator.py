# Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import os
import logging
import argparse
import random
import numpy as np
import copy
import netaddr, re
import json
from faker import Faker
from pathlib import Path
from typing import Iterable
from collections import defaultdict

from AIDojoCoordinator.game_components import GameState, Action, ActionType, IP, Network, Data, Service
from AIDojoCoordinator.coordinator import GameCoordinator
from cyst.api.configuration import NodeConfig, RouterConfig, ConnectionConfig, ExploitConfig, FirewallPolicy

from AIDojoCoordinator.utils.utils import get_logging_level

class NSGCoordinator(GameCoordinator):

    def __init__(self, game_host, game_port, task_config:str, allowed_roles=["Attacker", "Defender", "Benign"], seed=None):
        super().__init__(game_host, game_port, service_host=None, service_port=None, allowed_roles=allowed_roles, task_config_file=task_config)

        # Internal data structure of the NSG
        self._ip_to_hostname = {} # Mapping of `IP`:`host_name`(str) of all nodes in the environment
        self._networks = {} # A `dict` of the networks present in the environment. Keys: `Network` objects, values `set` of `IP` objects.
        self._services = {} # Dict of all services in the environment. Keys: hostname (`str`), values: `set` of `Service` objetcs.
        self._data = {} # Dict of all services in the environment. Keys: hostname (`str`), values `set` of `Service` objetcs.
        self._data_content = {} # ??? Not sure. Added by by sebas to fix error in reading config file
        self._firewall = {} # dict of all the allowed connections in the environment. Keys `IP` ,values: `set` of `IP` objects.
        self._fw_blocks = {}
        self._agent_fw_rules = {}
        # All exploits in the environment
        self._exploits = {}
        # A list of all the hosts where the attacker can start in a random start
        self.hosts_to_start = []
        self._network_mapping = {}
        self._ip_mapping = {}
        
        
        np.random.seed(seed)
        random.seed(seed)
        self._seed = seed
        self.logger.info(f'Setting env seed to {seed}')

    def _initialize(self):
        """
        Initializes the NetSecGame environment.

        Loads the CYST configuration, sets up dynamic IP and network address generation if enabled,
        and stores original copies of environment data structures for later resets. Also seeds the
        random number generator for reproducibility and logs the completion of initialization.

        Returns:
            None
        """
        # Load CYST configuration
        self._process_cyst_config(self._cyst_objects)
                # Check if dynamic network and ip adddresses are required
        if self._use_dynamic_ips:
            self.logger.info("Dynamic change of the IP and network addresses enabled")
            self._faker_object = Faker()
            Faker.seed(self._seed)  
        # store initial values for parts which are modified during the game
        self._data_original = copy.deepcopy(self._data)
        self._data_content_original = copy.deepcopy(self._data_content)
        self._firewall_original = copy.deepcopy(self._firewall)
        self.logger.info("Environment initialization finished")

    def _get_hosts_from_view(self, view_hosts:Iterable, allowed_hosts=None)->set[IP]:
        """
        Parses view and translates all keywords. Produces set of controlled host (IP)
        Args:
            view_hosts (Iterable): The view containing host information.
            allowed_hosts (list, optional): A list of host to start from if 'random' is specified. Defaults to None.
        Returns:
            set: A set of controlled hosts.
        """
        hosts = set()
        self.logger.debug(f'\tParsing hosts from view: {view_hosts}')
        # controlled_hosts
        for host in view_hosts:
            if isinstance(host, IP):
                hosts.add(host)
                self.logger.debug(f'\tAdding {host}.')
            elif host == 'random':
                # Random start
                if allowed_hosts is not None:
                    self.logger.debug(f'\tChoosing randomly from {allowed_hosts}')
                    selected = random.choice(allowed_hosts)
                else:
                    self.logger.debug(f'\tChoosing randomly from all available hosts {list(self._ip_to_hostname.keys())}')
                    selected = random.choice(list(self._ip_to_hostname.keys()))
                hosts.add(selected)
                self.logger.debug(f'\t\tAdding {selected}.')
            elif host == "all_local":
                # all local ips
                self.logger.debug(f'\tAdding all local hosts')
                hosts = hosts.union(self._get_all_local_ips())
            else:
                self.logger.error(f"Unsupported value encountered in view_hosts: {host}")
        return hosts

    def _get_services_from_view(self, view_known_services:dict)->dict:
        """
        Parses view and translates all keywords. Produces dict of known services {IP: set(Service)}

        Args:
            view_known_services (dict): The view containing known services information.

        Returns:
            dict: A dictionary mapping IP addresses to sets of known services.
        """
        # TODO: Add keyword scope parameter (like in _get_data_from_view)
        known_services = {}
        for ip, service_list in view_known_services.items():
            self.logger.debug(f'\tParsing services from {ip}: {service_list}')
            known_services[ip] = set()
            for service in service_list:
                if isinstance(service, Service):
                    known_services[ip].add(service)
                    self.logger.debug(f'\tAdding {service}.')
                elif isinstance(service, str):
                    if service == "random": # randomly select the service
                        self.logger.info(f"\tSelecting service randomly in {ip}")
                        # select candidates that are not explicitly listed
                        service_candidates = [s for s in self._services[self._ip_to_hostname[ip]] if s not in known_services[ip]]
                        if len(service_candidates) == 0:
                            self.logger.warning("\t\tNo available services. Skipping")
                        else:
                            # randomly select from candidates
                            selected = random.choice(service_candidates)
                            self.logger.debug(f"\t\tAdding: {selected}")
                            known_services[ip].add(selected)
                elif service == "all":
                    self.logger.info(f"\tSelecting all services in {ip}")
                    known_services[ip].update(self._services[self._ip_to_hostname[ip]])
                else:
                    self.logger.error(f"Unsupported value encountered in view_known_services: {service}")
        # re-map all IPs based on current mapping in self._ip_mapping
        return known_services

    def _get_data_from_view(self, view_known_data:dict, keyword_scope:str="host", exclude_types=["log"])->dict:
        """
        Parses view and translates all keywords. Produces dict of known data {IP: set(Data)}
        
        Args:
            view_known_data (dict): The view containing known data information.
            keyword_scope (str, optional): Scope of keywords like 'random' or 'all'. Defaults to "host" (i.e., only data from the specified host are considered).
            exclude_types (list, optional): List of data types to exclude when selecting data. Defaults to ["log"].
        Returns:
            dict: A dictionary mapping IP addresses to sets of known data.
        """
        known_data = {}
        for ip, data_list in view_known_data.items():
            self.logger.debug(f'\tParsing data from {ip}: {data_list}')
            known_data[ip] = set()
            for datum in data_list:
                if isinstance(datum, Data):
                    known_data[ip].add(datum)
                    self.logger.debug(f'\tAdding {datum}.')
                elif isinstance(datum, str):
                    # select candidates that are not explicitly listed
                    data_candidates = set()
                    if keyword_scope == "host": # scope of the keyword is the host only
                        for d in self._data[self._ip_to_hostname[ip]]:
                            if d.type not in exclude_types and d not in known_data[ip]:
                                data_candidates.add(d)
                    else:
                        # scope of the keyword is all hosts
                        for datapoints in self._data.values():
                            for d in datapoints:
                                if d.type not in exclude_types and d not in known_data[ip]:
                                    data_candidates.add(d)
                    if datum == "random": # randomly select the service
                        self.logger.info("\tSelecting data randomly")
                        if len(data_candidates) == 0:
                            self.logger.warning("\t\tNo available data. Skipping")
                        else:
                            # randomly select from candidates
                            selected = random.choice(list(data_candidates))
                            self.logger.debug(f"\t\tAdding: {selected}")
                            known_data[ip].add(selected)
                    elif datum == "all":
                        self.logger.info(f"\tSelecting all data in {ip}")
                        known_data[ip].update(data_candidates)
                    else:
                        self.logger.error(f"Unsupported value encountered in view_known_data: {datum}")
                else:
                    self.logger.error(f"Unsupported value encountered in view_known_data: {datum}")
        # re-map all IPs based on current mapping in self._ip_mapping
        return known_data
    
    def _get_networks_from_view(self, view_known_networks:Iterable)->set[Network]:
        """
        Parses view and translates all keywords. Produces set of known networks (Network).
        Args:
            view_known_networks (Iterable): The view containing known networks information.
        Returns:
            set: A set of known networks.
        """
        known_networks = set()
        for net in view_known_networks:
            if isinstance(net, Network):
                known_networks.add(self._network_mapping[net])
                self.logger.debug(f'\tAdding network {self._network_mapping[net]}.')
            elif net == 'random':
                # Randomly select a network from the available ones
                selected = random.choice(list(self._networks.keys()))
                known_networks.add(self._network_mapping[selected])
                self.logger.debug(f'\tAdding randomly selected network: {self._network_mapping[selected]}.')
            elif net == "all_local":
                # all local networks
                self.logger.debug('\t\tAdding all local private networks')
                for n in self._networks.keys():
                    if not n.is_private():
                        known_networks.add(self._network_mapping[n])
            else:
                self.logger.error(f"Unsupported value encountered in start_position['known_networks']: {net}")
        return known_networks

    def _create_goal_state_from_view(self, view:dict, allowed_hosts=None)->GameState:
        """
        Builds a GameState from given view (dict). All keywords are replaced by valid options.
        Args:
            view (dict): The view containing goal state information.
            allowed_hosts (set, optional): A set of allowed hosts for random selection. Defaults to None.
        Returns:
            GameState: The generated goal state.
        """
        self.logger.info(f'Generating goal state from view:{view}')
        # process known networks
        known_networks = self._get_networks_from_view(view_known_networks=view["known_networks"])
        # parse controlled hosts, replacing keywords if present
        controlled_hosts = self._get_hosts_from_view(view_hosts=view["controlled_hosts"], allowed_hosts=allowed_hosts)
        # parse known hosts
        known_hosts = self._get_hosts_from_view(view_hosts=view["known_hosts"])
        # parse known services
        known_services = self._get_services_from_view(view["known_services"])
        # parse known data
        known_data = self._get_data_from_view(view["known_data"], keyword_scope="global", exclude_types=["logs"])
        goal_state = GameState(controlled_hosts, known_hosts, known_services, known_data, known_networks)
        self.logger.info(f"Generated Goal GameState:{goal_state}")
        return goal_state

    def _create_state_from_view(self, view:dict, add_neighboring_nets:bool=True)->GameState:
        """
        Builds a GameState from given view.
        If there is a keyword 'random' used, it is replaced by a valid option at random.

        Currently, we artificially extend the knonw_networks with +- 1 in the third octet.
        """
        self.logger.info(f'Generating state from view:{view}')
        # re-map all networks based on current mapping in self._network_mapping
        known_networks = self._get_networks_from_view(view_known_networks=view["known_networks"])
        # parse controlled hosts
        controlled_hosts = self._get_hosts_from_view(view_hosts=view["controlled_hosts"], allowed_hosts=self.hosts_to_start)
        known_hosts = self._get_hosts_from_view(view_hosts=view["known_hosts"], allowed_hosts=self.hosts_to_start)
        # Add all controlled hosts to known_hosts
        known_hosts = known_hosts.union(controlled_hosts)
        if add_neighboring_nets:
            # Extend the known networks with the neighbouring networks
            # This is to solve in the env (and not in the agent) the problem
            # of not knowing other networks appart from the one the agent is in
            # This is wrong and should be done by the agent, not here
            # TODO remove this!
            for controlled_host in controlled_hosts:
                for net in self._get_networks_from_host(controlled_host): #TODO
                    net_obj = netaddr.IPNetwork(str(net))
                    known_networks.add(net)
                    if net_obj.ip.is_private(): #TODO
                        net_obj.value += 256
                        if net_obj.ip.is_private():
                            ip = Network(str(net_obj.ip), net_obj.prefixlen)
                            self.logger.debug(f'\tAdding {ip} to agent')
                            known_networks.add(ip)
                        net_obj.value -= 2*256
                        if net_obj.ip.is_private():
                            ip = Network(str(net_obj.ip), net_obj.prefixlen)
                            self.logger.debug(f'\tAdding {ip} to agent')
                            known_networks.add(ip)
                        #return value back to the original
                        net_obj.value += 256
        else:
            for controlled_host in controlled_hosts:
                for net in self._get_networks_from_host(controlled_host): #TODO
                    known_networks.add(net)
        # parse known services
        known_services = self._get_services_from_view(view["known_services"])
        # parse known data
        known_data = self._get_data_from_view(view["known_data"])
        game_state = GameState(controlled_hosts, known_hosts, known_services, known_data, known_networks)
        self.logger.info(f"Generated GameState:{game_state}")
        return game_state

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
            self.logger.info(f"\tProcessing config of node '{node_obj.id}'")
            #save the complete object
            node_objects[node_obj.id] = node_obj
            self.logger.info(f'\t\tAdded {node_obj.id} to the list of available nodes.')
            node_to_id[node_obj.id] = len(node_to_id)

            #examine interfaces
            self.logger.info(f"\t\tProcessing interfaces in node '{node_obj.id}'")
            for interface in node_obj.interfaces:
                net_ip, net_mask = str(interface.net).split("/")
                net = Network(net_ip,int(net_mask))
                ip = IP(str(interface.ip))
                if len(node_obj.active_services)>0:
                    self.logger.info(f"\tAdding as potential start point")
                    self.hosts_to_start.append(ip)
                self._ip_to_hostname[ip] = node_obj.id
                if net not in self._networks:
                    self._networks[net] = []
                self._networks[net].append(ip)
                self.logger.info(f'\t\tAdded network {str(interface.net)} to the list of available nets, with node {node_obj.id}.')


            #services
            self.logger.info(f"\t\tProcessing services & data in node '{node_obj.id}'")
            for service in node_obj.passive_services:
                # Check if it is a candidate for random start
                # Becareful, it will add all the IPs for this node
                if service.name == "can_attack_start_here":
                    self.hosts_to_start.append(IP(str(interface.ip)))
                    continue

                if node_obj.id not in self._services:
                    self._services[node_obj.id] = []
                self._services[node_obj.id].append(Service(service.name, "passive", service.version, service.local))
                #data
                self.logger.info(f"\t\t\tProcessing data in node '{node_obj.id}':'{service.name}' service")
                try:
                    for data in service.private_data:
                        self.logger.info(f"\t\t\t\tData: {data}")
                        if node_obj.id not in self._data:
                            self._data[node_obj.id] = set()
                        datapoint = Data(data.owner, data.description)
                        self._data[node_obj.id].add(datapoint)
                        # add content
                        self._data_content[node_obj.id, datapoint.id] = f"Content of {datapoint.id}"
                except AttributeError:
                    # Service does not contain any data
                    pass

        def process_router_config(router_obj:RouterConfig)->None:
            self.logger.info(f"\tProcessing config of router '{router_obj.id}'")
            # Process a router
            # Add the router to the list of nodes. This goes
            # against CYST definition. Check if we can modify it in CYST
            if router_obj.id.lower() == 'internet':
                # Ignore the router called 'internet' because it is not a router
                # in our network
                self.logger.info("\t\tSkipping the internet router")
                return False

            node_objects[router_obj.id] = router_obj
            node_to_id[router_obj.id] = len(node_to_id)
            self.logger.info(f"\t\tProcessing interfaces in router '{router_obj.id}'")
            for interface in r.interfaces:
                net_ip, net_mask = str(interface.net).split("/")
                net = Network(net_ip,int(net_mask))
                ip = IP(str(interface.ip))
                self._ip_to_hostname[ip] = router_obj.id
                if net not in self._networks:
                    self._networks[net] = []
                self._networks[net].append(ip)

            #add Firewall rules
            self.logger.info(f"\t\tReading FW rules in router '{router_obj.id}'")
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
                self.logger.info("Firewall enabled - processing FW rules")
                # LOCAL NETWORKS
                for net, ips in self._networks.items():
                    # IF net is local, allow connection between all nodes in it
                    if netaddr.IPNetwork(str(net)).ip.is_private():
                        for src in ips:
                            for dst in ips:
                                firewall[src].add(dst)
                
                # LOCAL TO INTERNET
                for net, ips in self._networks.items():
                    # IF net is local, allow connection between all nodes in it
                    if netaddr.IPNetwork(str(net)).ip.is_private():
                        for public_net, public_ips in self._networks.items():
                            if not netaddr.IPNetwork(str(public_net)).ip.is_private():
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
                        self.logger.info(f"\t{rule}")
                        for src_ip in all_ips:
                            if str(src_ip) in src_net:
                                for dst_ip in all_ips:
                                    if str(dst_ip) in dst_net:
                                        firewall[src_ip].add(dst_ip)
                                        self.logger.info(f"\t\tAdding {src_ip} -> {dst_ip}")
            else:
                self.logger.info("Firewall disabled, allowing all connections")
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
        
        self.logger.info("\tProcessing available exploits")

        #exploits
        self._exploits = exploits
        
        # create logfile in each nodes
        for node in nodes + routers:
            if node.id not in self._data:
                self._data[node.id] = set()
            self.logger.info(f"\tAdding logfile to node {node.id}")
            self._data[node.id].add(Data(owner="system", id="logfile", type="log", size=0))
        #create initial mapping
        self.logger.info("\tCreating initial mapping of IPs and Networks")
        for net in self._networks.keys():
            self._network_mapping[net] = net
        self.logger.info(f"\tintitial self._network_mapping: {self._network_mapping}")
        for ip in self._ip_to_hostname.keys():
            self._ip_mapping[ip] = ip
        self.logger.info(f"\tintitial self._ip_mapping: {self._ip_mapping}")
        self.logger.info("CYST configuration processed successfully")

    def _dynamic_ip_change(self, max_attempts:int=10, seed=None)-> None:
        """
        Changes the IP and network addresses in the environment
        Args:
            max_attempts (int, optional): Maximum number of attempts to find a valid mapping. Defaults to 10.
            seed (int, optional): Seed for random number generator. Defaults to None.
        Returns:
            None
        """
        self.logger.info("Changing IP and Network addresses in the environment")
        # find a new IP and network mapping 
        mapping_nets, mapping_ips = self._create_new_network_mapping(max_attempts, seed=seed)
        
        # update ALL data structure in the environment with the new mappings
        
        # self._networks
        new_self_networks = {}
        for net, ips in self._networks.items():
            new_self_networks[mapping_nets[net]] = set()
            for ip in ips:
                new_self_networks[mapping_nets[net]].add(mapping_ips[ip])
        self._networks = new_self_networks
        
        #self._firewall_original (we do not care about the changes done during the episode)
        new_self_firewall_original = {}
        for ip, dst_ips in self._firewall_original.items():
            new_self_firewall_original[mapping_ips[ip]] = set()
            for dst_ip in dst_ips:
                new_self_firewall_original[mapping_ips[ip]].add(mapping_ips[dst_ip])
        self.logger.debug(f"New FW: {new_self_firewall_original}")
        self._firewall_original = new_self_firewall_original

        # self._ip_to_hostname
        new_self_ip_to_hostname  = {}
        for ip, hostname in self._ip_to_hostname.items():
            new_self_ip_to_hostname[mapping_ips[ip]] = hostname
        self._ip_to_hostname = new_self_ip_to_hostname

        # Map hosts_to_start
        new_self_host_to_start  = []
        for ip in self.hosts_to_start:
            new_self_host_to_start.append(mapping_ips[ip])
        self.hosts_to_start = new_self_host_to_start

        def apply_mapping(d: dict, mapping: dict) -> dict:
            """
            Apply a mapping to a dictionary.
            - Keys are remapped with mapping if present.
            - Values:
                * If iterable (set/list/tuple), each element is remapped.
                * If string (or non-iterable), attempt direct remap.
            """
            out = defaultdict(set)
            for k, vals in d.items():
                nk = mapping.get(k, k)

                if isinstance(vals, str) or not isinstance(vals, Iterable):
                    # treat as a single atomic value
                    nv = {mapping.get(vals, vals)}
                else:
                    nv = {mapping.get(v, v) for v in vals}

                out[nk].update(nv)

            return dict(out)

        # start_position per role
        for role, start_position in self._starting_positions_per_role.items():
            # {'role': {'controlled_hosts': [...], 'known_hosts': [...], 'known_data': {...}, 'known_services': {...}, known_networks: [...], known_blocks: [...]}}
            new_start_position = {}
            new_start_position['known_networks'] = [mapping_nets.get(net, net) for net in start_position['known_networks']]
            new_start_position['controlled_hosts'] = [mapping_ips.get(ip, ip) for ip in start_position['controlled_hosts']]
            new_start_position['known_hosts'] = [mapping_ips.get(ip, ip) for ip in start_position['known_hosts']]
            new_start_position['known_services'] = {mapping_ips.get(ip, ip): services for ip, services in start_position['known_services'].items()}
            new_start_position["known_data"] = {mapping_ips.get(ip, ip): data for ip, data in start_position['known_data'].items()}
            # known_blocks {IP:set(IP)}
            new_start_position["known_blocks"] = apply_mapping(start_position.get("known_blocks", {}), mapping_ips)
            self._starting_positions_per_role[role] = new_start_position
            self.logger.debug(f"Updated starting position for role {role}: {self._starting_positions_per_role[role]}")
        
        # win_conditions_per_role 
        for role, win_condition in self._win_conditions_per_role.items():
            new_win_condition = {}
            new_win_condition['known_networks'] = [mapping_nets.get(net, net) for net in win_condition['known_networks']]
            new_win_condition['controlled_hosts'] = [mapping_ips.get(ip, ip) for ip in win_condition['controlled_hosts']]
            new_win_condition['known_hosts'] = [mapping_ips.get(ip, ip) for ip in win_condition['known_hosts']]
            new_win_condition['known_services'] = {mapping_ips.get(ip, ip): services for ip, services in win_condition['known_services'].items()}
            new_win_condition["known_data"] = {mapping_ips.get(ip, ip): data for ip, data in win_condition['known_data'].items()}
            new_win_condition["known_blocks"] = apply_mapping(win_condition.get("known_blocks", {}), mapping_ips)
            self._win_conditions_per_role[role] = new_win_condition
            self.logger.debug(f"Updated win condition for role {role}: {self._win_conditions_per_role[role]}")
        
        # goal_description_per_role
        def replace_ips_in_text(text: str, ip_mapping: dict, net_mapping:dict) -> str:
            """
            Replace IPs/CIDRs in text according to mapping {IP: IP}.
            """
            # regex: matches IPv4 like 1.2.3.4 or 1.2.3.4/24
            ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")

            def replacer(match):
                token = match.group(0)
                if "/" in token:
                    try:
                        net_obj = Network(*token.split("/"))
                        return str(net_mapping.get(net_obj, token))
                    except ValueError:
                        return token
                else:
                    try:
                        net_obj = IP(token)
                        return str(ip_mapping.get(net_obj, token))
                    except ValueError:
                        return token

            return ip_pattern.sub(replacer, text)

        new_goal_description = {role:replace_ips_in_text(description, mapping_ips, mapping_nets) for role, description in self._goal_description_per_role.items()}
        self._goal_description_per_role = new_goal_description
        self.logger.debug(f"Updated goal description per role: {self._goal_description_per_role}")
        
        # update mappings stored in the environment
        for net, mapping in self._network_mapping.items():
            self._network_mapping[net] = mapping_nets[mapping]
        self.logger.debug(f"self._network_mapping: {self._network_mapping}")
        for ip, mapping in self._ip_mapping.items():
            self._ip_mapping[ip] = mapping_ips[mapping]
        self.logger.debug(f"self._ip_mapping: {self._ip_mapping}")

    def _create_new_network_mapping(self, max_attempts:int=10, seed=None)->tuple:
        """ Method that generates random IP and Network addreses
          while following the topology loaded in the environment.
         All internal data structures are updated with the newly generated addresses."""
        self.logger.info(f"Generating new network and IP address mapping with seed {seed} (max attempts: {max_attempts})")
        if seed is not None:
            fake = Faker()
            fake.seed_instance(seed)
        else:
            fake = self._faker_object   
        mapping_nets = {}
        mapping_ips = {}
        # generate mapping for networks
        private_nets = []
        for net in self._networks.keys():
            if netaddr.IPNetwork(str(net)).ip.is_private():
                private_nets.append(net)
            else:
                mapping_nets[net] = Network(fake.ipv4_public(), net.mask)
        
        # for private networks, we want to keep the distances among them
        private_nets_sorted = sorted(private_nets)
        valid_valid_network_mapping = False
        counter_iter = 0
        while not valid_valid_network_mapping:
            try:
                # find the new lowest networks
                new_base = netaddr.IPNetwork(f"{fake.ipv4_private()}/{private_nets_sorted[0].mask}")
                # store its new mapping
                mapping_nets[private_nets[0]] = Network(str(new_base.network), private_nets_sorted[0].mask)
                base = netaddr.IPNetwork(str(private_nets_sorted[0]))
                is_private_net_checks = []
                for i in range(1,len(private_nets_sorted)):
                    current = netaddr.IPNetwork(str(private_nets_sorted[i]))
                    # find the distance before mapping
                    diff_ip = current.ip - base.ip
                    # find the new mapping 
                    new_net_addr = netaddr.IPNetwork(str(mapping_nets[private_nets_sorted[0]])).ip + diff_ip
                    # evaluate if its still a private network
                    is_private_net_checks.append(new_net_addr.is_private())
                    # store the new mapping
                    mapping_nets[private_nets_sorted[i]] = Network(str(new_net_addr), private_nets_sorted[i].mask)
                if False not in is_private_net_checks: # verify that ALL new networks are still in the private ranges
                    valid_valid_network_mapping = True
            except IndexError as e:
                self.logger.info(f"Dynamic address sampling failed, re-trying. {e}")
                counter_iter +=1
                if counter_iter > max_attempts:
                    self.logger.error(f"Dynamic address failed more than {max_attempts} times - stopping.")
                    exit(-1)
                # Invalid IP address boundary
        self.logger.info(f"New network mapping:{mapping_nets}")
        
        # genereate mapping for ips:
        for net,ips in self._networks.items():
            ip_list = list(netaddr.IPNetwork(str(mapping_nets[net])))[1:]
            # remove broadcast and network ip from the list
            random.shuffle(ip_list)
            for i,ip in enumerate(ips):
                mapping_ips[ip] = IP(str(ip_list[i]))
            # Always add keywords 'random' and 'all_local' 'all_attackers' to the mapping
            mapping_ips['random'] = 'random'
            mapping_ips['all_local'] = 'all_local'
            mapping_ips['all_attackers'] = 'all_attackers'

        self.logger.info(f"Mapping IPs done:{mapping_ips}")
        return mapping_nets, mapping_ips
    
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
                self.logger.debug("\tServices not found because host does have any service.")
        else:
            self.logger.debug("\tServices not found because target IP does not exists.")
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
            self.logger.debug("\t\t\tCan't get data in host. The host is not controlled.")
        return data
    
    def _get_known_blocks_in_host(self, host_ip:str, controlled_hosts:set)->set:
        known_blocks = set()
        if host_ip in controlled_hosts: #only return data if the agent controls the host
            if host_ip in self._ip_to_hostname:
                if host_ip in self._fw_blocks:
                    known_blocks = self._fw_blocks[host_ip]
        else:
            self.logger.debug("\t\t\tCan't get data in host. The host is not controlled.")
        return known_blocks

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
                self.logger.debug(f"\tData '{data_id}' not found in host '{hostname}'({host_ip})")
        else:
            self.logger.debug("Data content not found because target IP does not exists.")
        return content
    
    def _execute_action(self, current_state:GameState, action:Action, agent_id:tuple)-> GameState:
        """
        Execute the action and update the values in the state
        Before this function it was checked if the action was successful
        So in here all actions were already successful.

        - actions_type: Define if the action is simulated in netsecenv or in the real world
        - agent_id: is the name or type of agent that requested the action

        Returns: A new GameState
        """
        next_state = None
        match action.type:
            case ActionType.ScanNetwork:
                next_state = self._execute_scan_network_action(current_state, action, agent_id)
            case ActionType.FindServices:   
                next_state = self._execute_find_services_action(current_state, action, agent_id)
            case ActionType.FindData:
                next_state = self._execute_find_data_action(current_state, action, agent_id)
            case ActionType.ExploitService:
                next_state = self._execute_exploit_service_action(current_state, action, agent_id)
            case ActionType.ExfiltrateData:
                next_state = self._execute_exfiltrate_data_action(current_state, action, agent_id)
            case ActionType.BlockIP:
                next_state = self._execute_block_ip_action(current_state, action, agent_id)
            case _:
                raise ValueError(f"Unknown Action type or other error: '{action.type}'")
        return next_state
        
    def _record_false_positive(self, src_ip:IP, dst_ip:IP, agent_id:tuple)->bool:
        # only record false positive if the agent is benign
        if self.is_agent_benign(agent_id):
            # find agent(s) that created the rule
            src_host = src_ip
            dst_host = dst_ip
            if (src_host, dst_host) in self._agent_fw_rules:
                # check if this connection is actively blocked
                for author_agent in self._agent_fw_rules[(src_host, dst_host)]:
                    self.logger.info(f"Adding false positive for blocking {src_host} -> {dst_host} by {author_agent}")
                    if author_agent not in self._agent_false_positives:
                        self._agent_false_positives[author_agent] = 0
                    self._agent_false_positives[author_agent] += 1
            else:
                self.logger.debug(f"False positive for blocking {src_host} -> {dst_host} caused by the system configuration.")

    def _state_parts_deep_copy(self, current:GameState)->tuple:
        next_nets = copy.deepcopy(current.known_networks)
        next_known_h = copy.deepcopy(current.known_hosts)
        next_controlled_h = copy.deepcopy(current.controlled_hosts)
        next_services = copy.deepcopy(current.known_services)
        next_data = copy.deepcopy(current.known_data)
        next_blocked = copy.deepcopy(current.known_blocks)
        return next_nets, next_known_h, next_controlled_h, next_services, next_data, next_blocked

    def _firewall_check(self, src_ip:IP, dst_ip:IP)->bool:
        """Checks if firewall allows connection from 'src_ip to ''dst_ip'"""
        try:
            connection_allowed = dst_ip in self._firewall[src_ip]
        except KeyError:
            connection_allowed = False
        return connection_allowed

    def _execute_scan_network_action(self, current_state:GameState, action:Action, agent_id:tuple)->GameState:
        """
        Executes the ScanNetwork action in the environment
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data, next_blocked = self._state_parts_deep_copy(current_state)
        self.logger.debug(f"\t\tScanning {action.parameters['target_network']}")
        if "source_host" in action.parameters.keys() and action.parameters["source_host"] in current_state.controlled_hosts:
            new_ips = set()
            for ip in self._ip_to_hostname.keys(): #check if IP exists
                self.logger.debug(f"\t\tChecking if {ip} in {action.parameters['target_network']}")
                if str(ip) in netaddr.IPNetwork(str(action.parameters["target_network"])):
                    if self._firewall_check(action.parameters["source_host"], ip):
                        self.logger.debug(f"\t\t\tAdding {ip} to new_ips")
                        new_ips.add(ip)
                        self.update_log_file(next_data,action, ip)
                    else:
                        self._record_false_positive(action.parameters["source_host"], ip, agent_id)
                        self.logger.debug(f"\t\t\tConnection {action.parameters['source_host']} -> {ip} blocked by FW. Skipping")
            next_known_h = next_known_h.union(new_ips)
        else:
            self.logger.debug(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)

    def _execute_find_services_action(self, current_state:GameState, action:Action, agent_id:tuple)->GameState:
        """
        Executes the FindServices action in the environment
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data, next_blocked = self._state_parts_deep_copy(current_state)
        self.logger.debug(f"\t\tSearching for services in {action.parameters['target_host']}")
        if "source_host" in action.parameters.keys() and action.parameters["source_host"] in current_state.controlled_hosts:
            if self._firewall_check(action.parameters["source_host"], action.parameters['target_host']):
                found_services = self._get_services_from_host(action.parameters["target_host"], current_state.controlled_hosts)
                self.logger.debug(f"\t\t\tFound {len(found_services)}: {found_services}")
                if len(found_services) > 0:
                    next_services[action.parameters["target_host"]] = found_services

                    #if host was not known, add it to the known_hosts ONLY if there are some found services
                    if action.parameters["target_host"] not in next_known_h:
                        self.logger.debug(f"\t\tAdding {action.parameters['target_host']} to known_hosts")
                        next_known_h.add(action.parameters["target_host"])
                        next_nets = next_nets.union({net for net, values in self._networks.items() if action.parameters["target_host"] in values})
                # update logs
                self.update_log_file(next_data,action, action.parameters['target_host'])
            else:
                self._record_false_positive(action.parameters["source_host"], action.parameters["target_host"], agent_id)
                self.logger.debug(f"\t\t\tConnection {action.parameters['source_host']} -> {action.parameters['target_host']} blocked by FW. Skipping")
        else:
            self.logger.debug(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)
    
    def _execute_find_data_action(self, current:GameState, action:Action, agent_id:tuple)->GameState:
        """
        Executes the FindData action in the environment
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data, next_blocked = self._state_parts_deep_copy(current)
        self.logger.debug(f"\t\tSearching for data in {action.parameters['target_host']}")
        if "source_host" in action.parameters.keys() and action.parameters["source_host"] in current.controlled_hosts:
            if self._firewall_check(action.parameters["source_host"], action.parameters['target_host']):
                # update logs before getting the data so this action is listed there
                self.update_log_file(next_data,action, action.parameters['target_host'])
                new_data = self._get_data_in_host(action.parameters["target_host"], current.controlled_hosts)
                self.logger.debug(f"\t\t\t Found {len(new_data)}: {new_data}")
                if len(new_data) > 0:
                    if action.parameters["target_host"] not in next_data.keys():
                        next_data[action.parameters["target_host"]] = new_data
                    else:
                        next_data[action.parameters["target_host"]] = next_data[action.parameters["target_host"]].union(new_data)
                # ADD KNOWN FW BLOCKS
                new_blocks = self._get_known_blocks_in_host(action.parameters["target_host"], current.controlled_hosts)
                if len(new_blocks) > 0:
                    if action.parameters["target_host"] not in next_blocked.keys():
                        next_blocked[action.parameters["target_host"]] = new_blocks
                    else:
                        next_blocked[action.parameters["target_host"]] = next_blocked[action.parameters["target_host"]].union(new_blocks)
            else:
                self._record_false_positive(action.parameters["source_host"], action.parameters["target_host"], agent_id)
                self.logger.debug(f"\t\t\tConnection {action.parameters['source_host']} -> {action.parameters['target_host']} blocked by FW. Skipping")
        else:
            self.logger.debug(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)
    
    def _execute_exfiltrate_data_action(self, current_state:GameState, action:Action, agent_id:tuple)->GameState:
        """
        Executes the ExfiltrateData action in the environment
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data, next_blocked = self._state_parts_deep_copy(current_state)
        self.logger.info(f"\t\tAttempting to Exfiltrate {action.parameters['data']} from {action.parameters['source_host']} to {action.parameters['target_host']}")
        # Is the target host controlled?
        if action.parameters["target_host"] in current_state.controlled_hosts:
            self.logger.debug(f"\t\t\t {action.parameters['target_host']} is under-control: {current_state.controlled_hosts}")
            # Is the source host controlled?
            if action.parameters["source_host"] in current_state.controlled_hosts:
                self.logger.debug(f"\t\t\t {action.parameters['source_host']} is under-control: {current_state.controlled_hosts}")
                # Is the source host in the list of hosts we know data from? (this is to avoid the keyerror later in the if)
                # Does the current state for THIS source already know about this data?
                if self._firewall_check(action.parameters["source_host"], action.parameters['target_host']):
                    if action.parameters['source_host'] in current_state.known_data.keys() and action.parameters["data"] in current_state.known_data[action.parameters["source_host"]]:
                        # update logs
                        self.update_log_file(next_data,action, action.parameters['target_host'])
                        # Does the source host have any data?
                        if self._ip_to_hostname[action.parameters["source_host"]] in self._data.keys():
                            # Does the source host have this data?
                            if action.parameters["data"] in self._data[self._ip_to_hostname[action.parameters["source_host"]]]:
                                self.logger.debug("\t\t\t Data present in the source_host")
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
                                self.logger.debug("\t\t\tCan not exfiltrate. Source host does not have this data.")
                        else:
                            self.logger.debug("\t\t\tCan not exfiltrate. Source host does not have any data.")
                    else:
                        self.logger.debug("\t\t\tCan not exfiltrate. Agent did not find this data yet.")
                else:
                    self._record_false_positive(action.parameters["source_host"], action.parameters["target_host"], agent_id)
                    self.logger.debug(f"\t\t\tConnection {action.parameters['source_host']} -> {action.parameters['target_host']} blocked by FW. Skipping")
            else:
                self.logger.debug("\t\t\tCan not exfiltrate. Source host is not controlled.")
        else:
            self.logger.debug("\t\t\tCan not exfiltrate. Target host is not controlled.")
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)
    
    def _execute_exploit_service_action(self, current_state:GameState, action:Action, agent_id:tuple)->GameState:
        """
        Executes the ExploitService action in the environment
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data, next_blocked = self._state_parts_deep_copy(current_state)
        # We don't check if the target is a known_host because it can be a blind attempt to attack
        self.logger.info(f"\t\tAttempting to ExploitService in '{action.parameters['target_host']}':'{action.parameters['target_service']}'")
        if "source_host" in action.parameters.keys() and action.parameters["source_host"] in current_state.controlled_hosts:
            if action.parameters["target_host"] in self._ip_to_hostname: #is it existing IP?
                if self._firewall_check(action.parameters["source_host"], action.parameters['target_host']):
                    if self._ip_to_hostname[action.parameters["target_host"]] in self._services: #does it have any services?
                        if action.parameters["target_service"] in self._services[self._ip_to_hostname[action.parameters["target_host"]]]: #does it have the service in question?
                            if action.parameters["target_host"] in next_services: #does the agent know about any services this host have?
                                if action.parameters["target_service"] in next_services[action.parameters["target_host"]]:
                                    self.logger.debug("\t\t\tValid service")
                                    if action.parameters["target_host"] not in next_controlled_h:
                                        next_controlled_h.add(action.parameters["target_host"])
                                        self.logger.debug("\t\tAdding to controlled_hosts")
                                    new_networks = self._get_networks_from_host(action.parameters["target_host"])
                                    self.logger.debug(f"\t\t\tFound {len(new_networks)}: {new_networks}")
                                    next_nets = next_nets.union(new_networks)
                                else:
                                    self.logger.debug("\t\t\tCan not exploit. Agent does not know about target host selected service")
                            else:
                                self.logger.debug("\t\t\tCan not exploit. Agent does not know about target host having any service")
                        else:
                            self.logger.debug("\t\t\tCan not exploit. Target host does not the service that was attempted.")
                    else:
                        self.logger.debug("\t\t\tCan not exploit. Target host does not have any services.")
                    # update logs
                    self.update_log_file(next_data,action, action.parameters['target_host'])
                else:
                    self._record_false_positive(action.parameters["source_host"], action.parameters["target_host"], agent_id)
                    self.logger.debug(f"\t\t\tConnection {action.parameters['source_host']} -> {action.parameters['target_host']} blocked by FW. Skipping")
            else:
                self.logger.debug("\t\t\tCan not exploit. Target host does not exist.")
        else:
            self.logger.debug(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)
    
    def _execute_block_ip_action(self, current_state:GameState, action:Action, agent_id:tuple)->GameState:
        """
        Executes the BlockIP action 
        - The action has BlockIP("target_host": IP object, "source_host": IP object, "blocked_host": IP object)
        - The target host is the host where the blocking will be applied (the FW)
        - The source host is the host that the agent uses to connect to the target host. A host that must be controlled by the agent
        - The blocked host is the host that will be included in the FW list to be blocked.

        Logic:
        - Check if the agent controls the source host
        - Check if the agent controls the target host
        - Add the rule to the FW list
        - Update the state
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data, next_blocked = self._state_parts_deep_copy(current_state)
        # Is the src in the controlled hosts?
        if "source_host" in action.parameters.keys() and action.parameters["source_host"] in current_state.controlled_hosts:
            # Is the target in the controlled hosts?
            if "target_host" in action.parameters.keys() and action.parameters["target_host"] in current_state.controlled_hosts:
                # For now there is only one FW in the main router, but this should change in the future. 
                # This means we ignore the 'target_host' that would be the router where this is applied.
                if self._firewall_check(action.parameters["source_host"], action.parameters["target_host"]):
                    if action.parameters["target_host"] != action.parameters['blocked_host']:
                        self.logger.info(f"\t\tBlockConnection {action.parameters['target_host']} <-> {action.parameters['blocked_host']}")
                        # record which agent is adding the blocking rule
                        if (action.parameters["target_host"], action.parameters["blocked_host"]) not in self._agent_fw_rules:
                            self._agent_fw_rules[(action.parameters["target_host"], action.parameters["blocked_host"])] = set()
                        self._agent_fw_rules[(action.parameters["target_host"], action.parameters["blocked_host"])].add(agent_id)
                        # both directions are blocked
                        if (action.parameters["blocked_host"], action.parameters["target_host"]) not in self._agent_fw_rules:
                            self._agent_fw_rules[(action.parameters["blocked_host"], action.parameters["target_host"])] = set()
                        self._agent_fw_rules[(action.parameters["blocked_host"], action.parameters["target_host"])].add(agent_id)
                        try:
                            #remove connection target_host -> blocked_host
                            self._firewall[action.parameters["target_host"]].discard(action.parameters["blocked_host"])
                            self.logger.debug(f"\t\t\t Removed rule:'{action.parameters['target_host']}' -> {action.parameters['blocked_host']}")
                        except KeyError:
                            pass
                        try:
                            #remove blocked_host -> target_host
                            self._firewall[action.parameters["blocked_host"]].discard(action.parameters["target_host"])
                            self.logger.debug(f"\t\t\t Removed rule:'{action.parameters['blocked_host']}' -> {action.parameters['target_host']}")
                        except KeyError:
                            pass

                        #Update the FW_Rules visible to agents
                        if action.parameters["target_host"] not in  self._fw_blocks.keys():
                            self._fw_blocks[action.parameters["target_host"]] = set()
                        self._fw_blocks[action.parameters["target_host"]].add(action.parameters["blocked_host"])
                        if action.parameters["blocked_host"] not in  self._fw_blocks.keys():
                            self._fw_blocks[action.parameters["blocked_host"]] = set()
                        self._fw_blocks[action.parameters["blocked_host"]].add(action.parameters["target_host"])

                        # update the state
                        if action.parameters["target_host"] not in next_blocked.keys():
                            next_blocked[action.parameters["target_host"]] = set()
                        if action.parameters["blocked_host"] not in next_blocked.keys():
                            next_blocked[action.parameters["blocked_host"]] = set()
                        next_blocked[action.parameters["target_host"]].add(action.parameters["blocked_host"])           
                        next_blocked[action.parameters["blocked_host"]].add(action.parameters["target_host"])
                    else:
                        self.logger.debug(f"\t\t\t Cant block connection form :'{action.parameters['target_host']}' to '{action.parameters['blocked_host']}'")
                    # update logs
                    self.update_log_file(next_data,action, action.parameters['target_host'])
                else:
                    self._record_false_positive(action.parameters["source_host"], action.parameters["target_host"], agent_id)
                    self.logger.debug(f"\t\t\t Connection from '{action.parameters['source_host']}->'{action.parameters['target_host']} is blocked blocked by FW")
            else:
                self.logger.debug(f"\t\t\t Invalid target_host:'{action.parameters['target_host']}'")
        else:
            self.logger.debug(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)

    def _get_all_local_ips(self)->set:
        local_ips = set()
        for net, ips in self._networks.items():
            if netaddr.IPNetwork(str(net)).ip.is_private():
                for ip in ips:
                    local_ips.add(self._ip_mapping[ip])
        self.logger.info(f"\t\t\tLocal ips: {local_ips}")
        return local_ips
    
    def update_log_file(self, known_data:set, action, target_host:IP):
        hostaname = self._ip_to_hostname[target_host]
        self.logger.debug(f"Updating log file in host {hostaname}")
        try:
            current_log_file = list(filter(lambda x: x.owner == "system" and x.type == "log",self._data[hostaname]))[0]
            self._data[hostaname].discard(current_log_file)
            if current_log_file.size == 0:
                content = []
            else: 
                content = json.loads(current_log_file.content)
            content.append({'source_host': str(action.parameters["source_host"]), 'action_type': str(action.type)})
            new_content = json.dumps(content)
        except KeyError:
            self.logger.debug(f"\t\t\tLog not found in host {hostaname}. Creating new one.")
            new_content = [{'source_host': str(action.parameters["source_host"]), 'action_type': str(action.type)}]
            new_content = json.dumps(new_content)
        self._data[hostaname].add(Data(owner="system", id="logfile", type="log", size=len(new_content) , content= new_content))

    async def register_agent(self, agent_id, agent_role, agent_initial_view:dict, agent_win_condition_view:dict)->tuple[GameState, GameState]:
        start_game_state = self._create_state_from_view(agent_initial_view)
        goal_state = self._create_goal_state_from_view(agent_win_condition_view)
        return start_game_state, goal_state

    async def remove_agent(self, agent_id, agent_state)->bool:
        # No action is required
        return True
        
    async def step(self, agent_id, agent_state, action)->GameState:
        return self._execute_action(agent_state, action, agent_id)

    async def reset_agent(self, agent_id, agent_role, agent_initial_view:dict, agent_win_condition_view:dict)->tuple[GameState, GameState]:
       game_state = self._create_state_from_view(agent_initial_view)
       goal_state = self._create_goal_state_from_view(agent_win_condition_view)
       return game_state, goal_state    

    async def reset(self)->bool:
        """
        Function to reset the state of the game
        and prepare for a new episode
        """
        # write all steps in the episode replay buffer in the file
        self.logger.info('--- Reseting NSG Environment to its initial state ---')
        # change IPs if needed
        # This is done ONLY if it is (i) enabled in the task config and (ii) all agents requested it
        if self.task_config.get_use_dynamic_addresses():
            if all(self._randomize_topology_requests.values()):
                self.logger.info("All agents requested reset with randomized topology.")
                topology_reset_seed = None
                if len(set(self._randomize_topology_seed_requests.values())) != 0:
                    topology_reset_seed = list(set(self._randomize_topology_seed_requests.values()))[0]
                    self.logger.info(f"Using agreed seed {topology_reset_seed} for topology randomization.")
                else:
                    # No agreement on the seed, use None
                    topology_reset_seed = None
                    self.logger.info(f"No agreed seed for topology randomization. Using random seed.")
                self._randomize_topology_seed_requests.clear()
                self._randomize_topology_seed_requests.clear() 
                self._dynamic_ip_change(seed=topology_reset_seed)
            else:
                self.logger.info("Not all agents requested a topology randomization. Keeping the current one.")
        # reset self._data to orignal state
        self._data = copy.deepcopy(self._data_original)
        # reset self._data_content to orignal state
        self._data_content = copy.deepcopy(self._data_content_original)
        # reset all firewall related data structure
        self._firewall = copy.deepcopy(self._firewall_original)
        self._fw_blocks = {}
        self._agent_fw_rules = {}
        return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NetSecGame Coordinator Server Author: Ondrej Lukas ondrej.lukas@aic.fel.cvut.cz",
        usage="%(prog)s [options]",
    )
  
    parser.add_argument(
        "-l",
        "--debug_level",
        help="Define the debug level for the logs. DEBUG, INFO, WARNING, ERROR, CRITICAL",
        action="store",
        required=False,
        type=str,
        default="INFO",
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
        "-c",
        "--task_config",
        help="File with the task configuration",
        action="store",
        required=True,
        type=str,
        default="netsecenv_conf.yaml",
    )

    parser.add_argument(
        "-s",
        "--seed",
        help="Random seed for the environment",
        action="store",
        required=False,
        type=int,
        default=42,
    )

    args = parser.parse_args()
    print(args)
    # Set the logging
    log_filename = Path("logs/NSG_coordinator.log")
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

    game_server = NSGCoordinator(args.game_host, args.game_port, args.task_config, seed=args.seed)
    # Run it!
    game_server.run()
# Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz

import sys
import os
import logging
import argparse
import random
import numpy as np
import copy
from faker import Faker
from pathlib import Path
import netaddr


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from env.game_components import GameState, Action, ActionType, IP, Network, Data, Service
from coordinator import GameCoordinator
from cyst.api.configuration import NodeConfig, RouterConfig, ConnectionConfig, ExploitConfig, FirewallPolicy

from utils.utils import get_logging_level

class NSGCoordinator(GameCoordinator):

    def __init__(self, game_host, game_port, task_config:str, allowed_roles=["Attacker", "Defender", "Benign"], seed=42):
        super().__init__(game_host, game_port, service_host=None, service_port=None, allowed_roles=allowed_roles, task_config_file=task_config)

        # Internal data structure of the NSG
        self._ip_to_hostname = {} # Mapping of `IP`:`host_name`(str) of all nodes in the environment
        self._networks = {} # A `dict` of the networks present in the environment. Keys: `Network` objects, values `set` of `IP` objects.
        self._services = {} # Dict of all services in the environment. Keys: hostname (`str`), values: `set` of `Service` objetcs.
        self._data = {} # Dict of all services in the environment. Keys: hostname (`str`), values `set` of `Service` objetcs.
        self._firewall = {} # dict of all the allowed connections in the environment. Keys `IP` ,values: `set` of `IP` objects.
        self._fw_blocks = {}
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

    def _initialize(self)->None:
        # Load CYST configuration
        self._process_cyst_config(self._cyst_objects)
                # Check if dynamic network and ip adddresses are required
        if self._use_dynamic_ips:
            self.logger.info("Dynamic change of the IP and network addresses enabled")
            self._faker_object = Faker()
            Faker.seed(self._seed)  
        # store initial values for parts which are modified during the game
        self._data_original = copy.deepcopy(self._data)
        self._firewall_original = copy.deepcopy(self._firewall)
        self.logger.info("Environment initialization finished")

    def _create_state_from_view(self, view:dict, add_neighboring_nets:bool=True)->GameState:
        """
        Builds a GameState from given view.
        If there is a keyword 'random' used, it is replaced by a valid option at random.

        Currently, we artificially extend the knonw_networks with +- 1 in the third octet.
        """
        self.logger.info(f'Generating state from view:{view}')
        # re-map all networks based on current mapping in self._network_mapping
        known_networks = set([self._network_mapping[net] for net in  view["known_networks"]])
            
        controlled_hosts = set()
        # controlled_hosts
        for host in view['controlled_hosts']:
            if isinstance(host, IP):
                controlled_hosts.add(self._ip_mapping[host])
                self.logger.debug(f'\tThe attacker has control of host {self._ip_mapping[host]}.')
            elif host == 'random':
                # Random start
                self.logger.debug('\tAdding random starting position of agent')
                self.logger.debug(f'\t\tChoosing from {self.hosts_to_start}')
                selected = random.choice(self.hosts_to_start)
                controlled_hosts.add(selected)
                self.logger.debug(f'\t\tMaking agent start in {selected}')
            elif host == "all_local":
                # all local ips
                self.logger.debug('\t\tAdding all local hosts to agent')
                controlled_hosts = controlled_hosts.union(self._get_all_local_ips())
            else:
                self.logger.error(f"Unsupported value encountered in start_position['controlled_hosts']: {host}")
        # re-map all known based on current mapping in self._ip_mapping
        known_hosts = set([self._ip_mapping[ip] for ip in view["known_hosts"]])
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
                    if net_obj.ip.is_ipv4_private_use(): #TODO
                        known_networks.add(net)
                        net_obj.value += 256
                        if net_obj.ip.is_ipv4_private_use():
                            ip = Network(str(net_obj.ip), net_obj.prefixlen)
                            self.logger.debug(f'\tAdding {ip} to agent')
                            known_networks.add(ip)
                        net_obj.value -= 2*256
                        if net_obj.ip.is_ipv4_private_use():
                            ip = Network(str(net_obj.ip), net_obj.prefixlen)
                            self.logger.debug(f'\tAdding {ip} to agent')
                            known_networks.add(ip)
                        #return value back to the original
                        net_obj.value += 256
        known_services ={}
        for ip, service_list in view["known_services"]:
            known_services[self._ip_mapping[ip]] = service_list
        known_data = {}
        for ip, data_list in view["known_data"]:
            known_data[self._ip_mapping[ip]] = data_list
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
                        if node_obj.id not in self._data:
                            self._data[node_obj.id] = set()
                        datapoint = Data(data.owner, data.description)
                        self._data[node_obj.id].add(datapoint)
                        # add content
                        self._data_content[node_obj.id, datapoint.id] = f"Content of {datapoint.id}"
                except AttributeError:
                    pass
                    #service does not contain any data
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
        #create initial mapping
        self.logger.info("\tCreating initial mapping of IPs and Networks")
        for net in self._networks.keys():
            self._network_mapping[net] = net
        self.logger.info(f"\tintitial self._network_mapping: {self._network_mapping}")
        for ip in self._ip_to_hostname.keys():
            self._ip_mapping[ip] = ip
        self.logger.info(f"\tintitial self._ip_mapping: {self._ip_mapping}")
        self.logger.info("CYST configuration processed successfully")

    def _create_new_network_mapping(self)->tuple:
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
                    is_private_net_checks.append(new_net_addr.is_ipv4_private_use())
                    # store the new mapping
                    mapping_nets[private_nets_sorted[i]] = Network(str(new_net_addr), private_nets_sorted[i].mask)
                if False not in is_private_net_checks: # verify that ALL new networks are still in the private ranges
                    valid_valid_network_mapping = True
            except IndexError as e:
                self.logger.info(f"Dynamic address sampling failed, re-trying. {e}")
                counter_iter +=1
                if counter_iter > 10:
                    self.logger.error("Dynamic address failed more than 10 times - stopping.")
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
            # Always add random, in case random is selected for ips
            mapping_ips['random'] = 'random'
        self.logger.info(f"Mapping IPs done:{mapping_ips}")
        
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
        
        #update mappings stored in the environment
        for net, mapping in self._network_mapping.items():
            self._network_mapping[net] = mapping_nets[mapping]
        self.logger.debug(f"self._network_mapping: {self._network_mapping}")
        for ip, mapping in self._ip_mapping.items():
            self._ip_mapping[ip] = mapping_ips[mapping]
        self.logger.debug(f"self._ip_mapping: {self._ip_mapping}")
    
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
    
    def _execute_action(self, current_state:GameState, action:Action)-> GameState:
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
                next_state = self._execute_scan_network_action(current_state, action)
            case ActionType.FindServices:   
                next_state = self._execute_find_services_action(current_state, action)
            case ActionType.FindData:
                next_state = self._execute_find_data_action(current_state, action)
            case ActionType.ExploitService:
                next_state = self._execute_exploit_service_action(current_state, action)
            case ActionType.ExfiltrateData:
                next_state = self._execute_exfiltrate_data_action(current_state, action)
            case ActionType.BlockIP:
                next_state = self._execute_block_ip_action(current_state, action)
            case _:
                raise ValueError(f"Unknown Action type or other error: '{action.type}'")
        return next_state
        
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

    def _execute_scan_network_action(self, current_state:GameState, action:Action)->GameState:
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
                    else:
                        self.logger.debug(f"\t\t\tConnection {action.parameters['source_host']} -> {ip} blocked by FW. Skipping")
            next_known_h = next_known_h.union(new_ips)
        else:
            self.logger.debug(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)

    def _execute_find_services_action(self, current_state:GameState, action:Action)->GameState:
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
            else:
                self.logger.debug(f"\t\t\tConnection {action.parameters['source_host']} -> {action.parameters['target_host']} blocked by FW. Skipping")
        else:
            self.logger.debug(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)
    
    def _execute_find_data_action(self, current:GameState, action:Action)->GameState:
        """
        Executes the FindData action in the environment
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data, next_blocked = self._state_parts_deep_copy(current)
        self.logger.debug(f"\t\tSearching for data in {action.parameters['target_host']}")
        if "source_host" in action.parameters.keys() and action.parameters["source_host"] in current.controlled_hosts:
            if self._firewall_check(action.parameters["source_host"], action.parameters['target_host']):
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
                self.logger.debug(f"\t\t\tConnection {action.parameters['source_host']} -> {action.parameters['target_host']} blocked by FW. Skipping")
        else:
            self.logger.debug(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)
    
    def _execute_exfiltrate_data_action(self, current_state:GameState, action:Action)->GameState:
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
                    self.logger.debug(f"\t\t\tConnection {action.parameters['source_host']} -> {action.parameters['target_host']} blocked by FW. Skipping")
            else:
                self.logger.debug("\t\t\tCan not exfiltrate. Source host is not controlled.")
        else:
            self.logger.debug("\t\t\tCan not exfiltrate. Target host is not controlled.")
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)
    
    def _execute_exploit_service_action(self, current_state:GameState, action:Action)->GameState:
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
                else:
                    self.logger.debug(f"\t\t\tConnection {action.parameters['source_host']} -> {action.parameters['target_host']} blocked by FW. Skipping")
            else:
                self.logger.debug("\t\t\tCan not exploit. Target host does not exist.")
        else:
            self.logger.debug(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)
    
    def _execute_block_ip_action(self, current_state:GameState, action:Action)->GameState:
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
                else:
                    self.logger.debug(f"\t\t\t Connection from '{action.parameters['source_host']}->'{action.parameters['target_host']} is blocked blocked by FW")
            else:
                self.logger.debug(f"\t\t\t Invalid target_host:'{action.parameters['target_host']}'")
        else:
            self.logger.debug(f"\t\t\t Invalid source_host:'{action.parameters['source_host']}'")
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)

    def _get_all_local_ips(self)->set:
        local_ips = set()
        for net, ips in self._networks.items():
            if netaddr.IPNetwork(str(net)).ip.is_ipv4_private_use():
                for ip in ips:
                    local_ips.add(self._ip_mapping[ip])
        self.logger.info(f"\t\t\tLocal ips: {local_ips}")
        return local_ips
     
    async def register_agent(self, agent_id, agent_role, agent_initial_view)->GameState:
        if len(self._networks) == 0:
            self._initialize()
        game_state = self._create_state_from_view(agent_initial_view)
        return game_state
         
    async def remove_agent(self, agent_id, agent_state)->bool:
        # No action is required
        return True
        
    async def step(self, agent_id, agent_state, action)->GameState:
        return self._execute_action(agent_state, action)
    
    async def reset_agent(self, agent_id, agent_role, agent_initial_view)->GameState:
       game_state = self._create_state_from_view(agent_initial_view)
       return game_state

    async def reset(self)->bool:
        """
        Function to reset the state of the game
        and prepare for a new episode
        """
        # write all steps in the episode replay buffer in the file
        self.logger.info('--- Reseting NSG Environment to its initial state ---')
        # change IPs if needed
        if self.task_config.get_use_dynamic_addresses():
            self._create_new_network_mapping()
        # reset self._data to orignal state
        self._data = copy.deepcopy(self._data_original)
        # reset self._data_content to orignal state
        self._firewall = copy.deepcopy(self._firewall_original)
        self._fw_blocks = {}
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
        "-c",
        "--task_config",
        help="File with the task configuration",
        action="store",
        required=True,
        type=str,
        default="netsecenv_conf.yaml",
    )

    args = parser.parse_args()
    print(args)
    # Set the logging
    log_filename = Path("NSG_coordinator.log")
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
  
    game_server = NSGCoordinator(args.game_host, args.game_port, args.task_config)
    # Run it!
    game_server.run()
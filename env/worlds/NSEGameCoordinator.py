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
from game_components import GameState, Action, ActionType, GameStatus, IP, Network, Data
from coordinator_v3 import GameCoordinator
from cyst.api.configuration import NodeConfig, RouterConfig, ConnectionConfig, ExploitConfig, FirewallPolicy

from utils.utils import get_starting_position_from_cyst_config, get_logging_level

class NSGCoordinator(GameCoordinator):

    def __init__(self, game_host, game_port, service_host, service_port, world_type, allowed_roles=["Attacker", "Defender", "Benign"], seed=42):
        super().__init__(game_host, game_port, service_host, service_port, world_type, allowed_roles)

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

        # Check if dynamic network and ip adddresses are required
        if self.task_config.get_use_dynamic_addresses():
            self.logger.info("Dynamic change of the IP and network addresses enabled")
            self._faker_object = Faker()
            Faker.seed(seed)  

    def _initialize(self)->None:
        # Load CYST configuration
        self._process_cyst_config(self._cyst_objects)

        # store initial values for parts which are modified during the game
        self._data_original = copy.deepcopy(self._data)
        self._data_content_original = copy.deepcopy(self._data_content)
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
                net = gc.Network(net_ip,int(net_mask))
                ip = gc.IP(str(interface.ip))
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
                    self.hosts_to_start.append(gc.IP(str(interface.ip)))
                    continue

                if node_obj.id not in self._services:
                    self._services[node_obj.id] = []
                self._services[node_obj.id].append(gc.Service(service.name, "passive", service.version, service.local))
                #data
                self.logger.info(f"\t\t\tProcessing data in node '{node_obj.id}':'{service.name}' service")
                try:
                    for data in service.private_data:
                        if node_obj.id not in self._data:
                            self._data[node_obj.id] = set()
                        datapoint = gc.Data(data.owner, data.description)
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
                net = gc.Network(net_ip,int(net_mask))
                ip = gc.IP(str(interface.ip))
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

    async def register_agent(self, agent_id, agent_role, agent_initial_view)->GameState:
        if len(self._networks) == 0:
            self._initialize()
        game_state = self._create_state_from_view(agent_initial_view)
        return game_server
    
    async def remove_agent(self, agent_id, agent_state)->bool:
        # No action is required
        return True
        
    async def step(self, agent_addr, agent_state):
        raise NotImplementedError
    
    async def reset_agent(self, agent_id)->GameState:
        raise NotImplementedError

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
        self._data_content_original = copy.deepcopy(self._data_content_original)
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
        "-w",
        "--world_type",
        help="Define the world which is used as backed. Default NSE",
        action="store",
        required=False,
        type=str,
        default="cyst",
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
        "-sh",
        "--service_host",
        help="Host where to run the config server",
        action="store",
        required=False,
        type=str,
        default="127.0.0.1",
    )
    
    parser.add_argument(
        "-sp",
        "--service_port",
        help="Port where to listen for cyst config",
        action="store",
        required=False,
        type=int,
        default="9009",
    )


    args = parser.parse_args()
    print(args)
    # Set the logging
    log_filename = Path("CYST_coordinator.log")
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
  
    game_server = CYSTCoordinator(args.game_host, args.game_port, args.service_host , args.service_port, args.world_type)
    # Run it!
    game_server.run()
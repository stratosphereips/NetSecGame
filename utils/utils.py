# Utility functions for then env and for the agents
# Author: Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz
#import configparser
import yaml
import sys
from os import path
# This is used so the agent can see the environment and game components
sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))
from env.scenarios import scenario_configuration
from env.scenarios import smaller_scenario_configuration
from env.scenarios import tiny_scenario_configuration
from env.game_components import IP, Data, Network, Service
import netaddr
import logging

class ConfigParser():
    """
    Class to deal with the configuration file
    """
    def __init__(self, task_config_file):
        """
        Init the class 
        """
        self.logger = logging.getLogger('configparser')
        self.read_config_file(task_config_file)

    def read_config_file(self, conf_file_name):
        """
        reads configuration file
        """
        try:
            with open(conf_file_name) as source:
                self.config = yaml.safe_load(source)
        except (IOError, TypeError):
            self.logger.error(f'Error loading the configuration file')
            pass

    def read_env_action_data(self, action_name: str) -> dict:
        """
        Generic function to read the known data for any agent and goal of position
        """
        action_success_p = self.config['env']['actions'][action_name]['prob_success']
        action_detect_p = self.config['env']['actions'][action_name]['prob_detection']
        return action_success_p, action_detect_p

    def read_agents_known_data(self, type_agent: str, type_data: str) -> dict:
        """
        Generic function to read the known data for any agent and goal of position
        """
        known_data_conf = self.config['agents'][type_agent][type_data]['known_data']
        known_data = {}
        for ip, data in known_data_conf.items():
            try:
                # Check the host is a good ip
                _ = netaddr.IPAddress(ip)
                known_data_host = IP(ip)
                known_data[known_data_host] = set()
                for datum in data:
                    known_data_content_str_user =  datum[0]
                    known_data_content_str_data =  datum[1]
                    known_data_content = Data(known_data_content_str_user, known_data_content_str_data)
                    known_data[known_data_host].add(known_data_content)

            except (ValueError, netaddr.AddrFormatError):
                known_data = {}
        return known_data
    
    def read_agents_known_services(self, type_agent: str, type_data: str) -> dict:
        """
        Generic function to read the known services for any agent and goal of position
        """
        known_services_conf = self.config['agents'][type_agent][type_data]['known_services']
        known_services = {}
        for ip, data in known_services_conf.items():
            try:
                # Check the host is a good ip
                _ = netaddr.IPAddress(ip)
                known_services_host = IP(ip)

                name = data[0]
                type = data[1]
                version = data[2]
                is_local = data[3]

                known_services[known_services_host] = Service(name, type, version, is_local)

            except (ValueError, netaddr.AddrFormatError):
                known_services = {}
        return known_services

    def read_agents_known_networks(self, type_agent: str, type_data: str) -> dict:
        """
        Generic function to read the known networks for any agent and goal of position
        """
        known_networks_conf = self.config['agents'][type_agent][type_data]['known_networks']
        known_networks = set()
        for net in known_networks_conf:
            try:
                if '/' in net:
                    _ = netaddr.IPNetwork(net)
                    host_part, net_part = net.split('/')
                    known_networks.add(Network(host_part, int(net_part)))
            except (ValueError, TypeError, netaddr.AddrFormatError):
                self.logger(f'Configuration problem with the known networks')
        return known_networks

    def read_agents_known_hosts(self, type_agent: str, type_data: str) -> dict:
        """
        Generic function to read the known hosts for any agent and goal of position
        """
        known_hosts_conf = self.config['agents'][type_agent][type_data]['known_hosts']
        known_hosts = set()
        for ip in known_hosts_conf:
            try:
                _ = netaddr.IPAddress(ip)
                known_hosts.add(IP(ip))
            except (ValueError, netaddr.AddrFormatError):
                self.logger(f'Configuration problem with the known hosts')
        return known_hosts

    def read_agents_controlled_hosts(self, type_agent: str, type_data: str) -> dict:
        """
        Generic function to read the controlled hosts for any agent and goal of position
        """
        controlled_hosts_conf = self.config['agents'][type_agent][type_data]['controlled_hosts']
        controlled_hosts = set()
        for ip in controlled_hosts_conf:
            try:
                _ = netaddr.IPAddress(ip)
                controlled_hosts.add(IP(ip))
            except (ValueError, netaddr.AddrFormatError):
                if ip == 'random' :
                    # A random start ip was asked for
                    controlled_hosts.add('random')
                else:
                    self.logger(f'Configuration problem with the known hosts')
        return controlled_hosts

    def get_attacker_win_conditions(self):
        """
        Get the goal of the attacker 
        """
        # Read known nets
        known_networks = self.read_agents_known_networks('attacker', 'goal')

        # Read known hosts
        known_hosts = self.read_agents_known_hosts('attacker', 'goal')

        # Read controlled hosts
        controlled_hosts = self.read_agents_controlled_hosts('attacker', 'goal')

        # Goal services
        known_services = self.read_agents_known_services('attacker', 'goal')

        # Goal data
        known_data = self.read_agents_known_data('attacker', 'goal')

        attacker_goal = {}
        attacker_goal['known_networks'] = known_networks
        attacker_goal['controlled_hosts'] = controlled_hosts
        attacker_goal['known_hosts'] = known_hosts
        attacker_goal['known_data'] = known_data
        attacker_goal['known_services'] = known_services

        return attacker_goal
    
    def get_attacker_start_position(self):
        """
        Get the winning conditions of the attcker
        """
        # Read known nets
        known_networks = self.read_agents_known_networks('attacker', 'start_position')

        # Read known hosts
        known_hosts = self.read_agents_known_hosts('attacker', 'start_position')

        # Read controlled hosts
        controlled_hosts = self.read_agents_controlled_hosts('attacker', 'start_position')

        # Start services
        known_services = self.read_agents_known_services('attacker', 'start_position')

        # Start data
        known_data = self.read_agents_known_data('attacker', 'start_position')

        attacker_start_position = {}
        attacker_start_position['known_networks'] = known_networks
        attacker_start_position['controlled_hosts'] = controlled_hosts
        attacker_start_position['known_hosts'] = known_hosts
        attacker_start_position['known_data'] = known_data
        attacker_start_position['known_services'] = known_services

        return attacker_start_position

    def get_max_steps(self):
        """
        Get the max steps 
        """
        max_steps = self.config['env']['max_steps']
        return int(max_steps)

    def get_defender_placement(self):
        """
        Get the position of the defender
        """
        defender_placements = self.config['agents']['defender']['type']
        return defender_placements

    def get_scenario(self):
        """
        Get the scenario config object
        """
        scenario = self.config['env']['scenario']

        if scenario == "scenario1":
            cyst_config = scenario_configuration.configuration_objects
        elif scenario == "scenario1_small":
            cyst_config = smaller_scenario_configuration.configuration_objects
        elif scenario == "scenario1_tiny":
            cyst_config = tiny_scenario_configuration.configuration_objects
        else:
            cyst_config = 'scenario1'
        return cyst_config

    def get_seed(self, whom):
        """
        Get the seeds
        """
        seed = self.config[whom]['random_seed']
        return seed
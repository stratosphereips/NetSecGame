# Utility functions for then env and for the agents
import configparser
import sys
from os import path
# This is used so the agent can see the environment and game components
sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))
from env.scenarios import scenario_configuration
from env.scenarios import smaller_scenario_configuration
from env.scenarios import tiny_scenario_configuration
from env.game_components import IP, Data, Network, Service
import netaddr

class ConfigParser():
    """
    Class to deal with the configuration file
    """
    def __init__(self, task_config_file):
        """
        Init the class 
        """
        self.config = self.read_config_file(task_config_file)

    def read_config_file(self, conf_file_name):
        """
        reads configuration file
        """
        config = configparser.ConfigParser(interpolation=None, comment_prefixes='#')
        try:
            with open(conf_file_name) as source:
                config.read_file(source)
        except (IOError, TypeError):
            pass
        return config

    def read_configuration(self, section, name, default_value):
        """
        Read the configuration file 
        Other processes also access the configuration
        """
        try:
            return self.config.get(section, name)
        except (
            configparser.NoOptionError,
            configparser.NoSectionError,
            NameError,
            ValueError
        ):
            # There is a conf, but there is no option,
            # or no section or no configuration file specified
            return default_value
    
    def get_attacker_start_position(self):
        """
        Get the start position of the attacker 
        """
        # Read known nets
        known_networks = self.read_configuration('attacker.agent.goal', 'goal_known_networks', '')
        try:
            if '/' in known_networks:
                _ = netaddr.IPNetwork(known_networks)
                known_networks = set(Network(known_networks))
            else
                known_networks = set()
        except (ValueError, netaddr.AddrFormatError):
            known_networks = set()

        # Read known hosts. Only one for now
        known_hosts = self.read_configuration('attacker.agent.goal', 'goal_known_hosts', '')
        try:
            _ = netaddr.IPAddress(known_hosts)
            known_hosts = set(IP(known_hosts))
        except (ValueError, netaddr.AddrFormatError):
            known_hosts = set()

        # Read controlled hosts. For now we can have only one
        controlled_hosts = self.read_configuration('attacker.agent.goal', 'goal_controlled_hosts', '')
        try:
            _ = netaddr.IPAddress(controlled_hosts)
            controlled_hosts = set(IP(controlled_hosts))
        except (ValueError, netaddr.AddrFormatError):
            controlled_hosts = set()

        # Read services
        known_services_host_str = self.read_configuration('attacker.agent.goal', 'goal_known_services_host', '')
        try:
            # Check the host is a good ip
            _ = netaddr.IPAddress(known_services_host_str)
            known_services_host = IP(known_services_host_str)

            known_services_content_str = self.read_configuration('attacker.agent.goal', 'goal_known_services_str', '')
            name = known_services_content_str.split(',')[0]
            type = known_services_content_str.split(',')[1]
            version = known_services_content_str.split(',')[2]
            is_local = known_services_content_str.split(',')[3]

            known_services = {}
            known_services[known_services_host] = Service(name, type, version, is_local)

        except (ValueError, netaddr.AddrFormatError):
            known_services = {}

        # Read known data. Two components
        known_data_host_str = self.read_configuration('attacker.agent.goal', 'goal_known_data_host', '')
        try:
            # Check the host is a good ip
            _ = netaddr.IPAddress(known_data_host_str)
            known_data_host = IP(known_data_host_str)

            known_data_content_str = self.read_configuration('attacker.agent.goal', 'goal_known_data_str', '')
            known_data_content_str_user =  known_data_content_str.split(',')[0]
            known_data_content_str_data =  known_data_content_str.split(',')[1]
            known_data_content = Data(known_data_content_str_data, known_data_content_str_user)
            known_data = {}
            known_data[known_data_host] = known_data_content

        except (ValueError, netaddr.AddrFormatError):
            known_data = {}

        attacker_start_position = {}
        attacker_start_position['known_networks'] = known_networks
        attacker_start_position['controlled_hosts'] = controlled_hosts
        attacker_start_position['known_hosts'] = known_hosts
        attacker_start_position['known_data'] = known_data
        attacker_start_position['known_services'] = known_services

        return attacker_start_position
    
    def get_attacker_win_conditions(self):
        """
        Get the winning conditions of the attcker
        """
        # Read known nets
        known_networks = self.read_configuration('attacker.agent.startposition', 'pos_known_networks', '')
        try:
            if '/' in known_networks:
                _ = netaddr.IPNetwork(known_networks)
                known_networks = set(Network(known_networks))
            else:
                known_networks = set()
        except (ValueError, netaddr.AddrFormatError):
            known_networks = set()

        # Read known hosts. Only one for now
        known_hosts = self.read_configuration('attacker.agent.startposition', 'pos_known_hosts', '')
        try:
            _ = netaddr.IPAddress(known_hosts)
            known_hosts = set(IP(known_hosts))
        except (ValueError, netaddr.AddrFormatError):
            known_hosts = set()

        # Read controlled hosts. 
        do more
        controlled_hosts = self.read_configuration('attacker.agent.startposition', 'pos_controlled_hosts', '')
        try:
            _ = netaddr.IPAddress(controlled_hosts)
            controlled_hosts = set(IP(controlled_hosts))
        except (ValueError, netaddr.AddrFormatError):
            controlled_hosts = set()

        # Read services
        known_services_host_str = self.read_configuration('attacker.agent.startposition', 'pos_known_services_host', '')
        try:
            # Check the host is a good ip
            _ = netaddr.IPAddress(known_services_host_str)
            known_services_host = IP(known_services_host_str)

            known_services_content_str = self.read_configuration('attacker.agent.startposition', 'pos_known_services_str', '')
            name = known_services_content_str.split(',')[0]
            type = known_services_content_str.split(',')[1]
            version = known_services_content_str.split(',')[2]
            is_local = known_services_content_str.split(',')[3]

            known_services = {}
            known_services[known_services_host] = Service(name, type, version, is_local)

        except (ValueError, netaddr.AddrFormatError):
            known_services = {}

        # known data dict




    def get_max_steps(self):
        """
        Get the max steps 
        """
        max_steps = self.read_configuration('env', 'max_steps', 15)
        return int(max_steps)

    def get_defender_placement(self):
        """
        Get the position of the defender
        """
        defender_placements = self.read_configuration('defender.agent.type', 'type_of_defender', 'StochasticDefender')
        return defender_placements

    def get_scenario(self):
        """
        Get the scenario config object
        """
        scenario = self.read_configuration('env', 'scenario', 'scenario1')

        if scenario == "scenario1":
            cyst_config = scenario_configuration.configuration_objects
        elif scenario == "scenario1_small":
            cyst_config = smaller_scenario_configuration.configuration_objects
        elif scenario == "scenario1_tiny":
            cyst_config = tiny_scenario_configuration.configuration_objects
        else:
            cyst_config = 'scenario1'
        return cyst_config
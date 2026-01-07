# Config parser for NetSecGame Coordinator
# Author: Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz
# Author: Ondrej Lukas, ondrej.lukas@aic.fel.cvut.cz

import yaml
# This is used so the agent can see the environment and game components
import importlib
from AIDojoCoordinator.game_components import IP, Data, Network, Service, GameState, Action, Observation, ActionType
import netaddr
import logging
import os
import jsonlines
from random import randint
from cyst.api.configuration.network.node import NodeConfig
from  typing import Optional
from AIDojoCoordinator.utils.utils import get_file_hash, get_str_hash

class ConfigParser():
    """
    Class to deal with the configuration file of NetSecGame Coordinator
    Args:
        task_config_file (str|None): Path to the configuration file
        config_dict (dict|None): Dictionary with configuration data
    """
    def __init__(self, task_config_file:str|None=None, config_dict:dict|None=None):
        """
        Initializes the configuration parser. Required either path to a confgiuration file or a dict with configuraitons.
        """
        self.logger = logging.getLogger('configparser')
        if task_config_file:
            self.read_config_file(task_config_file)
        elif config_dict:
            self.config = config_dict
        else:
            self.logger.error("You must provide either the configuration file or a dictionary with the configuration!")

    def read_config_file(self, conf_file_name:str):
        """
        reads configuration file
        """
        try:
            with open(conf_file_name) as source:
                self.config = yaml.safe_load(source)
        except (IOError, TypeError) as e:
            self.logger.error(f'Error loading the configuration file{e}')
            pass
    
    def read_env_action_data(self, action_name: str) -> float:
        """
        Generic function to read the known data for any agent and goal of position
        """
        try:
            action_success_p = self.config['env']['actions'][action_name]['prob_success']
        except KeyError:
            action_success_p = 1
        return action_success_p

    def read_agents_known_data(self, type_agent: str, type_data: str) -> dict:
        """
        Generic function to read the known data for any agent and goal of position
        """
        known_data_conf = self.config['coordinator']['agents'][type_agent][type_data]['known_data']
        known_data = {}
        for ip, data in known_data_conf.items():
            try:
                # Check the host is a good ip
                _ = netaddr.IPAddress(ip)
                known_data_host = IP(ip)
                known_data[known_data_host] = set()
                for datum in data:
                    if not isinstance(datum, list) and datum.lower() == "random":
                        known_data[known_data_host].add("random")
                    else:
                        known_data_content_str_user =  datum[0]
                        known_data_content_str_data =  datum[1]
                        known_data_content = Data(known_data_content_str_user, known_data_content_str_data)
                        known_data[known_data_host].add(known_data_content)

            except (ValueError, netaddr.AddrFormatError):
                known_data = {}
        return known_data

    def read_agents_known_blocks(self, type_agent: str, type_data: str) -> dict:
        """
        Generic function to read the known blocks for any agent and goal of position
        """
        known_blocks_conf = self.config["coordinator"]['agents'][type_agent][type_data]['known_blocks']
        known_blocks = {}
        for target_host, block_list in known_blocks_conf.items():
            try:
                target_host  = IP(target_host)
            except ValueError:
                self.logger.error(f"Error when converting {target_host} to IP address object")
            if isinstance(block_list,list):
                known_blocks[target_host] = map(lambda x: IP(x), block_list)
            elif block_list == "all_attackers":
                known_blocks[target_host] = block_list
            else:
                raise ValueError(f"Unsupported value in 'known_blocks': {known_blocks_conf}")
        return known_blocks
    
    def read_agents_known_services(self, type_agent: str, type_data: str) -> dict:
        """
        Generic function to read the known services for any agent and goal of position
        """
        known_services_conf = self.config["coordinator"]['agents'][type_agent][type_data]['known_services']
        known_services = {}
        for ip, data in known_services_conf.items():
            try:
                # Check the host is a good ip
                _ = netaddr.IPAddress(ip)
                known_services_host = IP(ip)
                known_services[known_services_host] = []
                for service in data: # process each item in the list 
                    if isinstance(service, list): # Service defined as list
                        name = service[0]
                        type = service[1]
                        version = service[2]
                        is_local = service[3]
                        known_services[known_services_host].append(Service(name, type, version, is_local))
                    elif isinstance(service, str): # keyword 
                        if service.lower() == "random":
                            known_services[known_services_host].append("random")
                        else:
                            logging.warning(f"Unsupported values in agent known_services{ip}:{service}")
                    else:
                        logging.warning(f"Unsupported values in agent known_services{ip}:{service}")
            except (ValueError, netaddr.AddrFormatError):
                known_services = {}
        return known_services

    def read_agents_known_networks(self, type_agent: str, type_data: str) -> set:
        """
        Generic function to read the known networks for any agent and goal of position
        """
        known_networks_conf = self.config['coordinator']['agents'][type_agent][type_data]['known_networks']
        known_networks = set()
        for net in known_networks_conf:
            try:
                if '/' in net:
                    _ = netaddr.IPNetwork(net)
                    host_part, net_part = net.split('/')
                    known_networks.add(Network(host_part, int(net_part)))
            except (ValueError, TypeError, netaddr.AddrFormatError):
                self.logger.error('Configuration problem with the known networks')
        return known_networks

    def read_agents_known_hosts(self, type_agent: str, type_data: str) -> set:
        """
        Generic function to read the known hosts for any agent and goal of position
        """
        known_hosts_conf = self.config['coordinator']['agents'][type_agent][type_data]['known_hosts']
        known_hosts = set()
        for ip in known_hosts_conf:
            try:
                _ = netaddr.IPAddress(ip)
                known_hosts.add(IP(ip))
            except (ValueError, netaddr.AddrFormatError) as e :
                if ip == 'random':
                    # A random start ip was asked for
                    known_hosts.add('random')
                elif ip == 'all_local':
                    known_hosts.add('all_local')
                else:
                    self.logger.error(f'Configuration problem with the known hosts: {e}')
        return known_hosts

    def read_agents_controlled_hosts(self, type_agent: str, type_data: str) -> set:
        """
        Generic function to read the controlled hosts for any agent and goal of position
        """
        controlled_hosts_conf = self.config['coordinator']['agents'][type_agent][type_data]['controlled_hosts']
        controlled_hosts = set()
        for ip in controlled_hosts_conf:
            try:
                _ = netaddr.IPAddress(ip)
                controlled_hosts.add(IP(ip))
            except (ValueError, netaddr.AddrFormatError) as e:
                if ip == 'random' :
                    # A random start ip was asked for
                    controlled_hosts.add('random')
                elif ip == 'all_local':
                    controlled_hosts.add('all_local')
                else:
                    self.logger.error(f'Configuration problem with the controlled hosts: {e}')
        return controlled_hosts

    def get_player_win_conditions(self, type_of_player:str):
        """
        Get the goal of the player
        type_of_player: Can be 'attackers' or 'defenders' 
        """
        # Read known nets
        known_networks = self.read_agents_known_networks(type_of_player, 'goal')

        # Read known hosts
        known_hosts = self.read_agents_known_hosts(type_of_player, 'goal')

        # Read controlled hosts
        controlled_hosts = self.read_agents_controlled_hosts(type_of_player, 'goal')

        # Goal services
        known_services = self.read_agents_known_services(type_of_player, 'goal')

        # Read known blocks 
        known_blocks = self.read_agents_known_blocks(type_of_player, 'goal')

        # Goal data
        known_data = self.read_agents_known_data(type_of_player, 'goal')

        # Blocks
        known_blocks = self.read_agents_known_blocks(type_of_player, 'goal')

        player_goal = {}
        player_goal['known_networks'] = known_networks
        player_goal['controlled_hosts'] = controlled_hosts
        player_goal['known_hosts'] = known_hosts
        player_goal['known_data'] = known_data
        player_goal['known_services'] = known_services
        player_goal['known_blocks'] = known_blocks

        return player_goal
    
    def get_player_start_position(self, type_of_player:str):
        """
        Generate the starting position of an attacking agent
        type_of_player: Can be 'attackers' or 'defenders' 
        """
        # Read known nets
        known_networks = self.read_agents_known_networks(type_of_player, 'start_position')

        # Read known hosts
        known_hosts = self.read_agents_known_hosts(type_of_player, 'start_position')

        # Read controlled hosts
        controlled_hosts = self.read_agents_controlled_hosts(type_of_player, 'start_position')

        # Start services
        known_services = self.read_agents_known_services(type_of_player, 'start_position')

        # Start data
        known_data = self.read_agents_known_data(type_of_player, 'start_position')

        player_start_position = {}
        player_start_position['known_networks'] = known_networks
        player_start_position['controlled_hosts'] = controlled_hosts
        player_start_position['known_hosts'] = known_hosts
        player_start_position['known_data'] = known_data
        player_start_position['known_services'] = known_services

        return player_start_position

    def get_start_position(self, agent_role:str):
        match agent_role:
            case "Attacker":
                return self.get_player_start_position(agent_role)
            case "Defender":
                return self.get_player_start_position(agent_role)
            case "Benign":
                return {
                    'known_networks': set(),
                    'controlled_hosts': ["random", "random", "random"],
                    'known_hosts': set(),
                    'known_data': {},
                    'known_services': {}
                }
            case _:
                raise ValueError(f"Unsupported agent role: {agent_role}")
    
    def get_win_conditions(self, agent_role):
         match agent_role:
            case "Attacker":
                return self.get_player_win_conditions(agent_role)
            case "Defender":
                return self.get_player_win_conditions(agent_role)
            case "Benign":
                # create goal that is unreachable so we have infinite play by the benign agent
                return {
                    'known_networks': set(),
                    'controlled_hosts': set(),
                    'known_hosts': set(),
                    'known_data': {IP("1.1.1.1"): {Data(owner='User1', id='DataFromInternet', size=0, type='')}},
                    'known_services': {},
                    'known_blocks': {}
                }
            case _:
                raise ValueError(f"Unsupported agent role: {agent_role}")
    
    def get_max_steps(self, role=str)->Optional[int]:
        """
        Get the max steps based on agent's role
        """
        try:
            max_steps = int(self.config['coordinator']['agents'][role]["max_steps"])
        except KeyError:
            max_steps = None
            self.logger.warning(f"Item 'max_steps' not found in 'coordinator.agents.{role}'!. Setting value to default=None (no step limit)")
        except TypeError as e:
            max_steps = None
            self.logger.warning(f"Unsupported value in 'coordinator.agents.{role}.max_steps': {e}. Setting value to default=None (no step limit)")
        return max_steps

    def get_goal_description(self, agent_role)->str:
        """
        Get goal description per role
        """
        match agent_role:
            case "Attacker":
                try:
                    description = self.config['coordinator']['agents'][agent_role]["goal"]["description"]
                except KeyError:
                    description = ""
            case "Defender":
                try:
                    description = self.config['coordinator']['agents'][agent_role]["goal"]["description"]
                except KeyError:
                    description = ""
            case "Benign":
                description = ""
            case _:
                raise ValueError(f"Unsupported agent role: {agent_role}")
        return description

    def get_rewards(self, reward_names:list,  default_value=0)->dict:
        "Reads configuration for rewards for cases listed in 'rewards_names'"
        rewards = {}
        for name in reward_names:
            try:
                rewards[name] = self.config['env']["rewards"][name]
            except KeyError:
                self.logger.warning(f"No reward value found for '{name}'. Usinng default reward({name})={default_value}")
                rewards[name] = default_value
        return rewards

    def get_use_dynamic_addresses(self)->bool:
        """
        Reads if the IP and Network addresses should be dynamically changed.
        """
        try:
            use_dynamic_addresses = self.config['env']['use_dynamic_addresses']
        except KeyError:
            use_dynamic_addresses = False
        return bool(use_dynamic_addresses)

    def get_store_trajectories(self):
        """
        Read if the replay buffer should be stored in file
        """
        try:
            store_rb = self.config['env']['save_trajectories']
        except KeyError:
            # Option is not in the configuration - default to FALSE
            store_rb = False
        return store_rb
    
    def get_scenario(self):
        """
        Get the scenario config objects based on the configuration. Only import objects that are selected via importlib.
        """
        allowed_names = {
            "scenario1" : "AIDojoCoordinator.scenarios.scenario_configuration",
            "scenario1_small" : "AIDojoCoordinator.scenarios.smaller_scenario_configuration",
            "scenario1_tiny" : "AIDojoCoordinator.scenarios.tiny_scenario_configuration",
            "one_network": "AIDojoCoordinator.scenarios.one_net",
            "three_net_scenario": "AIDojoCoordinator.scenarios.three_net_scenario",
            "two_networks": "AIDojoCoordinator.scenarios.two_nets", # same as scenario1
            "two_networks_small": "AIDojoCoordinator.scenarios.two_nets_small", # same as scenario1_small
            "two_networks_tiny": "AIDojoCoordinator.scenarios.two_nets_tiny", # same as scenario1_small

        }
        scenario_name = self.config['env']['scenario']
        # make sure to validate the input
        if scenario_name not in allowed_names:
            raise ValueError(f"Unsupported scenario: {scenario_name}")
        
        # import the correct module
        module = importlib.import_module(allowed_names[scenario_name])
        return module.configuration_objects

    def get_seed(self, whom):
        """
        Get the seeds
        """
        seed = self.config[whom]['random_seed']
        if seed == 'random':
            seed = randint(0,100)
        return seed
    
    def get_randomize_goal_every_episode(self) -> bool:
        """
        Get if the randomization should be done only once or at the beginning of every episode
        """
        try:
            randomize_goal_every_episode = self.config["coordinator"]["agents"]["attackers"]["goal"]["is_any_part_of_goal_random"]
        except KeyError:
            # Option is not in the configuration - default to FALSE
            randomize_goal_every_episode = False
        return randomize_goal_every_episode
    
    def get_use_firewall(self)->bool:
        """
        Retrieves if the firewall functionality is allowed for netsecgame.
        Default: False
        """
        try:
            use_firewall = self.config['env']['use_firewall']
        except KeyError:
            use_firewall = False
        return use_firewall

    def get_use_global_defender(self)->bool:
        try:
            use_global_defender = self.config['env']['use_global_defender']
        except KeyError:
            use_global_defender = False
        return use_global_defender
    
    def get_required_num_players(self)->int:
        try:
            required_players = int(self.config['env']['required_players'])
        except KeyError:
            required_players = 1
        except ValueError:
            required_players = 1
        return required_players
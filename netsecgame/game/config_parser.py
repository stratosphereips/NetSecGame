# Config parser for NetSecGame Coordinator
# Author: Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz
# Author: Ondrej Lukas, ondrej.lukas@aic.fel.cvut.cz

import yaml
import netaddr
import logging
from random import randint
from typing import Optional, Dict, Any, List, Set, Union, Tuple, Iterable
from netsecgame.game_components import IP, Data, Network, Service, AgentRole
from netsecgame.game.scenarios import SCENARIO_REGISTRY

class ConfigParser():
    """
    Class to deal with the configuration file of NetSecGame Coordinator.

    Provides methods to read agent-specific and environment-wide configurations
    from YAML files or dictionaries.
    """
    def __init__(self, task_config_file:Optional[str]=None, config_dict:Optional[dict]=None)->None:
        """
        Initializes the configuration parser. Required either path to a configuration file or a dict with configurations.
        
        Args:
            task_config_file (Optional[str]): Path to the configuration file
            config_dict (Optional[dict]): Dictionary with configuration data

        Returns:
            None
        """
        self.logger = logging.getLogger('ConfigParser')
        if task_config_file:
            self.read_config_file(task_config_file)
        elif config_dict:
            self.config = config_dict
        else:
            self.logger.error("You must provide either the configuration file or a dictionary with the configuration!")

    def read_config_file(self, conf_file_name: str) -> None:
        """
        Reads the configuration from a YAML file.

        Args:
            conf_file_name (str): Path to the configuration file.

        Returns:
            None
        """
        try:
            with open(conf_file_name) as source:
                self.config = yaml.safe_load(source)
        except (IOError, TypeError) as e:
            self.logger.error(f'Error loading the configuration file{e}')
            pass
    
    def read_env_action_data(self, action_name: str) -> float:
        """
        Reads the success probability for a specific environment action.

        Args:
            action_name (str): The name of the action.

        Returns:
            float: The success probability (defaults to 1.0 if not found).
        """
        try:
            action_success_p = self.config['env']['actions'][action_name]['prob_success']
        except KeyError:
            action_success_p = 1
        return action_success_p

    def read_agents_known_data(self, type_agent: str, type_data: str) -> Dict[IP, Set[Union[Data, str]]]:
        """
        Reads the known data for a specific agent and category (goal/start_position).

        Args:
            type_agent (str): The role or type of the agent.
            type_data (str): The category of data (e.g., 'goal', 'start_position').

        Returns:
            Dict[IP, Set[Union[Data, str]]]: A mapping of IP addresses to sets of Data objects or 'random' keywords.
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

    def read_agents_known_blocks(self, type_agent: str, type_data: str) -> Dict[IP, Union[List[IP], str]]:
        """
        Reads the known firewall blocks for a specific agent and category.

        Args:
            type_agent (str): The role or type of the agent.
            type_data (str): The category of data.

        Returns:
            Dict[IP, Union[List[IP], str]]: A mapping of target IP addresses to blocked IPs or 'all_attackers'.
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
    
    def read_agents_known_services(self, type_agent: str, type_data: str) -> Dict[IP, List[Union[Service, str]]]:
        """
        Reads the known services for a specific agent and category.

        Args:
            type_agent (str): The role or type of the agent.
            type_data (str): The category of data.

        Returns:
            Dict[IP, List[Union[Service, str]]]: A mapping of IP addresses to lists of Service objects or 'random' keywords.
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

    def read_agents_known_networks(self, type_agent: str, type_data: str) -> Set[Network]:
        """
        Reads the known networks for a specific agent and category.

        Args:
            type_agent (str): The role or type of the agent.
            type_data (str): The category of data.

        Returns:
            Set[Network]: A set of known Network objects.
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

    def read_agents_known_hosts(self, type_agent: str, type_data: str) -> Set[Union[IP, str]]:
        """
        Reads the known hosts for a specific agent and category.

        Args:
            type_agent (str): The role or type of the agent.
            type_data (str): The category of data.

        Returns:
            Set[Union[IP, str]]: A set of host IP objects or keywords ('random', 'all_local').
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

    def read_agents_controlled_hosts(self, type_agent: str, type_data: str) -> Set[Union[IP, str]]:
        """
        Reads the controlled hosts for a specific agent and category.

        Args:
            type_agent (str): The role or type of the agent.
            type_data (str): The category of data.

        Returns:
            Set[Union[IP, str]]: A set of controlled host IPs or keywords ('random', 'all_local').
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

    def get_player_win_conditions(self, type_of_player: str) -> Dict[str, Any]:
        """
        Retrieves the win conditions for a specific player type.

        Args:
            type_of_player (str): The player type (e.g., 'attackers', 'defenders').

        Returns:
            Dict[str, Any]: A dictionary containing goal configurations (nets, hosts, etc.).
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
    
    def get_player_start_position(self, type_of_player: str) -> Dict[str, Any]:
        """
        Generates the starting position for a specific player type.

        Args:
            type_of_player (str): The player type (e.g., 'attackers', 'defenders').

        Returns:
            Dict[str, Any]: A dictionary containing starting configuration.
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

    def get_start_position(self, agent_role: str) -> Dict[str, Any]:
        """
        Returns the starting position based on the agent's role.

        Args:
            agent_role (str): The role of the agent ('Attacker', 'Defender', 'Benign').

        Returns:
            Dict[str, Any]: The starting state configuration.
        """
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
    
    def get_win_conditions(self, agent_role: str) -> Dict[str, Any]:
        """
        Returns the win conditions based on the agent's role.

        Args:
            agent_role (str): The role of the agent.

        Returns:
            Dict[str, Any]: The win conditions configuration.
        """
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
    
    def get_max_steps(self, role: str) -> Optional[int]:
        """
        Retrieves the maximum steps allowed for a specific role.

        Args:
            role (str): The role of the agent.

        Returns:
            Optional[int]: The maximum steps, or None if no limit is set.
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

    def get_goal_description(self, agent_role: str) -> str:
        """
        Retrieves the textual goal description for a specific role.

        Args:
            agent_role (str): The role of the agent.

        Returns:
            str: The goal description string.
        """
        match agent_role:
            case "Attacker":
                try:
                    description = self.config['coordinator']['agents'][agent_role]["goal"]["description"]
                    self.validate_goal_description(agent_role, description)
                except KeyError:
                    description = ""
            case "Defender":
                try:
                    description = self.config['coordinator']['agents'][agent_role]["goal"]["description"]
                    self.validate_goal_description(agent_role, description)
                except KeyError:
                    description = ""
            case "Benign":
                description = ""
            case _:
                raise ValueError(f"Unsupported agent role: {agent_role}")
        return description

    def validate_goal_description(self, agent_role: str, description: str):
        """
        Warns if the goal description misses key targets from the actual win conditions.
        """
        if not description:
            return  # No description to validate
            
        description_lower = description.lower()
        missing_elements = []

        try:
            win_conditions = self.config['coordinator']['agents'][agent_role]['goal']
        except KeyError:
            return

        # Check controlled hosts
        for host in win_conditions.get('controlled_hosts', []):
            if str(host) not in description_lower and str(host) != "random":
                missing_elements.append(f"Controlled Host: {host}")
                
        # Check known data targets
        for host, data_set in win_conditions.get('known_data', {}).items():
            if str(host) not in description_lower and str(host) != "random":
                # Only require host IP if it isn't "random"
                missing_elements.append(f"Target Host IP defined for data: {host}")

        if missing_elements:
            self.logger.warning(
                f"[{agent_role}] Goal description '{description}' might be missing some actual win condition targets: {missing_elements}"
            )

    def get_rewards(self, reward_names: List[str], default_value: int = 0) -> Dict[str, Any]:
        """
        Reads configuration for rewards for specific categories.

        Args:
            reward_names (List[str]): List of reward keys to read from the configuration.
            default_value (int): Default reward value if not specified. Defaults to 0.

        Returns:
            Dict[str, Any]: A mapping of reward names to their values.
        """
        rewards = {}
        for name in reward_names:
            try:
                rewards[name] = self.config['env']["rewards"][name]
            except KeyError:
                self.logger.warning(f"No reward value found for '{name}'. Usinng default reward({name})={default_value}")
                rewards[name] = default_value
        return rewards

    def get_use_dynamic_addresses(self, default_value: bool = False)->bool:
        """
        Reads if the IP and Network addresses should be dynamically changed.
        """
        try:
            use_dynamic_addresses = self.config['env']['use_dynamic_addresses']
        except KeyError:
            use_dynamic_addresses = default_value
        return bool(use_dynamic_addresses)

    def get_store_trajectories(self, default_value: bool = False):
        """
        Read if the replay buffer should be stored in file
        """
        try:
            store_trajectories = self.config['env']['save_trajectories']
        except KeyError:
            # Option is not in the configuration - default to FALSE
            store_trajectories = default_value
        return store_trajectories
    
    def get_scenario(self) -> Any:
        """
        Retrieves the scenario configuration objects.

        Returns:
            Any: The scenario configuration (usually a list of NodeConfig, etc.).
        """
        scenario_name = self.config['env']['scenario']
        # make sure to validate the input
        if scenario_name not in SCENARIO_REGISTRY:
            raise ValueError(
                f"Unsupported scenario: {scenario_name}. "
                f"Available scenarios: {list(SCENARIO_REGISTRY.keys())}"
            )
        
        return SCENARIO_REGISTRY[scenario_name]

    def get_seed(self, whom: str) -> int:
        """
        Retrieves the random seed for a specific component.

        Args:
            whom (str): The component name (e.g., 'coordinator', 'env').

        Returns:
            int: The random seed.
        """
        seed = self.config[whom]['random_seed']
        if seed == 'random':
            seed = randint(0,100)
        return seed
    
    def get_randomize_goal_every_episode(self, default_value: bool = False) -> bool:
        """
        Get if the randomization should be done only once or at the beginning of every episode
        """
        # TODO Remove in future
        try:
            randomize_goal_every_episode = self.config["coordinator"]["agents"]["attackers"]["goal"]["is_any_part_of_goal_random"]
        except KeyError:
            # Option is not in the configuration - default to FALSE
            randomize_goal_every_episode = default_value
        raise DeprecationWarning("This function is deprecated.")
        return randomize_goal_every_episode
    
    def get_use_firewall(self, default_value: bool = False) -> bool:
        """
        Checks if firewall functionality is enabled.

        Args:
            default_value (bool): Default value if not found. Defaults to False.

        Returns:
            bool: True if firewalls should be used, False otherwise.
        """
        try:
            use_firewall = self.config['env']['use_firewall']   
        except KeyError:
            use_firewall = default_value
        return use_firewall

    def get_use_global_defender(self, default_value: bool = False) -> bool:
        """
        Checks if the global defender is enabled.

        Args:
            default_value (bool): Default value if not found. Defaults to False.

        Returns:
            bool: True if global defender should be used, False otherwise.
        """
        try:
            use_global_defender = self.config['env']['use_global_defender']
        except KeyError:
            use_global_defender = default_value
        return use_global_defender
    
    def get_required_num_players(self, default_value: int = 1) -> int:
        """
        Retrieves the required number of players.

        Args:
            default_value (int): Default number of players. Defaults to 1.

        Returns:
            int: The required number of players.
        """
        try:
            required_players = int(self.config['env']['required_players'])
        except KeyError:
            required_players = default_value
        except ValueError:
            required_players = default_value
        return required_players
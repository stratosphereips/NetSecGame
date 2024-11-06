# Utility functions for then env and for the agents
# Author: Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz
# Author: Ondrej Lukas, ondrej.lukas@aic.fel.cvut.cz
#import configparser
import yaml
import sys
from os import path
# This is used so the agent can see the environment and game components
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
from env.scenarios import scenario_configuration
from env.scenarios import smaller_scenario_configuration
from env.scenarios import tiny_scenario_configuration
from env.scenarios import three_net_scenario
from env.game_components import IP, Data, Network, Service, GameState, Action, Observation
import netaddr
import logging
import csv
from random import randint
import json
import hashlib

def get_file_hash(filepath, hash_func='sha256', chunk_size=4096):
    """
    Computes hash of a given file.
    """
    hash_algorithm = hashlib.new(hash_func)
    with open(filepath, 'rb') as file:
        chunk = file.read(chunk_size)
        while chunk:
            hash_algorithm.update(chunk)
            chunk = file.read(chunk_size)
    return hash_algorithm.hexdigest()

def read_replay_buffer_from_csv(csvfile:str)->list:
    """
    Function to read steps from a CSV file
     and restore the objects in the replay buffer.

     expected colums in the csv:
     state_t0, action_t0, reward_t1, state_t1, done_t1
    """
    buffer = []
    try:
        with open(csvfile, 'r') as f_object:
            csv_reader = csv.reader(f_object, delimiter=';')
            for [s_t, a_t, r, s_t1 , done] in csv_reader:
                buffer.append((GameState.from_json(s_t), Action.from_json(a_t), r, GameState.from_json(s_t1), done))
    except FileNotFoundError:
        # There was no buffer
        pass
    return buffer

def store_replay_buffer_in_csv(replay_buffer:list, filename:str, delimiter:str=";")->None:
    """
    Function to store steps from a replay buffer in CSV file.
     Expected format of replay buffer items:
     (state_t0:GameState, action_t0:Action, reward_t1:float, state_t1:GameState, done_t1:bool)
    """
    with open(filename, 'a') as f_object:
        writer_object = csv.writer(f_object, delimiter=delimiter)
        for (s_t, a_t, r, s_t1, done) in replay_buffer:
            writer_object.writerow([s_t.as_json(), a_t.as_json(), r, s_t1.as_json(), done])

def state_as_ordered_string(state:GameState)->str:
    ret = ""
    ret += f"nets:[{','.join([str(x) for x in sorted(state.known_networks)])}],"
    ret += f"hosts:[{','.join([str(x) for x in sorted(state.known_hosts)])}],"
    ret += f"controlled:[{','.join([str(x) for x in sorted(state.controlled_hosts)])}],"
    ret += "services:{"
    for host in sorted(state.known_services.keys()):
        ret += f"{host}:[{','.join([str(x) for x in sorted(state.known_services[host])])}]"
    ret += "},data:{"
    for host in sorted(state.known_data.keys()):
        ret += f"{host}:[{','.join([str(x) for x in sorted(state.known_data[host])])}]"
    ret += "}, blocks:{"
    for host in sorted(state.known_blocks.keys()):
        ret += f"{host}:[{','.join([str(x) for x in sorted(state.known_blocks[host])])}]"
    ret += "}"
    return ret

def observation_to_str(observation:Observation)-> str:
    """
    Generates JSON string representation of a given Observation object.
    """
    state_str = observation.state.as_json()
    observation_dict = {
        'state': state_str,
        'reward': observation.reward,
        'end': observation.end,
        'info': dict(observation.info)
    }
    try:
        observation_str = json.dumps(observation_dict)
        return observation_str
    except Exception as e:
        print(f"Error in encoding observation '{observation}' to JSON string: {e}")
        raise e

def observation_as_dict(observation:Observation)->dict:
    """
    Generates dict string representation of a given Observation object.
    """
    observation_dict = {
        'state': observation.state.as_dict,
        'reward': observation.reward,
        'end': observation.end,
        'info': observation.info
    }
    return observation_dict

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
        except (IOError, TypeError) as e:
            self.logger.error(f'Error loading the configuration file{e}')
            pass
    
    def read_env_action_data(self, action_name: str) -> dict:
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
                        known_data[known_data_host] = "random"
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
            # try:
            #     # Check the host is a good ip
            #     _ = netaddr.IPAddress(target_host)
            #     target_host_ip = IP(target_host)
            #     for known_blocked_host in dict_blocked_hosts.values():
            #         known_blocked_host_ip = IP(known_blocked_host)
            #         known_blocks[target_host_ip].append(known_blocked_host_ip)
            # except (ValueError, netaddr.AddrFormatError):
            #     if target_host.lower() == "all_routers":
            #         known_blocks["all_routers"] = dict_blocked_hosts
            # except (ValueError):
            #     known_blocks = {}
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
                if data.lower() == "random":
                    known_services[known_services_host] = "random"
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
        known_networks_conf = self.config['coordinator']['agents'][type_agent][type_data]['known_networks']
        known_networks = set()
        for net in known_networks_conf:
            try:
                if '/' in net:
                    _ = netaddr.IPNetwork(net)
                    host_part, net_part = net.split('/')
                    known_networks.add(Network(host_part, int(net_part)))
            except (ValueError, TypeError, netaddr.AddrFormatError):
                self.logger('Configuration problem with the known networks')
        return known_networks

    def read_agents_known_hosts(self, type_agent: str, type_data: str) -> dict:
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

    def read_agents_controlled_hosts(self, type_agent: str, type_data: str) -> dict:
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

    def get_player_win_conditions(self, type_of_player):
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
    
    def get_player_start_position(self, type_of_player):
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

    def get_start_position(self, agent_role):
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
    
    def get_max_steps(self, role=str)->int:
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


    def get_goal_description(self, agent_role)->dict:
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
       

    def get_goal_reward(self)->float:
        """
        Reads  what is the reward for reaching the goal.
        default: 100
        """
        try:
            goal_reward = self.config['env']['goal_reward']
            return float(goal_reward)
        except KeyError:
            return 100
        except ValueError:
            return 100
    
    def get_detection_reward(self)->float:
        """
        Reads what is the reward for detection.
        default: -50
        """
        try:
            detection_reward = self.config['env']['detection_reward']
            return float(detection_reward)
        except KeyError:
            return -50
        except ValueError:
            return -50
    
    def get_step_reward(self)->float:
        """
        Reads what is the reward for detection.
        default: -1
        """
        try:
            step_reward = self.config['env']['step_reward']
            return float(step_reward)
        except KeyError:
            return -1
        except ValueError:
            return -1

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
        Get the scenario config object
        """
        scenario = self.config['env']['scenario']

        if scenario == "scenario1":
            cyst_config = scenario_configuration.configuration_objects
        elif scenario == "scenario1_small":
            cyst_config = smaller_scenario_configuration.configuration_objects
        elif scenario == "scenario1_tiny":
            cyst_config = tiny_scenario_configuration.configuration_objects
        elif scenario == "three_nets":
            cyst_config = three_net_scenario.configuration_objects
        else:
            cyst_config = 'scenario1'
        return cyst_config

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
            use_firewall = self.config['env']['use_global_defender']
        except KeyError:
            use_firewall = False
        return use_firewall
    
def get_logging_level(debug_level):
    """
    Configure logging level based on the provided debug_level string.
    """
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    
    level = log_levels.get(debug_level.upper(), logging.ERROR)
    return level

if __name__ == "__main__":
    state = GameState(known_networks={Network("1.1.1.1", 24),Network("1.1.1.2", 24)},
            known_hosts={IP("192.168.1.2"), IP("192.168.1.3")}, controlled_hosts={IP("192.168.1.2")},
            known_services={IP("192.168.1.3"):{Service("service1", "public", "1.01", True)}},
            known_data={IP("192.168.1.3"):{Data("ChuckNorris", "data1"), Data("ChuckNorris", "data2")},
                        IP("192.168.1.2"):{Data("McGiver", "data2")}})
    
    print(state_as_ordered_string(state))
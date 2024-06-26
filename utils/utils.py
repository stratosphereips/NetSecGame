# Utility functions for then env and for the agents
# Author: Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz
#import configparser
import yaml
import sys
from os import path
# This is used so the agent can see the environment and game components
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
from env.scenarios import scenario_configuration
from env.scenarios import smaller_scenario_configuration
from env.scenarios import tiny_scenario_configuration
from env.game_components import IP, Data, Network, Service, GameState, Action, ActionType, Observation
import netaddr
import logging
import csv
from random import randint
import json

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
    
    def read_defender_detection_prob(self, action_name: str) -> dict:
        if self.config["coordinator"]["agents"]["defenders"]["type"] in ["StochasticWithThreshold", "StochasticDefender"]:
            action_detect_p = self.config["coordinator"]["agents"]["defenders"]["action_detetection_prob"][action_name]
        else:
            action_detect_p = 0
        return action_detect_p  

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
            except (ValueError, netaddr.AddrFormatError):
                self.logger('Configuration problem with the known hosts')
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
            except (ValueError, netaddr.AddrFormatError):
                if ip == 'random' :
                    # A random start ip was asked for
                    controlled_hosts.add('random')
                else:
                    self.logger('Configuration problem with the known hosts')
        return controlled_hosts

    
    def get_attackers_win_conditions(self):
        """
        Get the goal of the attacker 
        """
        # Read known nets
        known_networks = self.read_agents_known_networks('attackers', 'goal')

        # Read known hosts
        known_hosts = self.read_agents_known_hosts('attackers', 'goal')

        # Read controlled hosts
        controlled_hosts = self.read_agents_controlled_hosts('attackers', 'goal')

        # Goal services
        known_services = self.read_agents_known_services('attackers', 'goal')

        # Goal data
        known_data = self.read_agents_known_data('attackers', 'goal')

        attackers_goal = {}
        attackers_goal['known_networks'] = known_networks
        attackers_goal['controlled_hosts'] = controlled_hosts
        attackers_goal['known_hosts'] = known_hosts
        attackers_goal['known_data'] = known_data
        attackers_goal['known_services'] = known_services

        return attackers_goal
    
    def get_attackers_start_position(self):
        """
        Generate the starting position of an attacking agent
        """
        # Read known nets
        known_networks = self.read_agents_known_networks('attackers', 'start_position')

        # Read known hosts
        known_hosts = self.read_agents_known_hosts('attackers', 'start_position')

        # Read controlled hosts
        controlled_hosts = self.read_agents_controlled_hosts('attackers', 'start_position')

        # Start services
        known_services = self.read_agents_known_services('attackers', 'start_position')

        # Start data
        known_data = self.read_agents_known_data('attackers', 'start_position')

        attackers_start_position = {}
        attackers_start_position['known_networks'] = known_networks
        attackers_start_position['controlled_hosts'] = controlled_hosts
        attackers_start_position['known_hosts'] = known_hosts
        attackers_start_position['known_data'] = known_data
        attackers_start_position['known_services'] = known_services

        return attackers_start_position

    def get_start_position(self, agent_role):
        match agent_role:
            case "Attacker":
                return self.get_attackers_start_position()
            case "Defender":
                return {}
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
                return self.get_attackers_win_conditions()
            case "Defender":
                return {}
            case "Benign":
                # create goal that is unreachable so we have infinite play by the benign agent
                return {
                    'known_networks': set(),
                    'controlled_hosts': set(),
                    'known_hosts': set(),
                    'known_data': {IP("1.1.1.1"): {Data(owner='User1', id='DataFromInternet', size=0, type='')}},
                    'known_services': {}
                }
            case _:
                raise ValueError(f"Unsupported agent role: {agent_role}")
    def get_max_steps(self):
        """
        Get the max steps 
        """
        max_steps = self.config['env']['max_steps']
        return int(max_steps)


    def get_goal_description(self, agent_role)->dict:
        """
        Get goal description per role
        """
        match agent_role:
            case "Attacker":
                try:
                    description = self.config['coordinator']['agents']["attackers"]["goal"]["description"]
                except KeyError:
                    description = ""
            case "Defender":
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

    def get_store_replay_buffer(self):
        """
        Read if the replay buffer should be stored in file
        """
        try:
            store_rb = self.config['env']['store_replay_buffer']
        except KeyError:
            # Option is not in the configuration - default to FALSE
            store_rb = False
        return store_rb
    
    def get_defender_type(self):
        """
        Get the type of the defender
        """
        try:
            defender_placements = self.config["coordinator"]['agents']['defenders']['type']
        except KeyError:
            # Option is not in the configuration - default to no defender present
            defender_placements = "NoDefender"
        return defender_placements
    
    def get_defender_tw_size(self):
        tw_size = self.config["coordinator"]['agents']['defenders']['tw_size']
        return tw_size
    
    def get_defender_thresholds(self):
        """Function to read thresholds for stochastic defender with thresholds"""
        thresholds = {}
        config_thresholds = self.config["coordinator"]['agents']['defenders']["thresholds"]
        # ScanNetwork
        thresholds[ActionType.ScanNetwork] = {"consecutive_actions": config_thresholds["scan_network"]["consecutive_actions"]}
        thresholds[ActionType.ScanNetwork]["tw_ratio"] = config_thresholds["scan_network"]["tw_ratio"]
        # FindServices
        thresholds[ActionType.FindServices] = {"consecutive_actions": config_thresholds["find_services"]["consecutive_actions"]}
        thresholds[ActionType.FindServices]["tw_ratio"] = config_thresholds["find_services"]["tw_ratio"]
        # FindData
        thresholds[ActionType.FindData] = {"repeated_actions_episode": config_thresholds["find_data"]["repeated_actions_episode"]}
        thresholds[ActionType.FindData]["tw_ratio"] = config_thresholds["find_data"]["tw_ratio"]
        # ExploitService
        thresholds[ActionType.ExploitService] = {"repeated_actions_episode": config_thresholds["exploit_service"]["repeated_actions_episode"]}
        thresholds[ActionType.ExploitService]["tw_ratio"] = config_thresholds["exploit_service"]["tw_ratio"]
        # ExfiltrateData
        thresholds[ActionType.ExfiltrateData] = {"consecutive_actions": config_thresholds["exfiltrate_data"]["consecutive_actions"]}
        thresholds[ActionType.ExfiltrateData]["tw_ratio"] = config_thresholds["exfiltrate_data"]["tw_ratio"]
        return thresholds

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
# Author: Ondrej Lukas, ondrej.lukas@aic.cvut.cz
# This agent allows to manually play the Network Security Game
import sys
import argparse
import logging
import random
from termcolor import colored
from os import path
import os
# This is used so the agent can see the environment and game components
sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

from env.network_security_game import NetworkSecurityEnvironment
from env.game_components import Network, IP
from env.game_components import ActionType, Action, GameState, Observation


class InteractiveAgent:
    """
    Author: Ondrej Lukas, ondrej.lukas@aic.cvut.cz
    This agent allows to manually play the Network Security Game

    """

    def __init__(self, env)->None:
        self._env = env

    def move(self, observation: Observation)->Action:
        """
        Perform a move of the agent by
        - Selecting the action
        - Selecting the parameters
        - Returning the actions with parameters
        - Returns False if no action could be selected
        """
        # Get Action type to play
        action_type = get_action_type_from_stdin()
        if action_type:
            #get parameters of actions
            params = get_action_params_from_stdin(action_type, observation.state)
            if params:
                action = Action(action_type, params)
                print(f"Playing {action}")
                return action
        print(colored("Incorrect input, terminating the game!", "red"))
        # If something failed, avoid doing the move
        return False


def get_action_type_from_stdin()->ActionType:
    """
    Small function to call the function that does the selection of actions
    Probably not needed separatedly
    """
    print("Available Actions:")
    action_type = get_selection_from_user(ActionType, f"Select an action to play [0-{len(ActionType)-1}]: ")
    return action_type

def sanitize_user_input(input_string, action_type):
    stripped = input_string.strip()
    if len(stripped) > 0:
        match action_type:
            case ActionType.ScanNetwork:
                splitted = stripped.split("/")
                if len(splitted) == 2:
                    return splitted
                else:
                    return False
            case _:
                splitted = stripped.split(" ")
                if len(splitted) == 1:
                    return splitted[0]
                else:
                    return False
    else:
        return False


def get_action_params_from_stdin(action_type: ActionType, current: GameState)->dict:
    """
    Method which promts user to give parameters for given action_type
    """
    params = {}
    match action_type:
        case ActionType.ScanNetwork:
            user_input = input(f"Provide network for selected action {action_type}: ")
            valid_input = sanitize_user_input(user_input, action_type)
            while not valid_input:
                print(colored("Incorrect input, desired format of network: X.X.X.X/mask", "red"))
                user_input = input(f"Provide network for selected action {action_type}: ")
                valid_input = sanitize_user_input(user_input, action_type)

            params = {"target_network": Network(valid_input[0], valid_input[1])}
        
        case ActionType.ExploitService:
            user_input_host = input(f"Provide target host for selected action {action_type}: ")
            valid_input = sanitize_user_input(user_input_host, action_type)
            while not valid_input:
                print(colored("Incorrect input, desired format of host: X.X.X.X", "red"))
                user_input_host = input(f"Provide target host for selected action {action_type}: ")
                valid_input = sanitize_user_input(user_input_host, action_type)
            trg_host = IP(valid_input)
            if trg_host in current.known_services:
                print(f"Known services in {trg_host}")
                service = get_selection_from_user(current.known_services[trg_host], f"Select service to exploint [0-len({len(current.known_services[trg_host])-1})]: ")
                params = {"target_host": trg_host, "target_service":service}
        
        case ActionType.ExfiltrateData:
            user_input_host_src = input(f"Provide SOURCE host for selected action {action_type}: ")
            valid_input_src_host = sanitize_user_input(user_input_host_src, action_type)
            while not valid_input_src_host:
                print(colored("Incorrect input, desired format of host: X.X.X.X", "red"))
                user_input_host_src = input(f"Provide SOURCE host for selected action {action_type}: ")
                valid_input_src_host = sanitize_user_input(user_input_host_src, action_type)
            src_host = IP(valid_input_src_host)
            if src_host in current.known_data:
                print(f"Known data in {src_host}")
                data = get_selection_from_user(current.known_data[src_host], f"Select data to exflitrate [0-{len(current.known_data[src_host])-1}]: ")
                if data:
                    user_input_host_trg = input(f"Provide TARGET host for data exfiltration: ")
                    valid_input_trg_host = sanitize_user_input(user_input_host_trg, action_type)
                    while not valid_input_trg_host:
                        print(colored("Incorrect input, desired format of host: X.X.X.X", "red"))
                        user_input_host_trg = input(f"Provide TARGET host for data exfiltration: ")
                        valid_input_trg_host = sanitize_user_input(user_input_host_trg, action_type)
                    trg_host = IP(valid_input_trg_host)
                    params = {"target_host": trg_host, "data":data, "source_host":src_host}
            else:
                print(f"Host {src_host} does not have any data yet.")
        case _:
            user_input = input(f"Provide target host for selected action {action_type}: ")
            valid_input = sanitize_user_input(user_input, action_type)
            while not valid_input:
                print(colored("Incorrect input, desired format of host: X.X.X.X", "red"))
                user_input = input(f"Provide target host for selected action {action_type}: ")
                valid_input = sanitize_user_input(user_input, action_type)
            params = {"target_host": IP(valid_input)}
    return params


def get_selection_from_user(actiontypes: ActionType, prompt) -> ActionType:
    """
    Receive an ActionType object that contains all the options of actions
    Get the selection of action in text from the user in the stdin
    """
    option_dict = dict(enumerate(actiontypes))
    input_alive = True
    selected_option = None
    for index, option in option_dict.items():
        print(f"\t{index} - {option}")
    while input_alive:
        user_input = input(prompt)
        if user_input.lower() == "exit":
            input_alive = False
        else:
            try:
                selected_idx = int(user_input)
                selected_option = option_dict[selected_idx]
                input_alive = False
            except (ValueError, KeyError):
                print(colored(f"Please insert a number in range {min(option_dict.keys())}-{max(option_dict.keys())}!", 'red'))
    return selected_option

def print_current_state(state: GameState, reward: int = None, previous_state=None):
    """
    Prints GameState to stdout in formatted way
    """
    def print_known_services(known_services, previous_state):
        if len(known_services) == 0:
            print(f"| {colored('SERVICES',None,attrs=['bold'])}: N/A")
        else:
            first = True
            services = {}
            if previous_state:
                for k in sorted(known_services.keys()):
                    if k in previous_state.known_services:
                        services[k] = [str(s) for s in sorted(known_services[k])]
                    else:
                        services[colored(k, 'yellow')] = [colored(str(s),'yellow') for s in sorted(known_services[k])]
            else:
                for k in sorted(known_services.keys()):
                    services[colored(k, 'yellow')] = [colored(str(s),'yellow') for s in sorted(known_services[k])]

            for host, service_list in services.items():
                if first:
                    print(f"| {colored('SERVICES',None,attrs=['bold'])}: {host}:")
                    for service in service_list:
                        print(f"|\t\t{service}")
                    first = False
                else:
                    print(f"|           {host}:")
                    for service in service_list:
                        print(f"|\t\t{service}")

    def print_known_data(known_data, previous_state):
        if len(known_data) == 0:
            print(f"| {colored('DATA',None,attrs=['bold'])}: N/A")
        else:
            first = True
            data = {}
            if previous_state:
                for k in sorted(known_data.keys()):
                    if k in previous_state.known_data:
                        data[k] = [str(d) for d in sorted(known_data[k])]
                    else:
                        data[colored(k, 'yellow')] = [colored(str(d),'yellow') for d in sorted(known_data[k])]
            else:
                for k in sorted(known_data.keys()):
                    data[colored(k, 'yellow')] = [colored(str(d),'yellow') for d in sorted(known_data[k])]
            
            for host, data_list in data.items():
                if first:
                    print(f"| {colored('DATA',None,attrs=['bold'])}: {host}:")
                    for datapoint in data_list:
                        print(f"|\t\t{datapoint}")
                    first = False
                else:
                    print(f"|       {host}:")
                    for datapoint in data_list:
                        print(f"|\t\t{datapoint}")

    print(f"\n+============================================= {colored('CURRENT STATE','light_blue',attrs=['bold'])} (reward={reward}) ===============================================")
    if previous_state:
        previous_nets =[]
        new_nets = []
        for net in state.known_networks:
            if net in previous_state.known_networks:
                previous_nets.append(net)
            else:
                new_nets.append(net)
        nets = [str(n) for n in sorted(previous_nets)] + [colored(str(n), 'yellow') for n in sorted(new_nets)]
    else:
        nets = [colored(str(net), 'yellow') for net in sorted(state.known_networks)]
    print(f"| {colored('NETWORKS',None,attrs=['bold'])}: {', '.join(nets)}")
    print("+----------------------------------------------------------------------------------------------------------------------")
    if previous_state:
        previous_hosts =[]
        new_hosts = []
        for host in state.known_hosts:
            if host in previous_state.known_hosts:
                previous_hosts.append(host)
            else:
                new_hosts.append(host)
        hosts = [str(h) for h in sorted(previous_hosts)] + [colored(str(h), 'yellow') for h in sorted(new_hosts)]
    else:
        hosts = [colored(str(host), 'yellow') for host in sorted(state.known_hosts)]
    print(f"| {colored('KNOWN_H',None,attrs=['bold'])}: {', '.join(hosts)}")
    print("+----------------------------------------------------------------------------------------------------------------------")
    if previous_state:
        previous_hosts =[]
        new_hosts = []
        for host in state.controlled_hosts:
            if host in previous_state.controlled_hosts:
                previous_hosts.append(host)
            else:
                new_hosts.append(host)
        owned_hosts = [str(h) for h in sorted(previous_hosts)] + [colored(str(h), 'yellow') for h in sorted(new_hosts)]
    else:
        owned_hosts = [colored(str(host), 'yellow') for host in sorted(state.controlled_hosts)]    
    print(f"| {colored('OWNED_H',None,attrs=['bold'])}: {', '.join(owned_hosts)}")
    print("+----------------------------------------------------------------------------------------------------------------------")
    print_known_services(state.known_services, previous_state)
    print("+----------------------------------------------------------------------------------------------------------------------")
    print_known_data(state.known_data, previous_state)
    print("+======================================================================================================================\n")

def play(env, agent, num_episodes=None):
    episode_counter = 0
    stop = False
    while not stop:
        observation = env.reset()
        previous_state = None
        while not observation.done and not stop:
            # Be sure the agent can do the move before giving to the env.
            print_current_state(observation.state, observation.reward, previous_state)
            action = agent.move(observation)
            if action:
                previous_state = observation.state
                observation = env.step(action)
            else:
                observation = Observation(None,None,True, "User-terminated")
        episode_counter +=1
        print(colored(f"\nEpisode over! Reason {observation.info}", 'light_cyan'))
        if input(colored("\nDo you want to play again? Y/n: ", 'light_cyan')) in ["Y", 'y']:
            print("\n################################################ STARTING NEW EPISODE ################################################\n")
        else:
            stop = True

def main() -> None:
    """
    Function to run the run the interactive agent
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--task_config_file", help="Reads the task definition from a configuration file", default=path.join(path.dirname(__file__), 'netsecenv-task.yaml'), action='store', required=False)
    parser.add_argument("--rb_log_directory", help="directory to store the logs", default="env/logs/replays", action='store', required=False)
    
    args = parser.parse_args()
    
    print(colored("\n\nWelcome to the Network Security Game!\n", 'light_cyan'))
    player_name = input(colored("Insert your name please: ", 'light_cyan'))
    
    while not player_name or len(player_name)==0:
        print(colored("Incorrect input, you have to provide player's name!", "red"))
        player_name = input("Insert your name please: ")


    logging.basicConfig(filename=f'interactive_agent_{player_name}.log', filemode='w', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S', level=logging.CRITICAL)
    logger = logging.getLogger('Interactive-agent')

    #Make sure the folder for replays exists
    if not os.path.exists(args.rb_log_directory):
        os.makedirs(args.rb_log_directory)
    # Create the env
    env = NetworkSecurityEnvironment(args.task_config_file)
    random.seed(env.seed)
    logger.info('Creating the agent')
    agent = InteractiveAgent(env)
    play(env, agent, None)

if __name__ == '__main__':
    main()
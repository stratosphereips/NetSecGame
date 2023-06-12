# Author: Ondrej Lukas, ondrej.lukas@aic.cvut.cz
# This agent allows to manually play the Network Security Game
import sys
import argparse
import logging
import random
from os import path
# This is used so the agent can see the environment and game components
sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

#with the path fixed, we can import now
from env.network_security_game import Network_Security_Environment
from env.scenarios import scenario_configuration
from env.scenarios import smaller_scenario_configuration
from env.scenarios import tiny_scenario_configuration
from env.game_components import Network, IP, Data
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
        print("Incorrect input, terminating the game!")
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

def get_action_params_from_stdin(action_type: ActionType, current: GameState)->dict:
    """
    Method which promts user to give parameters for given action_type
    """
    params = {}
    if action_type == ActionType.ScanNetwork:
        user_input = input(f"Provide network for selected action {action_type}: ")
        net_ip, net_mask = user_input.split("/")
        params = {"target_network": Network(net_ip, net_mask)}
    elif action_type == ActionType.FindData:
        user_input = input(f"Provide target host for selected action {action_type}: ")
        params = {"target_host": IP(user_input)}
    elif action_type == ActionType.FindServices:
        user_input = input(f"Provide target host for selected action {action_type}: ")
        params = {"target_host": IP(user_input)}
    elif action_type == ActionType.ExploitService:
        user_input_host = input(f"Provide target host for selected action {action_type}: ")
        trg_host = IP(user_input_host)
        if trg_host in current.known_services:
            print(f"Known services in {trg_host}")
            service = get_selection_from_user(current.known_services[trg_host], f"Select service to exploint [0-len({len(current.known_services[trg_host])-1})]: ")
            params = {"target_host": trg_host, "target_service":service}
    elif action_type == ActionType.ExfiltrateData:
        user_input_host_src = input(f"Provide SOURCE host for selected action {action_type}: ")
        src_host = IP(user_input_host_src)
        if src_host in current.known_data:
            print(f"Known data in {src_host}")
            data = get_selection_from_user(current.known_data[src_host], f"Select data to exflitrate [0-{len(current.known_data[src_host])-1}]: ")
            if data:
                user_input_host_trg = input(f"Provide TARGET host for data exfiltration: ")
                trg_host = IP(user_input_host_trg)
                params = {"target_host": trg_host, "data":data, "source_host":src_host}
        else:
            print(f"Host {src_host} does not have any data yet.")
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
                print(f"Please insert a number in range {min(option_dict.keys())}-{max(option_dict.keys())}!")
    return selected_option

def print_current_state(state: GameState, reward: int = None):
    """
    Prints GameState to stdout in formatted way
    """
    def print_known_services(known_services):
        if len(known_services) == 0:
            print("| SERVICES: N/A")
        else:
            first = True
            for host, services in known_services.items():
                if first:
                    print(f"| SERVICES: {host}:")
                    for service in services:
                        print(f"|\t\t{service}")
                    first = False
                else:
                    print(f"|           {host}:")
                    for service in services:
                        print(f"|\t\t{service}")

    def print_known_data(known_data):
        if len(known_data) == 0:
            print("| DATA: N/A")
        else:
            first = True
            for host, data_list in known_data.items():
                if first:
                    print(f"| DATA: {host}:")
                    for data in data_list:
                        print(f"|\t\t{data}")
                    first = False
                else:
                    print(f"|       {host}:")
                    for data in data_list:
                        print(f"|\t\t{data}")

    print(f"\n+========================================== CURRENT STATE (reward={reward}) ===========================================")
    print(f"| NETWORKS: {', '.join([str(net) for net in state.known_networks])}")
    print("+----------------------------------------------------------------------------------------------------------------------")
    print(f"| KNOWN_H: {', '.join([str(host) for host in state.known_hosts])}")
    print("+----------------------------------------------------------------------------------------------------------------------")
    print(f"| OWNED_H: {', '.join([str(host) for host in state.controlled_hosts])}")
    print("+----------------------------------------------------------------------------------------------------------------------")
    print_known_services(state.known_services)
    print("+----------------------------------------------------------------------------------------------------------------------")
    print_known_data(state.known_data)
    print("+======================================================================================================================\n")

def main() -> None:
    """
    Function to run the run the interactive agent
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=25, type=int)
    parser.add_argument("--defender", help="Is defender present", default=False, action='store_true')
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1", type=str)
    parser.add_argument("--verbosity", help="Sets verbosity of the environment", default=0, type=int)
    parser.add_argument("--seed", help="Sets the random seed", type=int, default=42)
    parser.add_argument("--random_start", help="Sets if starting position and goal data is randomized", default=False, action='store_true')
    args = parser.parse_args()

    logging.basicConfig(filename='interactive_agent.log', filemode='w', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S', level=logging.CRITICAL)
    logger = logging.getLogger('Interactive-agent')
    random.seed(args.seed)

    env = Network_Security_Environment(random_start=args.random_start, verbosity=args.verbosity)
    if args.scenario == "scenario1":
        cyst_config = scenario_configuration.configuration_objects
    elif args.scenario == "scenario1_small":
        cyst_config = smaller_scenario_configuration.configuration_objects
    elif args.scenario == "scenario1_tiny":
        cyst_config = tiny_scenario_configuration.configuration_objects
    else:
        print("unknown scenario")
        sys.exit(1)

    # define attacker goal and initial location
    if args.random_start:
        goal = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{IP("213.47.23.195"):"random"}
        }
        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{IP("213.47.23.195")},
            "known_services":{},
            "known_data":{}
        }
    else:
        goal = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{IP("213.47.23.195"):{Data("User1", "DataFromServer1")}}
        }

        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{IP("213.47.23.195"), IP("192.168.2.2")},
            "known_services":{},
            "known_data":{}
        }

    # Create agent
    observation = env.initialize(win_conditions=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps, cyst_config=cyst_config)
    logger.info('Creating the agent')
    agent = InteractiveAgent(env)

    print("Welcome to the Network Security Game!\n")
    while not observation.done:
        # Be sure the agent can do the move before giving to the env.
        print_current_state(observation.state, observation.reward)
        action = agent.move(observation)
        if action:
            observation = env.step(action)
    print(f"Episode over! Reason {observation.info}")
if __name__ == '__main__':
    main()

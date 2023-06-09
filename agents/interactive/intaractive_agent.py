# Author: Ondrej Lukas, ondrej.lukas@aic.cvut.cz
# This agent allows to manually play the Network Security Game
import argparse
import logging

import random
# This is used so the agent can see the environment and game components
import sys
from os import path
sys.path.append( path.dirname(path.dirname( path.dirname( path.abspath(__file__)))))

#with the path fixed, we can import now
from env.network_security_game import Network_Security_Environment
from env.scenarios import scenario_configuration, smaller_scenario_configuration, tiny_scenario_configuration
from env.game_components import *



class InteractiveAgent:
    
    def __init__(self, env)->None:
        self.env = env
    
    def _generate_valid_actions(self, state: GameState)->list:
        valid_actions = set()
        #Network Scans
        for network in state.known_networks:
            # TODO ADD neighbouring networks
            valid_actions.add(Action(ActionType.ScanNetwork, params={"target_network": network}))
        # Service Scans
        for host in state.known_hosts:
            valid_actions.add(Action(ActionType.FindServices, params={"target_host": host}))
        # Service Exploits
        for host, service_list in state.known_services.items():
            for service in service_list:
                valid_actions.add(Action(ActionType.ExploitService, params={"target_host": host , "target_service": service}))
        # Data Scans
        for host in state.controlled_hosts:
            valid_actions.add(Action(ActionType.FindData, params={"target_host": host}))
        
        # Data Exfiltration
        for src_host, data_list in state.known_data.items():
            for data in data_list:
                for trg_host in state.controlled_hosts:
                    if trg_host != src_host:
                        valid_actions.add(Action(ActionType.ExfiltrateData, params={"target_host": trg_host, "source_host": src_host, "data": data}))
        return list(valid_actions)

    def move(self, observation:Observation)->Action:
        self._print_current_state(observation.state, observation.reward)
        # Get Action type to play
        action_type = self._get_action_type_from_stdin()
        if action_type:
            #get parameters of actions
            params = self._get_action_params_from_stdin(action_type, observation.state)
            if params:
                action = Action(action_type, params)
                print(f"Playing {action}")
                return action
        print("Incorrect input, terminating the game!")

    def _print_current_state(self, state:GameState, reward:int=None): 
        print(f"+========================================== CURRENT STATE (reward={reward}) ===========================================")
        print(f"| NETWORKS: {', '.join([str(n) for n in state.known_networks])}")
        print("+----------------------------------------------------------------------------------------------------------------------")
        print(f"| KNOWN_H: {', '.join([str(h) for h in state.known_hosts])}")
        print("+----------------------------------------------------------------------------------------------------------------------")
        print(f"| OWNED_H: {', '.join([str(h) for h in state.controlled_hosts])}")
        print("+----------------------------------------------------------------------------------------------------------------------")
        if len(state.known_services) == 0:
            print("| SERVICES: N/A")
        else:
            first = True
            for h,services in state.known_services.items():
                if first:
                    print(f"| SERVICES: {h}:")
                    for s in services:
                        print(f"|\t\t{s}")
                    first = False
                else:
                    print(f"|           {h}:")
                    for s in services:
                        print(f"|\t\t{s}")
        print("+----------------------------------------------------------------------------------------------------------------------")
        if len(state.known_data) == 0:
            print("| DATA: N/A")
        else:
            first = True
            for h, data in state.known_data.items():
                if first:
                    print(f"| DATA: {h}:")
                    for d in data:
                        print(f"|\t\t{d}")
                    first = False
                else:
                    print(f"|       {h}:")
                    for s in data:
                        print(f"|\t\t{d}")
        print("+======================================================================================================================")

    def _get_action_type_from_stdin(self)->ActionType:
        print("Available Actions:")
        return self._get_selection_from_user(ActionType, f"Select an action to play [0-{len(ActionType)}]: ")
    
    def _get_action_params_from_stdin(self, action_type:ActionType, current:GameState)->dict:
        if action_type == ActionType.ScanNetwork:
            user_input = input(f"Provide network for selected action {action_type}: ")
            net_ip, net_mask = user_input.split("/")
            return {"target_network": Network(net_ip, net_mask)}
        elif action_type == ActionType.FindData:
            user_input = input(f"Provide target host for selected action {action_type}: ")
            return {"target_host": IP(user_input)}
        elif action_type == ActionType.FindServices:
            user_input = input(f"Provide target host for selected action {action_type}: ")
            return {"target_host": IP(user_input)}
        elif action_type == ActionType.ExploitService:
            user_input_host = input(f"Provide target host for selected action {action_type}: ")
            trg_host = IP(user_input_host)
            if trg_host in current.known_services:
                print(f"Known services in {trg_host}")
                service = self._get_selection_from_user(current.known_services[trg_host], f"Select service to exploint [0-len({len(current.known_services[trg_host])})]: ")
                return {"target_host": trg_host, "target_service":service}
        elif action_type == ActionType.ExfiltrateData:
            user_input_host_src = input(f"Provide SOURCE host for selected action {action_type}: ")
            src_host = IP(user_input_host_src)
            if src_host in current.known_data:
                print(f"Known data in {src_host}")
                data = self._get_selection_from_user(current.known_data[src_host], f"Select data to exflitrate [0-{len(current.known_data[src_host])}]: ")
                if data:
                    user_input_host_trg = input(f"Provide TARGET host for data exfiltration: ")
                    trg_host = IP(user_input_host_trg)
                    return {"target_host": trg_host, "data":data, "source_host":src_host}
        else:
            return None

    def _get_selection_from_user(self, options, prompt):
        option_dict = {k:v for k,v in enumerate(options)}
        input_alive = True
        selected_option = None
        for i,at in option_dict.items():
            print(f"\t{i} - {at}")
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

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=25, type=int)
    parser.add_argument("--defender", help="Is defender present", default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1", type=str)
    parser.add_argument("--verbosity", help="Sets verbosity of the environment", default=0, type=int)
    parser.add_argument("--seed", help="Sets the random seed", type=int, default=42)
    parser.add_argument("--random_start", help="Sets if starting position and goal data is randomized", default=False, action=argparse.BooleanOptionalAction)
    args = parser.parse_args()

    logging.basicConfig(filename='interactive_agent.log', filemode='w', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.CRITICAL)
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
        exit(1)

    # define attacker goal and initial location
    if args.random_start:
        goal = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{"213.47.23.195":"random"}
        }
        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{"213.47.23.195"},
            "known_services":{},
            "known_data":{}
        }
    else:
        goal = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{IP("213.47.23.195"):{("User1", "DataFromServer1")}}
        }

        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{"213.47.23.195","192.168.2.2"},
            "known_services":{},
            "known_data":{}
        }
    

    # Create agent
    observation = env.initialize(win_conditons=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps, cyst_config=cyst_config)
    logger.info(f'Creating the agent')
    agent = InteractiveAgent(env)

    print("Welcome to the Network Security Game!\n")
    while not observation.done:
        observation = env.step(agent.move(observation))
    print(f"Episode over! Reason {observation.info}")

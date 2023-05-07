#Author: Ondrej Lukas, ondrej.lukas@aic.cvut.cz
# This agents just randomnly picks actions. No learning
from game_components import *
from random import choice, seed
import random
import argparse
from network_security_game import Network_Security_Environment
from scenarios import scenario_configuration, smaller_scenario_configuration, tiny_scenario_configuration
import logging
import numpy as np
from torch.utils.tensorboard import SummaryWriter
import time


class RandomAgent:

    def __init__(self, env):
        self.env = env
    
    def move(self, state:GameState) -> Action:
        state = state.observation
        # Randomly choose from the available actions
        actions = self.env.get_valid_actions(state)
        return choice(actions)
    
    def play(self, state) -> tuple:
        return_value = 0
        while not state.done:
            #select action
            action = self.move(state)
            #get next state of the environment
            next_state = self.env.step(action)
            #collect reward
            return_value += next_state.reward
            #move to next state
            state = next_state
        return return_value, self.env.is_goal(state.observation), self.env.detected, self.env.timestamp

    def evaluate(self, state) -> tuple: #(cumulative_reward, goal?, detected?, num_steps)
        return_value = 0
        while not state.done:
            action = self.move(state)
            next_state = self.env.step(action)
            return_value += next_state.reward
            state = next_state
        game_ended_detected = self.env.detected
        return return_value, self.env.is_goal(state.observation), game_ended_detected, self.env.timestamp


if __name__ == '__main__':
    # set seed 
    seed(42)
    parser = argparse.ArgumentParser()
    parser.add_argument("--episodes", help="Sets number of training episodes", default=1000, type=int)
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=25, type=int)
    parser.add_argument("--defender", help="Is defender present", default=True, action="store_true")
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1_small", type=str)
    parser.add_argument("--verbosity", help="Sets verbosity of the environment", default=0, type=int)
    parser.add_argument("--seed", help="Sets the random seed", type=int, default=42)
    parser.add_argument("--random_start", help="Sets if starting position and goal data is randomized", default=False, action="store_true")
    parser.add_argument("--test_for", help="Sets evaluation length", default=1000, type=int)
    parser.add_argument("--test_each", help="Sets periodic evaluation during testing", default=100, type=int)
    args = parser.parse_args()

    logging.basicConfig(filename='random_agent.log', filemode='a', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.CRITICAL)
    logger = logging.getLogger('Random-agent')

    # Setup tensorboard
    run_name = f"netsecgame__randomlearning__{args.seed}__{int(time.time())}"
    writer = SummaryWriter(f"logs/{run_name}")
    writer.add_text(
        "hypherparameters", 
        "|param|value|\n|-|-|\n%s" % ("\n".join([f"|{key}|{value}|" for key, value in vars(args).items()]))
    )

    random.seed(args.seed)

    env = Network_Security_Environment(random_start=args.random_start, verbosity=args.verbosity)
    if args.scenario == "scenario1":
        env.process_cyst_config(scenario_configuration.configuration_objects)
    elif args.scenario == "scenario1_small":
        env.process_cyst_config(smaller_scenario_configuration.configuration_objects)
    elif args.scenario == "scenario1_tiny":
        env.process_cyst_config(tiny_scenario_configuration.configuration_objects)
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
            "controlled_hosts":{"213.47.23.195","192.168.2.0/24"},
            "known_services":{},
            "known_data":{}
        }
    else:
        goal = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{"213.47.23.195":{("User1", "DataFromServer1")}}
        }

        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{"213.47.23.195","192.168.2.2"},
            "known_services":{},
            "known_data":{}
        }
    

    # Create agent
    logger.info(f'Initializing the environment')
    state = env.initialize(win_conditons=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps)
    logger.info(f'Creating the agent')
    agent = RandomAgent(env)

    # Testing
    wins = 0
    detected = 0
    returns = []
    num_steps = []
    num_win_steps = [] 
    num_detected_steps = []
    logger.info(f'Starting the training')
    for i in range(1, args.episodes + 1):
        state = env.reset()
        ret, win, detection, steps = agent.evaluate(state)
        if win:
            wins += 1
            num_win_steps += [steps]
        if detection:
            detected +=1
            num_detected_steps += [steps]
        returns += [ret]
        num_steps += [steps]

        test_win_rate = (wins/(args.test_for+1))*100
        test_detection_rate = (detected/(args.test_for+1))*100
        test_average_returns = np.mean(returns)
        test_std_returns = np.std(returns)
        test_average_episode_steps = np.mean(num_steps)
        test_std_episode_steps = np.std(num_steps)
        test_average_win_steps = np.mean(num_win_steps)
        test_std_win_steps = np.std(num_win_steps)
        test_average_detected_steps = np.mean(num_detected_steps)
        test_std_detected_steps = np.std(num_detected_steps)


        if i % args.test_each == 0 and i != 0:
            text = f'''Tested after {i} episodes. 
                Wins={wins}, 
                Detections={detected}, 
                winrate={test_win_rate:.3f}%, 
                detection_rate={test_detection_rate:.3f}%, 
                average_returns={test_average_returns:.3f} +- {test_std_returns:.3f}, 
                average_episode_steps={test_average_episode_steps:.3f} +- {test_std_episode_steps:.3f}, 
                average_win_steps={test_average_win_steps:.3f} +- {test_std_win_steps:.3f},
                average_detected_steps={test_average_detected_steps:.3f} +- {test_std_detected_steps:.3f}
                '''
            print(text)
            logger.info(text)
            # Store in tensorboard
            writer.add_scalar("charts/test_avg_win_rate", test_win_rate, i)
            writer.add_scalar("charts/test_avg_detection_rate", test_detection_rate, i)
            writer.add_scalar("charts/test_avg_returns", test_average_returns , i)
            writer.add_scalar("charts/test_std_returns", test_std_returns , i)
            writer.add_scalar("charts/test_avg_episode_steps", test_average_episode_steps , i)
            writer.add_scalar("charts/test_std_episode_steps", test_std_episode_steps , i)
            writer.add_scalar("charts/test_avg_win_steps", test_average_win_steps , i)
            writer.add_scalar("charts/test_std_win_steps", test_std_win_steps , i)
            writer.add_scalar("charts/test_avg_detected_steps", test_average_detected_steps , i)
            writer.add_scalar("charts/test_std_detected_steps", test_std_detected_steps , i)


    text = f'''Final test after {i} episodes, for {args.test_for} steps. 
        Wins={wins}, 
        Detections={detected}, 
        winrate={test_win_rate:.3f}%, 
        detection_rate={test_detection_rate:.3f}%, 
        average_returns={test_average_returns:.3f} +- {test_std_returns:.3f}, 
        average_episode_steps={test_average_episode_steps:.3f} +- {test_std_episode_steps:.3f}, 
        average_win_steps={test_average_win_steps:.3f} +- {test_std_win_steps:.3f},
        average_detected_steps={test_average_detected_steps:.3f} +- {test_std_detected_steps:.3f}
        '''
    print(text)
    logger.info(text)
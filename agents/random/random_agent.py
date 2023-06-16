#Author: Ondrej Lukas, ondrej.lukas@aic.cvut.cz
# This agents just randomnly picks actions. No learning
import sys
from os import path
sys.path.append( path.dirname(path.dirname( path.dirname( path.abspath(__file__) ) ) ))
import env.game_components as components
from random import choice, seed
import random
import argparse
import numpy as np
import time
import logging
from torch.utils.tensorboard import SummaryWriter

# This is used so the agent can see the environment and game components

#with the path fixed, we can import now
from env.network_security_game import Network_Security_Environment
from env.scenarios import scenario_configuration, smaller_scenario_configuration, tiny_scenario_configuration
from env.game_components import *


class RandomAgent:
    def __init__(self, env):
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

    def move(self, observation:Observation) -> Action:
        state = observation.state
        # Randomly choose from the available actions
        actions = self._generate_valid_actions(state)
        return choice(actions)

    def play(self, observation:Observation) -> tuple:
        return_value = 0
        while not observation.done:
            # Select action
            action = self.move(observation)
            # Get next observation of the environment
            next_observation = self.env.step(action)
            # Collect reward
            return_value += next_observation.reward
            # Move to next state
            observation = next_observation
        return return_value, self.env.is_goal(observation.state), self.env.detected, self.env.timestamp

    def evaluate(self, observation:Observation) -> tuple: #(cumulative_reward, goal?, detected?, num_steps)
        return_value = 0
        while not observation.done:
            action = self.move(observation)
            next_observation = self.env.step(action)
            return_value += next_observation.reward
            observation = next_observation
        game_ended_detected = self.env.detected
        return return_value, self.env.is_goal(observation.state), game_ended_detected, self.env.timestamp


if __name__ == '__main__':
    # set seed
    seed(42)
    parser = argparse.ArgumentParser()
    parser.add_argument("--episodes", help="Sets number of training episodes", default=1000, type=int)
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=25, type=int)
    parser.add_argument("--defender", help="Is defender present", default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1_tiny", type=str)
    parser.add_argument("--verbosity", help="Sets verbosity of the environment", default=0, type=int)
    parser.add_argument("--seed", help="Sets the random seed", type=int, default=42)
    parser.add_argument("--random_start", help="Sets if starting position and goal data is randomized", default=True, action=argparse.BooleanOptionalAction)
    parser.add_argument("--test_for", help="Sets evaluation length", default=1000, type=int)
    parser.add_argument("--test_each", help="Sets periodic evaluation during testing", default=100, type=int)
    parser.add_argument("--task_config_file", help="Reads the task definition from a configuration file", default=path.join(path.dirname(__file__), 'netsecenv-task.yaml'), action='store', required=False)
    args = parser.parse_args()

    logging.basicConfig(filename='agents/random/random_agent.log', filemode='a', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.CRITICAL)
    logger = logging.getLogger('Random-agent')

    # Setup tensorboard
    run_name = f"netsecgame__qlearning__{args.seed}__{int(time.time())}"
    writer = SummaryWriter(f"agents/tensorboard-logs/{run_name}")
    writer.add_text(
        "hypherparameters",
        "|param|value|\n|-|-|\n%s" % ("\n".join([f"|{key}|{value}|" for key, value in vars(args).items()]))
    )

    random.seed(args.seed)

    # Training
    logger.info(f'Initializing the environment')
    env = Network_Security_Environment(args.task_config_file)
    observation = env.reset()


    # Create agent
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
        observation = env.reset()
        ret, win, detection, steps = agent.evaluate(observation)
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
    logger.info(text)

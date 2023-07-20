#Author: Ondrej Lukas, ondrej.lukas@aic.cvut.cz
# This agents just randomnly picks actions. No learning
import sys
from os import path
sys.path.append( path.dirname(path.dirname( path.dirname( path.abspath(__file__) ) ) ))
from random import choice
import argparse
import numpy as np
import time
import logging
from torch.utils.tensorboard import SummaryWriter

# This is used so the agent can see the environment and game components

#with the path fixed, we can import now
from env.network_security_game import NetworkSecurityEnvironment
from env.game_components import Action, ActionType, GameState, Observation

class RandomAgent:
    def __init__(self, env, args):
        self.env = env
        self.args = args
        

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

    def move(self, observation:Observation, actions_taken) -> Action:
        state = observation.state
        # Randomly choose from the available actions
        valid_actions = self._generate_valid_actions(state)
        if self.args.force_ignore:
            valid_actions = [action for action in valid_actions if action not in actions_taken]
        return choice(valid_actions)

    def evaluate(self, observation:Observation) -> tuple: #(cumulative_reward, goal?, detected?, num_steps)
        """
        Run the random agent for many steps until the game is ended
        """
        return_value = 0
        actions_taken = []
        while not observation.done:
            # Select action
            action = self.move(observation, actions_taken)
            # Get next observation of the environment
            next_observation = self.env.step(action)
            # Collect reward
            return_value += next_observation.reward
            # Move to next state
            observation = next_observation
            actions_taken.append(action)
        game_ended_detected = self.env.detected
        return return_value, self.env.is_goal(observation.state), game_ended_detected, self.env.timestamp


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--episodes", help="Sets number of testing episodes", default=1000, type=int)
    parser.add_argument("--test_for", help="Sets evaluation length", default=1000, type=int)
    parser.add_argument("--test_each", help="Sets periodic evaluation during testing", default=100, type=int)
    parser.add_argument("--task_config_file", help="Reads the task definition from a configuration file", default=path.join(path.dirname(__file__), 'netsecenv-task.yaml'), action='store', required=False)
    parser.add_argument("--force_ignore", help="Force ignore repeated actions in code", default=False, action=argparse.BooleanOptionalAction)
    args = parser.parse_args()

    # Create the environment
    env = NetworkSecurityEnvironment(args.task_config_file)
    # If you need a separate log, uncomment this
    logging.basicConfig(filename='agents/random/logs/random_agent.log', filemode='a', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.INFO)
    logger = logging.getLogger('Random-agent')
    logger.info(f'Initializing the environment')

    # Setup tensorboard
    run_name = f"netsecgame__llm__{env.seed}__{int(time.time())}"
    writer = SummaryWriter(f"agents/random/logs/{run_name}")

    # Create agent
    agent = RandomAgent(env, args)

    # Testing
    wins = 0
    detected = 0
    returns = []
    num_steps = []
    num_win_steps = []
    num_detected_steps = []
    logger.info(f'Starting the testing')
    print('Starting the testing')
    for episode in range(1, args.episodes + 1):

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

        test_win_rate = (wins/episode) * 100
        test_detection_rate = (detected/episode) * 100
        test_average_returns = np.mean(returns)
        test_std_returns = np.std(returns)
        test_average_episode_steps = np.mean(num_steps)
        test_std_episode_steps = np.std(num_steps)
        test_average_win_steps = np.mean(num_win_steps)
        test_std_win_steps = np.std(num_win_steps)
        test_average_detected_steps = np.mean(num_detected_steps)
        test_std_detected_steps = np.std(num_detected_steps)


        if episode % args.test_each == 0 and episode != 0:
            print(f'Episode {episode}')
            logger.info(f'Episode {episode}')
            text = f'''Tested after {episode} episodes.
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
            print(text)
            # Store in tensorboard
            writer.add_scalar("charts/test_avg_win_rate", test_win_rate, episode)
            writer.add_scalar("charts/test_avg_detection_rate", test_detection_rate, episode)
            writer.add_scalar("charts/test_avg_returns", test_average_returns , episode)
            writer.add_scalar("charts/test_std_returns", test_std_returns , episode)
            writer.add_scalar("charts/test_avg_episode_steps", test_average_episode_steps , episode)
            writer.add_scalar("charts/test_std_episode_steps", test_std_episode_steps , episode)
            writer.add_scalar("charts/test_avg_win_steps", test_average_win_steps , episode)
            writer.add_scalar("charts/test_std_win_steps", test_std_win_steps , episode)
            writer.add_scalar("charts/test_avg_detected_steps", test_average_detected_steps , episode)
            writer.add_scalar("charts/test_std_detected_steps", test_std_detected_steps , episode)


    text = f'''Final test after {episode} episodes, for {args.episodes} steps.
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
    print(text)

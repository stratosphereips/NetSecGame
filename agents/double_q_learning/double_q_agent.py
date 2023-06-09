# Author: Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
from os import stat
import numpy as np
from random import choice, random, uniform
import random
import pickle
import sys
import argparse
from timeit import default_timer as timer

import logging
from torch.utils.tensorboard import SummaryWriter
import time

# This is used so the agent can see the environment and game components
import sys
from os import path
sys.path.append( path.dirname(path.dirname(path.dirname( path.abspath(__file__) ) ) ))

#with the path fixed, we can import now
from env.network_security_game import Network_Security_Environment
from env.scenarios import scenario_configuration, smaller_scenario_configuration, tiny_scenario_configuration
from env.game_components import *

class DoubleQAgent:

    def __init__(self, env, alpha=0.1, gamma=0.6, epsilon=0.1):
        self.env = env
        self.alpha = alpha
        self.gamma = gamma 
        self.epsilon = epsilon
        self.q_values1 = {}
        self.q_values2 = {}

    def store_q_table(self,filename):
        with open(filename, "wb") as f:
            pickle.dump({"q1":self.q_values1, "q2":self.q_values2}, f)
    
    def load_q_table(self,filename):
        with open(filename, "rb") as f:
            data = pickle.load(f)
            self.q_values1 = data["q1"]
            self.q_values2 = data["q2"]
    def get_q_value1(self, state, action) -> float:
        if (state, action) not in self.q_values1:
            self.q_values1[state, action] = 0
            self.q_values2[state, action] = 0
        return self.q_values1[state, action]
    
    def get_q_value2(self, state, action,) -> float:
        if (state, action) not in self.q_values2:
            self.q_values2[state, action] = 0
            self.q_values1[state, action] = 0
        return self.q_values2[state, action]

    def move(self, obs:Observation, testing=False) -> Action:
        """
        Make a move
        """
        state = obs.state
        actions = self.env.get_valid_actions(state)
        if random.uniform(0, 1) <= self.epsilon and not testing:
            a = choice(actions)
            if (state, a) not in self.q_values1:
                self.q_values1[state, a] = 0
                self.q_values2[state, a] = 0
            return a
        else: #greedy play
            #speedup the max q selection
            #select the acion with highest q_value
            tmp1 = dict(((state,a), self.q_values1.get((state,a), 0)) for a in actions)
            tmp2 = dict(((state,a), self.q_values1.get((state,a), 0)) for a in actions)
            tmp = dict((k, tmp1[k]+tmp2[k]) for k in tmp1.keys())
            max_q_key = max(tmp, key=tmp.get)
            if max_q_key not in self.q_values1:
                self.q_values1[max_q_key] = 0
                self.q_values2[max_q_key] = 0
            return max_q_key[1]
    
    def max_action(self, state:GameState, q_values) -> Action:
        actions = self.env.get_valid_actions(state)
        tmp = dict(((state,a), q_values.get((state,a), 0)) for a in actions)
        return max(tmp,key=tmp.get)[1] #return maximum Q_value for a given state (out of available actions)
    
    def play(self, observation, testing=False) -> tuple:
        rewards = 0
        while not observation.done:
            # Select action
            action = self.move(observation, testing)
            # Get next state of the environment
            next_observation = self.env.step(action)
            
            if random.uniform(0, 1) <= 0.5:
                #find max Q-Value for next state
                if next_observation.done:
                    max_q_next = 0
                else:
                    max_a_next = self.max_action(next_observation.state, self.q_values1)
                    max_q_next = self.get_q_value2(next_observation.state, max_a_next)
                new_Q = self.q_values1[observation.state, action] + self.alpha * (next_observation.reward + self.gamma*max_q_next - self.q_values1[observation.state, action])
                self.q_values1[observation.state, action] = new_Q
            else:
                #find max Q-Value for next state
                if next_observation.done:
                    max_q_next = 0
                else:
                    max_a_next = self.max_action(next_observation.state, self.q_values2)
                    max_q_next = self.get_q_value1(next_observation.state, max_a_next)
                #update q values
                new_Q = self.q_values2[observation.state, action] + self.alpha*(next_observation.reward + self.gamma*max_q_next - self.q_values2[observation.state, action])
                self.q_values2[observation.state, action] = new_Q
            
            rewards += next_observation.reward
            #move to next state
            observation = next_observation
        return rewards, self.env.is_goal(observation.state), self.env.detected, self.env.timestamp

    def evaluate(self, observation) -> tuple: #(cumulative_reward, goal?, detected?, num_steps)
        """
        Evaluate the agent so far for one episode

        Do without learning
        """
        return_value = 0
        while not observation.done:
            action = self.move(observation, testing=True)
            next_state = self.env.step(action)
            return_value += next_state.reward
            observation = next_state
         # Has to return
        # 1. returns
        # 2. if it is a win
        # 3. if it is was detected
        # 4. amount of steps when finished
        wins = next_state.reward > 0
        detected = self.env.detected
        steps = self.env.timestamp
        return return_value, wins, detected, steps


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--episodes", help="Sets number of training episodes", default=1000, type=int)
    parser.add_argument("--epsilon", help="Sets epsilon for exploration", default=0.2, type=float)
    parser.add_argument("--gamma", help="Sets gamma for Q learing", default=0.9, type=float)
    parser.add_argument("--alpha", help="Sets alpha for learning rate", default=0.3, type=float)
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=25, type=int)
    parser.add_argument("--defender", help="Is defender present", default=True, action=argparse.BooleanOptionalAction)
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1", type=str)
    parser.add_argument("--evaluate", help="Do not train, only run evaluation", default=False, action="store_true")
    parser.add_argument("--eval_each", help="Sets periodic evaluation during training", default=50, type=int)
    parser.add_argument("--eval_for", help="Sets evaluation length", default=100, type=int)
    parser.add_argument("--test_for", help="Sets evaluation length", default=1000, type=int)
    parser.add_argument("--test_each", help="Sets periodic evaluation during testing", default=100, type=int)
    parser.add_argument("--random_start", help="Sets if starting position and goal data is randomized", default=True, action=argparse.BooleanOptionalAction)
    parser.add_argument("--seed", help="Sets the random seed", type=int, default=42)
    args = parser.parse_args()

    args.filename = "DoubleQAgent_2goal_" + ",".join(("{}={}".format(key, value) for key, value in sorted(vars(args).items()) if key not in["evaluate", "eval_each", "eval_each"])) + ".pickle"


    logging.basicConfig(filename='doubleq_agent.log', filemode='a', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.INFO)
    logger = logging.getLogger('DoubleQ-agent')

    # Setup tensorboard
    run_name = f"netsecgame__doubleqlearning__{args.seed}__{int(time.time())}"
    writer = SummaryWriter(f"agents/tensorboard-logs/{run_name}")
    writer.add_text(
        "hypherparameters", 
        "|param|value|\n|-|-|\n%s" % ("\n".join([f"|{key}|{value}|" for key, value in vars(args).items()]))
    )

    random.seed(args.seed)

    env = Network_Security_Environment(verbosity=0, random_start=args.random_start)
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
            "known_data":{"213.47.23.195":{("User1", "DataFromServer1")}}
        }

        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{"213.47.23.195","192.168.2.2"},
            "known_services":{},
            "known_data":{}
        }
    
    # Training
    logger.info(f'Initializing the environment')
    obs = env.initialize(win_conditons=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps)
    logger.info(f'Creating the agent')
    agent = DoubleQAgent(env, args.alpha, args.gamma, args.epsilon)
    try:
        # Load a previous qtable from a pickled file
        logger.info(f'Loading a previous Qtable')
        agent.load_q_table(args.filename)
    except FileNotFoundError:
        logger.info(f"No previous qtable file found to load, starting with an emptly zeroed qtable")
    if not args.evaluate:
        logger.info(f'Starting the training')
        for i in range(0, args.episodes + 1):
            obs = env.reset()
            ret, win,_,_ = agent.play(obs)
            if i % args.eval_each == 0 and i != 0:
                wins = 0
                detected = 0
                returns = [] 
                num_steps = [] 
                num_win_steps = [] 
                num_detected_steps = []
                for j in range(args.eval_for):
                    obs = env.reset()
                    ret, win, detection, steps = agent.evaluate(obs)
                    if win:
                        wins += 1
                        num_win_steps += [steps]
                    if detection:
                        detected +=1
                        num_detected_steps += [steps]
                    returns += [ret]
                    num_steps += [steps]

                eval_win_rate = (wins/(args.eval_for+1))*100
                eval_detection_rate = (detected/(args.eval_for+1))*100
                eval_average_returns = np.mean(returns)
                eval_std_returns = np.std(returns)
                eval_average_episode_steps = np.mean(num_steps)
                eval_std_episode_steps = np.std(num_steps)
                eval_average_win_steps = np.mean(num_win_steps)
                eval_std_win_steps = np.std(num_win_steps)
                eval_average_detected_steps = np.mean(num_detected_steps)
                eval_std_detected_steps = np.std(num_detected_steps)

                text = f'''Evaluated after {i} episodes, for {args.eval_for} steps. 
                    Wins={wins}, 
                    Detections={detected}, 
                    winrate={eval_win_rate:.3f}%, 
                    detection_rate={eval_detection_rate:.3f}%, 
                    average_returns={eval_average_returns:.3f} +- {eval_std_returns:.3f}, 
                    average_episode_steps={eval_average_episode_steps:.3f} +- {eval_std_episode_steps:.3f}, 
                    average_win_steps={eval_average_win_steps:.3f} +- {eval_std_win_steps:.3f},
                    average_detected_steps={eval_average_detected_steps:.3f} +- {eval_std_detected_steps:.3f}
                    '''
                print(text)
                logger.info(text)
                # Store in tensorboard
                writer.add_scalar("charts/eval_avg_win_rate", eval_win_rate, i)
                writer.add_scalar("charts/eval_avg_detection_rate", eval_detection_rate, i)
                writer.add_scalar("charts/eval_avg_returns", eval_average_returns , i)
                writer.add_scalar("charts/eval_std_returns", eval_std_returns , i)
                writer.add_scalar("charts/eval_avg_episode_steps", eval_average_episode_steps , i)
                writer.add_scalar("charts/eval_std_episode_steps", eval_std_episode_steps , i)
                writer.add_scalar("charts/eval_avg_win_steps", eval_average_win_steps , i)
                writer.add_scalar("charts/eval_std_win_steps", eval_std_win_steps , i)
                writer.add_scalar("charts/eval_avg_detected_steps", eval_average_detected_steps , i)
                writer.add_scalar("charts/eval_std_detected_steps", eval_std_detected_steps , i)

        # Store the model on disk
        agent.store_q_table(args.filename)

    # Final evaluation
    wins = 0
    detected = 0
    returns = [] 
    start_t = timer()
    num_win_steps = [] 
    num_detected_steps = []
    for i in range(args.test_for):
        obs = env.reset()
        ret, win, detection, steps = agent.evaluate(obs)
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

        # Print and report every 100 test episodes
        if i % 100 == 0 and i != 0:
            text = f'''Tested after {i} episodes, for {args.test_for} steps. 
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
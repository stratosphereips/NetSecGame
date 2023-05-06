from network_security_game import Network_Security_Environment
from scenarios import scenario_configuration, smaller_scenario_configuration, tiny_scenario_configuration
from game_components import *
from torch.utils.tensorboard import SummaryWriter
import numpy as np
from random import choice, random
import random
import pickle
import argparse
from timeit import default_timer as timer
import time
import logging

class NaiveQAgent:

    def __init__(self, env, alpha=0.1, gamma=0.6, epsilon=0.1):
        self.env = env
        self.alpha = alpha
        self.gamma = gamma 
        self.epsilon = epsilon
        self.q_values = {}

    def store_q_table(self,filename):
        with open(filename, "wb") as f:
            pickle.dump(self.q_values, f)
    
    def load_q_table(self,filename):
        with open(filename, "rb") as f:
            self.q_values = pickle.load(f)
    
    def move(self, state:GameState, testing=False) -> Action:
        """
        Given a state, select the next action to take
        This follows the target policy, which is e-greedy here
        a mix of random (exploratory) and behavioral (exploiting)
        """
        state = state.observation
        actions = self.env.get_valid_actions(state)
        if random.uniform(0, 1) <= self.epsilon and not testing: #random play
            action = choice(actions)
            if (state, action) not in self.q_values:
                # Assume a value of 0 if this is a new state.
                self.q_values[state,action] = 0
            return action
        else: #greedy play
            # Get qvalues for allowed actions in this state. 
            #  That is, temporaly create a qtable
            # Assume a value of 0 if this is a new state (not in the qtable)
            tmp = dict(((state,a), self.q_values.get((state,a), 0)) for a in actions)
            # find (state, action) pair with the highest q value
            action_max_value = max(tmp,key=tmp.get)
            #if the key is not in q_values, insert it
            if action_max_value not in self.q_values:
                self.q_values[action_max_value] = 0
            return action_max_value[1]
    
    def max_action_q(self, state:GameState) -> Action:
        """
        Given a state, select the next action to take
        This finds the action that maximices the state-action value
        This follows the behavioral policy that is being trained
        """
        state = state.observation
        # Get list of allowed actions
        actions = self.env.get_valid_actions(state)
        # Get q_values for given actions in current state
        tmp = dict(((state,a), self.q_values.get((state,a), 0)) for a in actions)
        # Find max q_value
        action_max_value = tmp[max(tmp,key=tmp.get)] 
        return action_max_value
    
    def play(self, state, testing=False) -> tuple:
        """
        Make a game play moves for a whole episode
        Select an action based on some policy
        Return an observation but as variables (not sure why)
        """
        # To sum the rewards
        rewards = 0
        while not state.done:
            # Select action
            action = self.move(state, testing)
            # Get next state of the environment
            next_state = self.env.step(action)
            # Update q-values
            if next_state.done:
                max_q_next = 0
            else:
                max_q_next = self.max_action_q(next_state)
            self.q_values[state.observation, action] = self.alpha * self.q_values[state.observation, action] + (1-self.alpha) * (next_state.reward + self.gamma * max_q_next)            
            rewards += next_state.reward
            #move to next state
            state = next_state
        return rewards, self.env.is_goal(state.observation), self.env.detected, self.env.timestamp

    def evaluate(self, state) -> tuple: #(cumulative_reward, goal?, detected?, num_steps)
        rewards = 0
        while not state.done:
            action = self.move(state, testing=True)
            next_state = self.env.step(action)
            rewards += next_state.reward
            state = next_state
        reached_goal = self.env.is_goal(state.observation)
        return rewards, reached_goal, self.env.detected, self.env.timestamp


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--episodes", help="Sets number of training episodes", default=1000, type=int)
    parser.add_argument("--epsilon", help="Sets epsilon for exploration", default=0.2, type=float)
    parser.add_argument("--gamma", help="Sets gamma for Q learing", default=0.9, type=float)
    parser.add_argument("--alpha", help="Sets alpha for learning rate", default=0.3, type=float)
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=25, type=int)
    parser.add_argument("--defender", help="Is defender present", default=True, action="store_true")
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1", type=str)
    parser.add_argument("--test", help="Do not train, only run test", default=False, action="store_true")
    parser.add_argument("--evaluate", help="Do not train, only run evaluation", default=False, action="store_true")
    parser.add_argument("--eval_each", help="During training, evaluate every this amount of episodes. Evaluation is for 100 episodes each time.", default=50, type=int)
    parser.add_argument("--eval_for", help="Sets evaluation length", default=100, type=int)
    parser.add_argument("--test_for", help="Sets evaluation length", default=1000, type=int)
    parser.add_argument("--random_start", help="Sets if starting position and goal data is randomized", default=False, action="store_true")
    parser.add_argument("--verbosity", help="Sets verbosity of the environment", default=0, type=int)
    parser.add_argument("--seed", help="Sets the random seed", type=int, default=42)
    parser.add_argument("--filename", help="Load previous model file", type=str)

    args = parser.parse_args()
    args.filename = "NaiveQAgent_" + ",".join(("{}={}".format(key, value) for key, value in sorted(vars(args).items()) if key not in ["evaluate", "eval_each", "eval_for"])) + ".pickle"

    logging.basicConfig(filename='q_naive_agent.log', filemode='a', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.INFO)
    logger = logging.getLogger('Qnaive-agent')

    run_name = f"netsecgame__qnaive-learning__{args.seed}__{int(time.time())}"
    writer = SummaryWriter(f"logs/{run_name}")
    writer.add_text(
        "hypherparameters", 
        "|param|value|\n|-|-|\n%s" % ("\n".join([f"|{key}|{value}|" for key, value in vars(args).items()]))
    )

    random.seed(args.seed)

    logger.info(f'Setting the network security environment')
    env = Network_Security_Environment(verbosity=0)
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

    # Training
    # Set the configuration of the game in the env
    logger.info(f'Initializing the environment')
    state = env.initialize(win_conditons=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps)
    # Instantiate the agent
    logger.info(f'Creating the agent')
    agent = NaiveQAgent(env, args.alpha, args.gamma, args.epsilon)

    try:
        # If given a stored qtable, load it
        logger.info(f'Loading a previous Qtable')
        agent.load_q_table(args.filename)
    except FileNotFoundError:
        logger.info(f"No previous qtable file found to load, starting with an emptly zeroed qtable")

    # Don't train if testing
    if not args.test:
        logger.info(f'Starting the training')
        for i in range(1, args.episodes + 1): 
            # Reset
            state = env.reset()
            # Play complete round
            ret, win, _, _ = agent.play(state)
            # Every X episodes, eval
            if i % args.eval_each == 0:
                wins = 0
                detected = 0
                returns = []
                num_steps = [] 
                num_win_steps = []
                num_detected_steps = []
                for j in range(args.eval_for):
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

                text = f'''Evaluated after {i} episodes, for {args.eval_for} episodes. 
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

        # Store the q table on disk 
        agent.store_q_table(args.filename)

    # Test
    wins = 0
    detected = 0
    returns = []
    num_steps = []
    num_win_steps = []  
    num_detected_steps = []
    start_t = timer()
    for i in range(args.test_for + 1):
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
    
        # Print and report every 100 test episodes
        if i % 100 == 0 and i != 0:
            text = f'''Test {i} episodes. 
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


    text = f'''Final test after {i} episodes 
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
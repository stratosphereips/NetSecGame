# Authors:  Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
#           Arti       
from network_security_game import Network_Security_Environment
from environment import *
from game_components import *
import numpy as np
from random import choice, random, seed
import random
import pickle
import sys
import argparse
from timeit import default_timer as timer
import logging
from torch.utils.tensorboard import SummaryWriter
import time

class QAgent:
    """
    Class implementing the Q-Learning algorithm
    """

    def __init__(self, env, alpha=0.1, gamma=0.6, epsilon=0.1):
        self.env = env
        self.alpha = alpha
        self.gamma = gamma 
        self.epsilon = epsilon
        self.q_values = {}
        #self.counts = {}

    def store_q_table(self,filename):
        with open(filename, "wb") as f:
            pickle.dump(self.q_values, f)
    
    def load_q_table(self,filename):
        with open(filename, "rb") as f:
            self.q_values = pickle.load(f)
    
    def move(self, state:GameState, testing=False) -> Action:
        state = state.observation
        actions = self.env.get_valid_actions(state)
        if random.uniform(0, 1) <= self.epsilon and not testing:
            a = choice(actions)
            if (state, a) not in self.q_values:
                self.q_values[state, a] = 0
            return a
        else: #greedy play
            #select the acion with highest q_value
            tmp = dict(((state,a), self.q_values.get((state,a), 0)) for a in actions)
            max_q_key = max(tmp, key=tmp.get)
            if max_q_key not in self.q_values:
                self.q_values[max_q_key] = 0
                #self.counts[max_q_key] = 0
            return max_q_key[1]
    
    def max_action_q(self, state:GameState) -> Action:
        state = state.observation
        actions = self.env.get_valid_actions(state)
        tmp = dict(((state,a), self.q_values.get((state,a), 0)) for a in actions)
        return tmp[max(tmp,key=tmp.get)] #return maximum Q_value for a given state (out of available actions)
    
    def play(self, state, testing=False) -> tuple:
        """
        Play a complete episode from beginning to end

        1. Get next action 
        2. Step and get next state
        3. Get max action of next state
        4. Update q table
        5. Store rewards
        6. loop
        """
        rewards = 0
        while not state.done:
            #select action
            action = self.move(state, testing)
            #get next state of the environment
            next_state = self.env.step(action)           

            # Find max Q-Value for next state
            if next_state.done:
                max_q_next = 0
            else:
                max_q_next = self.max_action_q(next_state)

            # Update q values
            new_Q = self.q_values[state.observation, action] + self.alpha*(next_state.reward + self.gamma * max_q_next - self.q_values[state.observation, action])
            self.q_values[state.observation, action] = new_Q
            
            rewards += next_state.reward

            #move to next state
            state = next_state

        # If state is 'done' this should throw an error of missing variables
        return rewards, next_state.reward > 0, self.env.detected, self.env.timestamp

    def evaluate(self, state) -> tuple: #(cumulative_reward, goal?, detected?, num_steps)
        """
        Evaluate the agent so far for one episode

        Do without learning
        """
        rewards = 0
        while not state.done:
            action = self.move(state, testing=True)
            next_state = self.env.step(action)
            rewards += next_state.reward
            state = next_state
        #reached_goal = self.env.is_goal(state.observation)
        return rewards, next_state.reward > 0, self.env.detected, self.env.timestamp


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", help="Sets number of training epochs", default=1000, type=int)
    parser.add_argument("--epsilon", help="Sets epsilon for exploration", default=0.2, type=float)
    parser.add_argument("--gamma", help="Sets gamma for Q learing", default=0.9, type=float)
    parser.add_argument("--alpha", help="Sets alpha for learning rate", default=0.3, type=float)
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=25, type=int)
    parser.add_argument("--defender", help="Is defender present", default=True, action="store_true")
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1", type=str)
    parser.add_argument("--evaluate", help="Do not train, only run evaluation", default=False, action="store_true")
    parser.add_argument("--eval_each", help="During training, evaluate every this amount of episodes. Evaluation is for 100 episodes each time.", default=50, type=int)
    parser.add_argument("--eval_for", help="Sets final evaluation length", default=1000, type=int)
    parser.add_argument("--random_start", help="Sets evaluation length", default=False, action="store_true")
    parser.add_argument("--seed", help="Sets the random seed", type=int, default=42)
    args = parser.parse_args()
    args.filename = "QAgent_" + ",".join(("{}={}".format(key, value) for key, value in sorted(vars(args).items()) if key not in ["evaluate", "eval_each", "eval_for"])) + ".pickle"

    logging.basicConfig(filename='q_agent.log', filemode='a', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.INFO)
    logger = logging.getLogger('Q-agent')

    # Setup tensorboard
    run_name = f"netsecgame__qlearning__{args.seed}__{int(time.time())}"
    writer = SummaryWriter(f"logs/{run_name}")
    writer.add_text(
        "hypherparameters", 
        "|param|value|\n|-|-|\n%s" % ("\n".join([f"|{key}|{value}|" for key, value in vars(args).items()]))
    )


    #set random seed
    #random.seed(42)
    #random.seed(1234)
    #random.seed(10)
    #random.seed(19)
    # Set the random seed 
    random.seed(args.seed)


    logger.info(f'Setting the network security environment')
    env = Network_Security_Environment(random_start=args.random_start, verbosity=0)
    if args.scenario == "scenario1":
        env.process_cyst_config(scenarios.scenario_configuration.configuration_objects)
    elif args.scenario == "scenario1_small":
        env.process_cyst_config(scenarios.smaller_scenario_configuration.configuration_objects)
    elif args.scenario == "scenario1_tiny":
        env.process_cyst_config(scenarios.tiny_scenario_configuration.configuration_objects)
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
    logger.info(f'Initializing the environment')
    state = env.initialize(win_conditons=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps)
    logger.info(f'Creating the agent')
    agent = QAgent(env, args.alpha, args.gamma, args.epsilon)
    try:
        # Load a previous qtable from a pickled file
        logger.info(f'Loading a previous Qtable')
        agent.load_q_table(args.filename)
    except FileNotFoundError:
        logger.info(f"No previous qtable file found to load, starting with an emptly zeroed qtable")
    
    # If we are not evaluating the model
    if not args.evaluate:
        # Run for some episodes 
        logger.info(f'Starting the training')
        for i in range(1, args.episodes + 1):
            # Reset
            state = env.reset()
            # Play complete round
            ret, win,_,_ = agent.play(state)
            # Every X episodes, eval
            if i % args.eval_each == 0:
                wins = 0
                detected = 0
                rewards = []
                num_steps = [] 
                for j in range(100):
                    state = env.reset()
                    ret, win, detection, steps = agent.evaluate(state)
                    if win:
                        wins += 1
                    if detection:
                        detected +=1
                    rewards += [ret]
                    num_steps += [steps]
                text = f"Evaluated after {i} episodes: Winrate={(wins/(j+1))*100}%, detection_rate={(detected/(j+1))*100}%, average_return={np.mean(rewards)} +- {np.std(rewards)}, average_steps={np.mean(num_steps)} +- {np.std(num_steps)}"
                print(text)
                logger.info(text)
                # Store in tensorboard
                writer.add_scalar("charts/episodic_return", np.mean(rewards), i)
                writer.add_scalar("charts/episodic_length", np.mean(num_steps), i)
                writer.add_scalar("charts/episodic_wins", np.mean(num_steps), i)

        # Store the q table on disk
        agent.store_q_table(args.filename)

    # FINAL EVALUATION
    wins = 0
    detected = 0
    rewards = []
    num_steps = [] 
    for i in range(args.eval_for):
        state = env.reset()
        ret, win, detection, steps = agent.evaluate(state)
        if win:
            wins += 1
        if detection:
            detected +=1
        rewards += [ret]
        num_steps += [steps]
    text = f"Final evaluation ({i+1} episodes): Winrate={(wins/(i+1))*100}%, detection_rate={(detected/(i+1))*100}%, average_return={np.mean(rewards)} +- {np.std(rewards)}, average_steps={np.mean(num_steps)} +- {np.std(num_steps)}"
    print(text)
    logger.info(text)
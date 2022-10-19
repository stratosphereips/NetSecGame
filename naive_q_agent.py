from environment import *
from environment_v2 import EnvironmentV2
from game_components import *
import numpy as np
from random import choice, random
import random
import pickle
import argparse
from timeit import default_timer as timer

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
        state = state.observation
        actions = self.env.get_valid_actions(state)
        if random.uniform(0, 1) <= self.epsilon and not testing: #random play
            a = choice(actions)
            if (state, a) not in self.q_values:
                self.q_values[state,a] = 0
            return a
        else: #greedy play
            #get q values for allowed actions
            tmp = dict(((state,a), self.q_values.get((state,a), 0)) for a in actions)
            # find (state, action) pair with the highest q value
            max_q_key = max(tmp,key=tmp.get)
            #if the key is not in q_values, insert it
            if max_q_key not in self.q_values:
                self.q_values[max_q_key] = 0
            return max_q_key[1]
    
    def max_action_q(self, state:GameState) -> Action:
        state = state.observation
        #get list of allowed actions
        actions = self.env.get_valid_actions(state)
        #get q_values for given actions in current state
        tmp = dict(((state,a), self.q_values.get((state,a), 0)) for a in actions)
        #find max q_value
        return tmp[max(tmp,key=tmp.get)]   
    
    def play(self, state, testing=False) -> tuple:
        rewards = 0
        while not state.done:
            #select action
            action = self.move(state, testing)
            #get next state of the environment
            next_state = self.env.step(action)
            #update q values
            if next_state.done:
                max_q_next = 0
            else:
                max_q_next = self.max_action_q(next_state)
            #self.q_values[state.observation, action] = self.alpha*self.q_values[state.observation, action] + (1-self.alpha)*(next_state.reward + self.gamma*max_q_next)
            self.q_values[state.observation, action] = self.alpha*self.q_values[state.observation, action] + (1-self.alpha)*(next_state.reward + self.gamma*max_q_next)            
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
    parser.add_argument("--epochs", help="Sets number of training epochs", default=10000, type=int)
    parser.add_argument("--epsilon", help="Sets epsilon for exploration", default=0.2, type=float)
    parser.add_argument("--gamma", help="Sets gamma for Q learing", default=0.9, type=float)
    parser.add_argument("--alpha", help="Sets alpha for learning rate", default=0.1, type=float)
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=25, type=int)
    parser.add_argument("--defender", help="Is defender present", default=False, action="store_true")
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1", type=str)
    parser.add_argument("--evaluate", help="Do not train, only run evaluation", default=False, action="store_true")
    parser.add_argument("--eval_each", help="Sets periodic evaluation during training", default=500, type=int)
    parser.add_argument("--eval_for", help="Sets evaluation length", default=1000, type=int)
    parser.add_argument("--random_start", help="Sets if starting position and goal data is randomized", default=False, action="store_true")

    args = parser.parse_args()
    args.filename = "NaiveQAgent_" + ",".join(("{}={}".format(key, value) for key, value in sorted(vars(args).items()) if key not in ["evaluate", "eval_each", "eval_for"])) + ".pickle"

    #set random seed
    
    env = EnvironmentV2(verbosity=0)
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
    #TRAINING
    state = env.initialize(win_conditons=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps)
    agent = NaiveQAgent(env, args.alpha, args.gamma, args.epsilon)
    try:
        agent.load_q_table(args.filename)
    except FileNotFoundError:
        print("No file found, starting from zeros")
    if not args.evaluate:
        for i in range(args.epochs):
            state = env.reset()
            ret, win,_,_ = agent.play(state)
            if i % args.eval_each == 0:
                wins = 0
                detected = 0
                rewards = [] 
                for j in range(100):
                    state = env.reset()
                    ret, win, detection, steps = agent.evaluate(state)
                    if win:
                        wins += 1
                    if detection:
                        detected +=1
                    rewards += [ret]
                print(f"Evaluated after {i} episodes: Winrate={(wins/(j+1))*100}%, detection_rate={(detected/(j+1))*100}%, average_return={np.mean(rewards)} +- {np.std(rewards)}")
        agent.store_q_table(args.filename)

    #FINAL EVALUATION
    wins = 0
    detected = 0
    rewards = [] 
    start_t = timer()
    for i in range(args.eval_for):
        state = env.reset()
        ret, win, detection, steps = agent.evaluate(state)
        if win:
            wins += 1
        if detection:
            detected +=1
        rewards += [ret]
    print(f"Final evaluation ({i+1} episodes): Winrate={(wins/(i+1))*100}%, detection_rate={(detected/(i+1))*100}%, average_return={np.mean(rewards)} +- {np.std(rewards)}.")
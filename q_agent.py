from environment import *
from game_components import *
import numpy as np
from random import choice, random, uniform
import random
import pickle
import sys
import argparse
from datetime import datetime
# env = Environment()
# #print(env)
# env.read_topology("test.yaml")

# # define attacker goal and initial location 
# goal = {"known_networks":[], "known_hosts":[], "controlled_hosts":["192.168.0.4"], "known_services":{}, "known_data":{}}
# attacker_start = {"known_networks":[], "known_hosts":["192.168.0.5"], "controlled_hosts":["192.168.0.5"], "known_services":{}, "known_data":{}}
# state = env.initialize(win_conditons=goal, defender_positions={}, attacker_start_position=attacker_start, max_steps=100)

# # hyperparameters 
# alpha = 0.1
# gamma = 0.6
# epsilon = 0.1

# q_table = np.zeros ((env.get_all_states, env.get_valid_actions))


# episodes = 1000
# for episode in range(1, episodes+1):
#     state = env.reset()
#     done = False
#     score = 0

#     while not state.done:
        
#         if random.uniform(0, 1) > epsilon:
#             actions = np.argmax(q_table[state,:])
#         else:
#             actions = choice(env.get_valid_actions(state.observation, transitions))
                              
#         new_state = env.step(actions)
        
#         score += state.reward

#         #Update Q-table for Q(s,a)
#         q_table[state, actions] = q_table[state, actions] + alpha * (reward + gamma * 
#         np.max(q_table[new_state,:]) - q_table[state,actions])
    
    
      
#     print('Episode {}: Score:{}'.format(episode, score))

class QAgent:

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
        if random.uniform(0, 1) <= self.epsilon and not testing:
            a = choice(actions)
            if (state, a) not in self.q_values:
                self.q_values[state,a] = 0
            return a
        else: #greedy play
            max_q_value = -np.inf
            max_action = None
            for a in actions:
                if (state, a) not in self.q_values.keys():
                    self.q_values[state,a] = 0
                q_value = self.q_values[state,a]
                if q_value > max_q_value:
                    max_q_value = q_value
                    max_action = a
            return max_action
    
    def max_action_q(self, state:GameState) -> Action:
        state = state.observation
        actions = self.env.get_valid_actions(state)
        max_q_value = -np.inf
        max_action = None
        for a in actions:
            if (state, a) not in self.q_values.keys():
                self.q_values[state,a] = 0
            q_value = self.q_values[state,a]
            if q_value > max_q_value:
                max_q_value = q_value
                max_action = a
        return max_q_value

    def play(self, state, testing=False) -> tuple:
        rewards = 0
        while not state.done:
            #select action
            action = self.move(state, testing)
            #get next state of the environment
            next_state = self.env.step(action)
            #update q values
            new_Q = self.q_values[state.observation, action] + self.alpha*(next_state.reward + self.gamma*(self.max_action_q(next_state)) - self.q_values[state.observation, action])
            self.q_values[state.observation, action] = new_Q
            
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
    parser.add_argument("--epochs", help="Sets number of training epochs", default=1000, type=int)
    parser.add_argument("--epsilon", help="Sets epsilon for exploration", default=0.15, type=float)
    parser.add_argument("--gamma", help="Sets gamma for Q learing", default=0.9, type=float)
    parser.add_argument("--alpha", help="Sets alpha for learning rate", default=0.2, type=float)
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=10, type=int)
    args = parser.parse_args()
    args.filename = "QAgent_" + ",".join(("{}={}".format(key, value) for key, value in sorted(vars(args).items()))) + ".pickle"

    
    env = Environment(verbosity=0)
    #print(env)
    env.process_cyst_config(configuration_objects)

    # define attacker goal and initial location
    goal = {"known_networks":set(), "known_hosts":{}, "controlled_hosts":set("192.168.1.2"), "known_services":{}, "known_data":{}}
    attacker_start = {"known_networks":set(), "known_hosts":set(), "controlled_hosts":{"213.47.23.195", "192.168.2.2"}, "known_services":{}, "known_data":{}}

    #TRAINING
    state = env.initialize(win_conditons=goal, defender_positions={}, attacker_start_position=attacker_start, max_steps=args.max_steps)
    agent = QAgent(env, args.alpha, args.gamma, args.epsilon)
    for i in range(args.epochs):
        state = env.reset()
        ret, win,_,_ = agent.play(state)
        if i % 500 == 0:
            wins = 0
            detected = 0
            rewards = 0 
            for j in range(100):
                state = env.reset()
                ret, win, detection, steps = agent.evaluate(state)
                if win:
                    wins += 1
                if detection:
                    detected +=1
                rewards += ret
            print(f"Evaluated after {i} episodes: Winrate={(wins/(j+1))*100}%, detection_rate={(detected/(j+1))*100}%, average_return={(rewards/(j+1))}")
    agent.store_q_table(args.filename)

    #EVALUATION
    wins = 0
    detected = 0
    rewards = 0 
    for i in range(500):
        state = env.reset()
        ret, win, detection, steps = agent.evaluate(state)
        if win:
            wins += 1
        if detection:
            detected +=1
        rewards += ret
    print(f"Final evaluation ({i+1} episodes): Winrate={(wins/(i+1))*100}%, detection_rate={(detected/(i+1))*100}%, average_return={(rewards/(i+1))}")

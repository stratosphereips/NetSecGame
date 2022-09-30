from environment import *
from game_components import *
import numpy as np
from random import choice, random, uniform
import random
import pickle
import sys
import argparse

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
    
    def move(self, state:GameState) -> Action:
        state = state.observation
        actions = self.env.get_valid_actions(state)
        if random.uniform(0, 1) > self.epsilon:
            a = choice(actions)
            if (state, a) not in self.q_values:
                self.q_values[state,a] = 0
            return a
        else:
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

    def play(self, state):
        rewards = 0
        steps = 0
        while not state.done:
            steps += 1
            action = self.move(state)
            next_state = self.env.step(action)
            new_Q = self.alpha*self.q_values[state.observation, action] + (1-self.alpha)*next_state.reward + self.gamma*(self.max_action_q(next_state)) - self.q_values[state.observation, action]
            self.q_values[state.observation, action] = new_Q
            #print("Action:", action, "reward=", next_state.reward, "goal=", self.env.is_goal(next_state.observation))
            rewards += next_state.reward
            state = next_state
        return rewards, self.env.is_goal(state.observation), steps

if __name__ == '__main__':

    
    env = Environment()
    #print(env)
    env.process_cyst_config(configuration_objects)

    # define attacker goal and initial location
    goal = {"known_networks":set(), "known_hosts":{"192.168.1.4"}, "controlled_hosts":set(), "known_services":{}, "known_data":{}}
    attacker_start = {"known_networks":set(), "known_hosts":set(), "controlled_hosts":{"213.47.23.195", "192.168.2.2"}, "known_services":{}, "known_data":{}}

    state = env.initialize(win_conditons=goal, defender_positions={}, attacker_start_position=attacker_start, max_steps=50)
    agent = NaiveQAgent(env)
    for i in range(1000):
        state = env.reset()
        ret, win,_ = agent.play(state)
    agent.store_q_table("q_values.pickle")

    agent2 = NaiveQAgent(env)

    agent2.load_q_table("q_values.pickle")
    for i in range(50):
        state = env.reset()
        ret, win, steps = agent2.play(state)
        print(f"Episode {i}:{steps} steps, rewards:{ret}, win:{win}")
        print("----------")
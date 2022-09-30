from environment import *
import game_components
import numpy as np
from random import choice

env = Environment()
#print(env)
env.read_topology("test.yaml")

# define attacker goal and initial location 
goal = {"known_networks":[], "known_hosts":[], "controlled_hosts":["192.168.0.4"], "known_services":{}, "known_data":{}}
attacker_start = {"known_networks":[], "known_hosts":["192.168.0.5"], "controlled_hosts":["192.168.0.5"], "known_services":{}, "known_data":{}}
state = env.initialize(win_conditons=goal, defender_positions={}, attacker_start_position=attacker_start, max_steps=100)

# hyperparameters 
alpha = 0.1
gamma = 0.6
epsilon = 0.1

q_table = np.zeros ((env.get_all_states, env.get_valid_actions))


episodes = 1000
for episode in range(1, episodes+1):
    state = env.reset()
    done = False
    score = 0

    while not state.done:
        
        if random.uniform(0, 1) > epsilon:
            actions = np.argmax(q_table[state,:])
        else:
            actions = choice(env.get_valid_actions(state.observation, transitions))
                              
        new_state = env.step(actions)
        
        score += state.reward

        #Update Q-table for Q(s,a)
        q_table[state, actions] = q_table[state, actions] + alpha * (reward + gamma * 
        np.max(q_table[new_state,:]) - q_table[state,actions])
    
    
      
    print('Episode {}: Score:{}'.format(episode, score))



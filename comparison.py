from q_agent import QAgent
from naive_q_agent import NaiveQAgent
from double_q_agent import DoubleQAgent
import numpy as np
import matplotlib
from environment_v2 import EnvironmentV2
import math
import pickle
from environment import *
from game_components import *

seeds = [31,45,21321312, 675,545]
training_episodes=25001
eval_each = 500
eval_for = 500


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
    "controlled_hosts":{"213.47.23.195","192.168.2.0/24"},
    "known_services":{},
    "known_data":{}
}

#prepare the environment
env = EnvironmentV2(random_start=True)
env.process_cyst_config(scenario_configuration.configuration_objects)
state = env.initialize(win_conditons=goal, defender_positions=True, attacker_start_position=attacker_start, max_steps=25)

#prepare agents
naive_a =  NaiveQAgent(epsilon=0.2, gamma=0.9, alpha=0.8, env=env)
q_a = QAgent(alpha=0.3, epsilon=0.2, gamma=0.9, env=env)
double_a = DoubleQAgent(alpha=0.2, epsilon=0.2, gamma=0.9, env=env)
agents = [naive_a, q_a, double_a]

# #prepare numpy arrays for results
# results_rewards = np.zeros([len(agents), math.ceil(training_episodes/eval_each), len(seeds), eval_for])
# results_wins = np.zeros([len(agents), math.ceil(training_episodes/eval_each), len(seeds), eval_for])
# results_detections = np.zeros([len(agents), math.ceil(training_episodes/eval_each), len(seeds), eval_for])

# #run the training
# for s in range(len(seeds)):
#     seed(seeds[s])
#     for a in range(len(agents)):
#         agent = agents[a]
#         #pointer = 0
#         for i in range(training_episodes):
#             if i % eval_each == 0:
#                 for j in range(eval_for):
#                     state = env.reset()
#                     ret, win, detection, _ = agent.evaluate(state)
#                     results_rewards[a][int(i/eval_each)][s][j] = ret
#                     results_wins[a][int(i/eval_each)][s][j] = win
#                     results_detections[a][int(i/eval_each)][s][j] = detection
#                 print(f"S:{s}, A:{a}, train_step:{i}")
#                 #pointer +=1
#             state = env.reset()
#             ret, win,_,_ = agent.play(state)
#         print(f"\tagent{a} done")
#     print(f"seed{s} done")
# with open(f"learning_comparison_{training_episodes}_{eval_each}_{eval_for}.pickle", "wb") as f:
#     pickle.dump({"returns":results_rewards, "wins":results_wins, "detections":results_detections,
#      "parameters":{"seeds":seeds, "training_episodes":training_episodes,"eval_each":eval_each,"eval_for":eval_for}}, f)


#prepare numpy arrays for results
results_rewards = np.zeros([len(agents), math.ceil(training_episodes/eval_each), eval_for])
results_wins = np.zeros([len(agents), math.ceil(training_episodes/eval_each), eval_for])
results_detections = np.zeros([len(agents), math.ceil(training_episodes/eval_each), eval_for])

#run the training
for i in range(training_episodes):
    for a in range(len(agents)):
        agent = agents[a]
        if i % eval_each == 0:
            for j in range(eval_for):
                state = env.reset()
                ret, win, detection, _ = agent.evaluate(state)
                results_rewards[a][int(i/eval_each)][j] = ret
                results_wins[a][int(i/eval_each)][j] = win
                results_detections[a][int(i/eval_each)][j] = detection
            print(f"A:{a}, train_step:{i}")
        #pointer +=1
        state = env.reset()
        ret, win,_,_ = agent.play(state)

with open(f"learning_comparison_{training_episodes}_{eval_each}_{eval_for}.pickle", "wb") as f:
    pickle.dump({"returns":results_rewards, "wins":results_wins, "detections":results_detections,
     "parameters":{"seeds":seeds, "training_episodes":training_episodes,"eval_each":eval_each,"eval_for":eval_for},
     "agents":agents
     }, f)
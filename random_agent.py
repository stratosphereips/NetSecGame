#Author: Ondrej Lukas, ondrej.lukas@aic.cvut.cz
from environment import *
from environment_v2 import EnvironmentV2
from game_components import *
from random import choice, seed
import argparse

class RandomAgent:

    def __init__(self, env):
        self.env = env
    
    def move(self, state:GameState, testing=False) -> Action:
        state = state.observation
        actions = self.env.get_valid_actions(state)
        return choice(actions)
    
    def play(self, state, testing=False) -> tuple:
        rewards = 0
        while not state.done:
            #select action
            action = self.move(state, testing)
            #get next state of the environment
            next_state = self.env.step(action)
            #collect reward
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
        #reached_goal = self.env.is_goal(state.observation)
        return rewards, self.env.is_goal(state.observation), self.env.detected, self.env.timestamp


if __name__ == '__main__':
    # set seed 
    seed(42)
    parser = argparse.ArgumentParser()
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=25, type=int)
    parser.add_argument("--defender", help="Is defender present", default=False, action="store_true")
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1_small", type=str)
    parser.add_argument("--verbosity", help="Sets verbosity of the environment", default=0, type=int)
    args = parser.parse_args()

    env = EnvironmentV2(verbosity=args.verbosity)
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
        "controlled_hosts":{"213.47.23.195","192.168.2.2/24"},
        "known_services":{},
        "known_data":{}
    }
    #TRAINING
    state = env.initialize(win_conditons=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps)
    agent = RandomAgent(env)

    #FINAL EVALUATION
    wins = 0
    detected = 0
    rewards = []
    num_steps = 0
    for i in range(5000):
        state = env.reset()
        ret, win, detection, steps = agent.evaluate(state)
        if win:
            wins += 1
        if detection:
            detected +=1
        rewards += [ret]
    print(f"Final evaluation ({i+1} episodes): Winrate={(wins/(i+1))*100}%, detection_rate={(detected/(i+1))*100}%, average_return={np.mean(rewards)}+-{np.std(rewards)}.")
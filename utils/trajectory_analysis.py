import json
import numpy as np
import sys
import os 
import utils
import matplotlib.pyplot as plt



sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__) )))
from env.game_components import GameState, Action, ActionType

def read_json(filename):
    with open(filename, "r") as infile:
        data = json.load(infile)
    return data

def compute_mean_length(game_plays:list)->float:
    lengths = []
    for play in game_plays:
        if play["end_reason"]:
            lengths.append(len(play["trajectory"]))
    return np.mean(lengths)

def state_diff(s1:GameState, s2: GameState) -> float:
    diff = len(s1.known_networks-s2.known_networks) +  len(s2.known_networks-s1.known_networks)
    diff += len(s1.known_hosts-s2.known_hosts) +  len(s2.known_hosts-s1.known_hosts)
    diff += len(s1.controlled_hosts-s2.controlled_hosts) +  len(s2.controlled_hosts-s1.controlled_hosts)
    
    diff_services = 0
    for key in s1.known_services.keys():
        if key in s2.known_services:
            diff_services += len(s1.known_services[key]-s2.known_services[key]) + len(s2.known_services[key]-s1.known_services[key])
        else:
            diff_services += len(s1.known_services[key])
    for key in s2.known_services.keys():
        if key not in s1.known_services:
            diff_services += len(s2.known_services[key])

    diff_data = 0
    for key in s1.known_data.keys():
        if key in s2.known_data:
            diff_data += len(s1.known_data[key]-s2.known_data[key]) + len(s2.known_data[key]-s1.known_data[key])
        else:
            diff_data += len(s1.known_data[key])
    for key in s2.known_data.keys():
        if key not in s1.known_data:
            diff_data += len(s2.known_data[key])

    diff += diff_services
    diff += diff_data
    return diff



def compare_action_type_sequence(game_plays:list, end_reason=None):
    actions_per_step = {}
    for play in game_plays:
        if end_reason and play["end_reason"] != end_reason:
            continue
        for i,step in enumerate(play["trajectory"]):
            if i not in actions_per_step.keys():
                actions_per_step[i] = set()
            #state = GameState.from_dict(step["s"])
            action = Action.from_dict(step["a"])
            # reward = step["r"]
            # next_state = step["s_next"]
            actions_per_step[i].add(action.type)
    for i, actions in actions_per_step.items():
        print(f"Step {i}, #different action_types:{len(actions)}")

def plot_histogram(data:dict, fileneme, ignore_types = [ActionType.JoinGame, ActionType.QuitGame, ActionType.ResetGame]):
    fig, ax = plt.subplots()
    bottom = np.zeros(len(data))
    action_counts = {}
    names = []
    for action_type in ActionType:
        if action_type not in ignore_types:
            tmp = np.zeros(len(data))
            names.append(str(action_type))
            for i in range(len(data)):
                tmp[i] = data[i][action_type]
            action_counts[action_type] = tmp
    
    for action_type, values in action_counts.items():
        ax.bar(data.keys(), values, label=str(action_type).lstrip("ActionType."), bottom=bottom)
        bottom += values
    ax.set_title("ActionType distribution per step")
    #plt.xticks(np.arange(0, len(data), step=1), labels=[i+1 for i in range(0,len(data))])
    plt.xlabel("Step number")
    plt.ylabel("ActionType usage (%)")
    ax.legend(loc='best', ncol=1)
    plt.savefig(fileneme)

def get_action_type_hist_per_step(game_plays:list, end_reason=None, filename="action_type_histogram.png"):
    actions_per_step = {}
    for play in game_plays:
        if end_reason and play["end_reason"] != end_reason:
            continue
        for i,step in enumerate(play["trajectory"]):
            if i not in actions_per_step.keys():
                actions_per_step[i] = {action_type:0 for action_type in ActionType}
            #state = GameState.from_dict(step["s"])
            action = Action.from_dict(step["a"])
            # reward = step["r"]
            # next_state = step["s_next"] 
            actions_per_step[i][action.type] += 1

    to_plot = {}
    for i, actions in actions_per_step.items():
        total_actions = sum(actions.values())
        per_step = {}
        for a in actions:
            per_step[a] = actions[a]/total_actions
        to_plot[i] = per_step
        print(f"Step {i} ({total_actions}), #different action_types:{list(actions.values())[:-3]}")
    if not os.path.exists("figures"):
        os.makedirs("figures")
    plot_histogram(to_plot , os.path.join("figures", filename))

def compare_state_sequence(game_plays:list, end_reason=None)->float:
    states_per_step = {}
    for play in game_plays:
        if end_reason and play["end_reason"] != end_reason:
            continue
        for i,step in enumerate(play["trajectory"]):
            if i not in states_per_step.keys():
                states_per_step[i] = set()
            state = GameState.from_dict(step["s"])
            # action = step["a"]
            # reward = step["r"]
            # next_state = step["s_next"]
            states_per_step[i].add(utils.state_as_ordered_string(state))
    for i, states in states_per_step.items():
        print(f"Step {i}, #different states:{len(states)}")



game_plays = read_json(sys.argv[1])
print(f"mean episode length:{compute_mean_length(game_plays)}")
compare_state_sequence(game_plays)
print("-------------------------------")
compare_action_type_sequence(game_plays)
print("-------------------------------")
get_action_type_hist_per_step(game_plays)
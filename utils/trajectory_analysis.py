import json
import numpy as np
import sys
import os 
import utils
import matplotlib.pyplot as plt
import matplotlib
from mpl_toolkits.axes_grid1 import make_axes_locatable
import umap
from sklearn.preprocessing import StandardScaler



sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__) )))
from env.game_components import GameState, Action, ActionType

def combine_trajecories(filenames, output_filename):
    "Merges trajectory files"
    data =[]
    for file in filenames:
        data += read_json(file)
    with open(output_filename, "w") as outfile:
        json.dump(data, outfile)

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

def action_diff(a1:Action, a2: Action)->float:
    action_type_diff = 0 if a1.type is a2.type else 1
    src_host_diff = 0 if a1.parameters["source_host"] == a2.parameters["source_host"] else 1
    return action_type_diff+src_host_diff
    
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

def plot_barplot(data:dict, fileneme, ignore_types = [ActionType.JoinGame, ActionType.QuitGame, ActionType.ResetGame]):
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
        ax.bar(data.keys(), values, label=str(action_type).lstrip("ActionType."),bottom=bottom)
        #ax.plot(data.keys(), values, label=str(action_type).lstrip("ActionType."))
        bottom += values
    ax.set_title("ActionType distribution per step - Q-learning")
    ax.minorticks_on()
    #plt.xticks(np.arange(0, len(data), step=1), labels=[i+1 for i in range(0,len(data))])
    plt.xlabel("Step number")
    plt.ylim(top=530)
    plt.xlim(right=100)
    
    plt.ylabel("ActionType usage")
    ax.legend(loc='best', ncol=1)
    plt.savefig(fileneme)
    plt.close()

def plot_histogram(data:dict, fileneme, ignore_types = [ActionType.JoinGame, ActionType.QuitGame, ActionType.ResetGame]):
    fig, ax = plt.subplots()
    for action_type in ActionType:
        if action_type not in ignore_types:
            name = str(action_type).lstrip("ActionType.") 
            if action_type not in data:
                data[action_type] = [0]
            ax.hist(data[action_type],bins=max([max(x) for x in data.values()]), label=name, alpha=0.5)
    ax.set_title("ActionType distribution per step")
    #plt.xticks(np.arange(0, len(data), step=1), labels=[i+1 for i in range(0,len(data))])
    plt.xlabel("Step number")
    plt.ylabel("ActionType usage")
    ax.legend(loc='best', ncol=1)
    plt.savefig(fileneme)
    plt.close()   

def get_action_type_histogram_per_step(game_plays:list, end_reason=None, filename="action_type_histogram.png"):
    """
    Prepares data and generates histogram of action type distribution per step
    """
    actions_step_usage = {}
    for play in game_plays:
        if end_reason and play["end_reason"] != end_reason:
            continue
        for i,step in enumerate(play["trajectory"]):
            action = Action.from_dict(step["a"])
            if action.type not in actions_step_usage:
                actions_step_usage[action.type] = []
            actions_step_usage[action.type].append(i)
    if not os.path.exists("figures"):
        os.makedirs("figures")
    plot_histogram(actions_step_usage , os.path.join("figures", filename))

def get_action_type_barplot_per_step(game_plays:list, end_reason=None, filename="action_type_barplot.png"):
    """
    Prepares data and generates stacked barplot of action type distribution per step
    """
    actions_per_step = {}
    for play in game_plays:
        if end_reason and play["end_reason"] not in end_reason:
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
        per_step = {}
        for a in actions:
            per_step[a] = actions[a]
        to_plot[i] = per_step
        #print(f"Step {i} ({total_actions}), #different action_types:{list(actions.values())[:-3]}")
    if not os.path.exists("figures"):
        os.makedirs("figures")
    plot_barplot(to_plot , os.path.join("figures", filename))

def barplot_action_efficiency(data:list, model_names:list, filename="action_efficiency_plot.png", end_reason=None):
    width = 0.18  # the width of the bars
    multiplier = 0
    action_data = {
        ActionType.ScanNetwork:np.zeros(len(model_names)),
        ActionType.FindServices:np.zeros(len(model_names)),
        ActionType.FindData:np.zeros(len(model_names)),
        ActionType.ExploitService:np.zeros(len(model_names)),
        ActionType.ExfiltrateData:np.zeros(len(model_names)),
        }

    for i,trajectories in enumerate(data):
        num_trajectories = 0
        for t in trajectories:
            if t["end_reason"] in end_reason:
                num_trajectories += 1
                for step in t["trajectory"]:
                    action = Action.from_dict(step["a"])
                    action_data[action.type][i] += 1
        for action_type in action_data:
            action_data[action_type][i] = np.round(num_trajectories/action_data[action_type][i], decimals=2)
    x = np.arange(len(model_names))  # the label locations
    fig, ax = plt.subplots(figsize=(10, 6))
    for attribute, measurement in action_data.items():
        offset = width * multiplier
        rects = ax.bar(x + offset, measurement, width, label=attribute)
        ax.bar_label(rects, padding=3)
        multiplier += 1
    ax.set_ylabel('Action efficiency (%)')
    ax.set_title(f'Mean action efficiency for trajectories ending by with {end_reason}')
    ax.set_xticks(x + 2*width, model_names)
    ax.legend([str(x).lstrip("ActionType.") for x in action_data.keys()],loc='best')
    ax.set_ylim(0, 1)
    plt.savefig(os.path.join("figures", filename))
    plt.close()

def compare_state_sequence(game_plays:list, end_reason=None)->float:
    states_per_step = {}
    for play in game_plays:
        if end_reason and play["end_reason"] != end_reason:
            continue
        for i,step in enumerate(play["trajectory"]):
            if i not in states_per_step.keys():
                states_per_step[i] = set()
            state = GameState.from_dict(step["s"])
            states_per_step[i].add(utils.state_as_ordered_string(state))
    for i, states in states_per_step.items():
        print(f"Step {i}, #different states:{len(states)}")

def trajectory_step_distance(step1:dict, step2:dict)->float:
    s1 = GameState.from_dict(step1["s"])
    s1_next = GameState.from_dict(step1["s_next"])
    s2 = GameState.from_dict(step2["s"])
    s2_next = GameState.from_dict(step2["s_next"])
    action_similarity = 0
    reward_diff = abs(step1["r"] - step2["r"])
    effect_diff = abs(state_diff(s1,s1_next) - state_diff(s2, s2_next))
    return action_similarity + reward_diff + effect_diff

def state_size(state:GameState)->list:
    size = []
    size.append(len(state.known_networks))
    size.append(len(state.known_hosts))
    size.append(len(state.controlled_hosts))
    size.append(sum([len(x) for x in state.known_services.values()]))
    size.append(sum([len(x) for x in state.known_data.values()]))
    return size

def cluster_trajectory_steps(game_plays:list, filename, end_reason=None, y="timestamp"):
    action_conversion = {
        ActionType.ScanNetwork:0,
        ActionType.FindServices:1,
        ActionType.FindData:2,
        ActionType.ExploitService:3,
        ActionType.ExfiltrateData:4,
    }

    trajectory_steps = []
    for play in game_plays:
        if end_reason and play["end_reason"] != end_reason:
            continue
        for i, step in enumerate(play["trajectory"]):
            features = []
            state = GameState.from_dict(step["s"])
            next_state = GameState.from_dict(step["s_next"])
            action = Action.from_dict(step["a"])
            reward = step["r"]
            features += state_size(state)
            features.append(reward)
            features += state_size(next_state)
            if y == "timestamp":
                features.append(action_conversion[action.type])
                trajectory_steps.append((features,i))
            elif y == "action_type":
                trajectory_steps.append((features, action_conversion[action.type]))
    reducer = umap.UMAP()
    embedding = reducer.fit_transform([x[0] for x in trajectory_steps])
    if y == "timestamp":
        plt.scatter(embedding[:, 0], embedding[:, 1], c=[x[1] for x in trajectory_steps], cmap='plasma', s=5, alpha=0.5)
        plt.colorbar(label=" Step number")
    elif y == "action_type":
        from_list = matplotlib.colors.LinearSegmentedColormap.from_list
        cm = from_list('Set15', plt.cm.tab10(range(0,len(action_conversion))), len(action_conversion), )
        plt.cm.register_cmap(None, cm)
        plt.set_cmap(cm)
        colors = [x[1] for x in trajectory_steps]
        scatter = plt.scatter(embedding[:, 0], embedding[:, 1], c=colors, cmap=cm, s=5, alpha=0.5)
        handles, _ = scatter.legend_elements()
        plt.legend(handles, [str(action_type).lstrip("ActionType.") for action_type in action_conversion.keys()],
                    loc="best", title="ActionTypes")
    plt.savefig(os.path.join("figures", filename), dpi=300)
    plt.close()

def update_cmap(data, cm, name):
    from_list = matplotlib.colors.LinearSegmentedColormap.from_list
    if len(data) < 2:
        new_cm = from_list(name, cm(range(0,2)), 2, )
    else:
        new_cm = from_list(name, cm(range(0,len(data))), len(data), )
    return new_cm

def cluster_combined_trajectories(game_plays, filename=None, end_reason=None, optimal_gamelays=None):
    action_conversion = {
        ActionType.ScanNetwork:0,
        ActionType.FindServices:1,
        ActionType.FindData:2,
        ActionType.ExploitService:3,
        ActionType.ExfiltrateData:4,
    }
    def extract_features(game_plays, end_reason=None):
        trajectory_steps = []
        for play in game_plays:
            if end_reason and play["end_reason"] not in end_reason:
                continue
            for i, step in enumerate(play["trajectory"]):
                features = []
                state = GameState.from_dict(step["s"])
                next_state = GameState.from_dict(step["s_next"])
                print(step["a"])
                action =  Action(ActionType.from_string(step["a"]["type"]), {})
                reward = step["r"]
                features += state_size(state)
                features += state_size(next_state)
                features += [state_diff(state, next_state)]
                features.append(reward)
                #features += [i]
                if ["end_reason"] == "goal_reached":
                    final_reward = 100
                elif ["end_reason"] == "detected":
                    final_reward = -5
                else:
                    final_reward = -1
                features += [-1*(len(play)-i)+final_reward]
                action_type_one_hot = [0 for _ in range(len(action_conversion))]
                action_type_one_hot[action_conversion[action.type]] = 1
                features += action_type_one_hot
                trajectory_steps.append({"features":features,
                "action_type": action_conversion[action.type],
                "model":play["model"],
                "timestamp": i,
                "end_reason": play["end_reason"]         
                })
        return trajectory_steps
    trajectory_steps = extract_features(game_plays, end_reason)
    optimal_steps = extract_features(optimal_gamelays, end_reason)
    scaler = StandardScaler().fit([x["features"] for x in trajectory_steps])
    scaled_data = scaler.transform([x["features"] for x in trajectory_steps])
    scaled_optimal = scaler.transform([x["features"] for x in optimal_steps])
    model_types = sorted(set([x["model"] for x in trajectory_steps]))
    model_type_conversion = {x:i for i,x in enumerate(model_types)}

    end_reasons = sorted(set([x["end_reason"] for x in trajectory_steps]))
    end_reason_conversion = {x:i for i,x in enumerate(end_reasons)}
    
    reducer = umap.UMAP(metric="cosine",n_neighbors=50, min_dist=0.9,transform_seed=42).fit(scaled_data)
    embedding = reducer.transform(scaled_data)
    embedding_optimal = reducer.transform(scaled_optimal)
    fig, ((ax1, ax2),(ax3,ax4)) = plt.subplots(2, 2, figsize=(12, 8))
    #fig.suptitle('Trajectory step comparison')
    ax1.set_title("Step number")
    im1= ax1.scatter(embedding[:, 0], embedding[:, 1], c=[x["timestamp"] for x in trajectory_steps], cmap='plasma', s=0.2, alpha=0.5)
    ax1.scatter(embedding_optimal[:, 0], embedding_optimal[:, 1], c="cyan", marker="x")
    divider = make_axes_locatable(ax1)
    cax = divider.append_axes('right', size='5%', pad=0.05)
    fig.colorbar(im1, cax=cax, orientation='vertical')
    # from_list = matplotlib.colors.LinearSegmentedColormap.from_list
    # cm = from_list('Dark3', plt.cm.Dark2(range(0,len(model_type_conversion))), len(model_type_conversion), )
    cm = update_cmap(model_type_conversion, plt.cm.Dark2 ,"Dark3")
    scatter2 = ax2.scatter(embedding[:, 0], embedding[:, 1], c=[model_type_conversion[x["model"]] for x in trajectory_steps], s=0.2,cmap=cm, alpha=0.5)
    ax2.set_title("Model type")
    try:
        handles2, _ = scatter2.legend_elements()
        ax2.legend(handles2, [model_type for model_type in model_type_conversion.keys()],
                        loc="best")
    except ValueError:
        pass

    from_list = matplotlib.colors.LinearSegmentedColormap.from_list
    cm = from_list('Set4', plt.cm.Set1(range(0,len(end_reason_conversion))), len(end_reason_conversion), )
    cm = update_cmap(end_reason_conversion, plt.cm.Set1 ,"Set4")
    scatter3 = ax3.scatter(embedding[:, 0], embedding[:, 1], c=[end_reason_conversion[x["end_reason"]] for x in trajectory_steps],cmap=cm, s=0.2, alpha=0.5)
    ax3.set_title("End reason")
    try:
        handles3, _ = scatter3.legend_elements()
        ax3.legend(handles3, [end_reason for end_reason in end_reason_conversion.keys()],
                        loc="best")
    except ValueError:
        pass    
    from_list = matplotlib.colors.LinearSegmentedColormap.from_list
    cm = from_list('Set15', plt.cm.tab10(range(0,len(action_conversion))), len(action_conversion), )
    cm = update_cmap(action_conversion, plt.cm.tab10 ,"Set15")
    scatter4 = ax4.scatter(embedding[:, 0], embedding[:, 1], c=[x["action_type"] for x in trajectory_steps], cmap=cm, s=0.2, alpha=0.5)
    ax4.set_title("Action type")
    handles, _ = scatter4.legend_elements()
    ax4.legend(handles, [str(action_type).lstrip("ActionType.") for action_type in action_conversion.keys()],
                    loc="best",)
    for axis in [ax1, ax2, ax3, ax4]:
        axis.set_xticks([])
        axis.set_yticks([])
    fig.subplots_adjust(wspace=0.1, hspace=0.1)
    fig.savefig(os.path.join("figures", filename),bbox_inches='tight',  dpi=600)
    plt.close()

def generate_mdp_from_trajecotries(game_plays:list, filename:str, end_reason=None)->dict:
    idx_mapping = {
        "Start":0,
        ActionType.ScanNetwork:1,
        ActionType.FindServices:2,
        ActionType.FindData:3,
        ActionType.ExploitService:4,
        ActionType.ExfiltrateData:5,
    }
    counts = {
        "Start":0,
        ActionType.ScanNetwork:0,
        ActionType.FindServices:0,
        ActionType.FindData:0,
        ActionType.ExploitService:0,
        ActionType.ExfiltrateData:0,
    }
    transitions = np.zeros([len(counts), len(counts)])
    unique_actions = set()
    for play in game_plays:
        if end_reason and play["end_reason"] not in end_reason:
            continue
        previous_action = "Start"
        for i, step in enumerate(play["trajectory"]):
            counts[previous_action] += 1
            action =  Action(ActionType.from_string(step["a"]["type"]), {}).type
            params_string = [f"{k}:{v}" for k,v in step["a"]["params"].items()]
            unique_actions.add((step["a"]["type"],",".join(params_string)))
            transitions[idx_mapping[previous_action], idx_mapping[action]] += 1
            previous_action = action
    # make transitions probabilities
    for action_type, count in counts.items():
        transitions[idx_mapping[action_type]] = transitions[idx_mapping[action_type]]/count
    transitions = np.round(transitions, 2)
    print(transitions)
    print(len(unique_actions))

    fig, ax = plt.subplots()
    im = ax.imshow(transitions)
    ax.set_xticks(np.arange(len(idx_mapping)), labels=idx_mapping.keys())
    ax.set_yticks(np.arange(len(idx_mapping)), labels=idx_mapping.keys())
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
         rotation_mode="anchor")
    # Loop over data dimensions and create text annotations.
    for i in range(len(idx_mapping)):
        for j in range(len(idx_mapping)):
            text = ax.text(j, i, transitions[i, j],
                        ha="center", va="center", color="w")

    ax.set_title(f"Visualization of MDP for {play['model']}")
    fig.tight_layout()
    fig.savefig(os.path.join("figures", f"{filename}_{END_REASON if end_reason else ''}"),  dpi=600)
    

def gameplay_graph(trajectory)->tuple:
    states = {}
    actions = {}
    edges = {}

    for step in trajectory:
        

    pass
if __name__ == '__main__':

    #END_REASON = ["goal_reached", "detected"]
    # END_REASON = ["detected", "max_steps
    END_REASON = None
    #END_REASON = ["goal_reached"]

    # combine
    game_plays_q_learning = read_json("./NSG_trajectories_q_agent_marl.experiment0004-episodes-20000.json")
    game_plays_gpt = read_json("NSG_trajectories_GPT3.json")
    game_plays_conceptual = read_json("NSG_trajectories_experiment47-episodes-680000.json")
    print("optimal")
    game_plays_optimal = read_json("NSG_trajectories_optimal.json")
    # barplot_action_efficiency(
    #  [game_plays_q_learning, game_plays_conceptual, game_plays_gpt],
    #  ("Q-learning", "Conceptual-learning", "LLM (GPT 3.5)"),
    #  end_reason=["goal_reached"],
    # )
    # get_action_type_barplot_per_step(game_plays_q_learning, filename="plot_by_action_q_learning.png", end_reason=END_REASON)
    # get_action_type_barplot_per_step(game_plays_conceptual, filename="plot_by_action_concepts.png", end_reason=END_REASON)
    # get_action_type_barplot_per_step(game_plays_gpt, filename="plot_by_action_gpt.png", end_reason=END_REASON)
    for play in game_plays_q_learning:
        play["model"] = "Q-learning"
    for play in game_plays_gpt:
        play["model"] = "GPT-3.5"
    for play in game_plays_conceptual:
        play["model"] = "Q-learning-concepts"
    for play in game_plays_optimal:
        play["model"] = "Optimal"

    #game_plays_combined = game_plays_q_learning + game_plays_gpt+game_plays_conceptual
    #cluster_combined_trajectories(game_plays_combined, filename=f"trajectory_step_with_optimal_comparison_scaled{'_'.join(END_REASON if END_REASON else '')}.png", end_reason=END_REASON,optimal_gamelays=game_plays_optimal)
    generate_mdp_from_trajecotries(game_plays_q_learning,filename="MDP_visualization_q_learning", end_reason=END_REASON)
    generate_mdp_from_trajecotries(game_plays_gpt,filename="MDP_visualization_gpt", end_reason=END_REASON)
    generate_mdp_from_trajecotries(game_plays_conceptual,filename="MDP_visualization_conceptual", end_reason=END_REASON)
    generate_mdp_from_trajecotries(game_plays_optimal,filename="MDP_visualization_optimal", end_reason=END_REASON)
import jsonlines
import numpy as np
import os 
import utils
import matplotlib.pyplot as plt
import matplotlib
from mpl_toolkits.axes_grid1 import make_axes_locatable
import umap
import plotly.graph_objects as go
from sklearn.preprocessing import StandardScaler

from netsecgame.game_components import GameState, Action, ActionType

   

def read_json(filename, max_lines=50)->list:
    trajectories = []
    with jsonlines.open(filename) as reader:
        for obj in reader:
            trajectories.append(obj)
            if len(trajectories) > max_lines:
                break
    return trajectories

def compute_mean_length(game_plays:list)->float:
    lengths = []
    for play in game_plays:
        if play["end_reason"]:
            lengths.append(len(play["trajectory"]["actions"]))
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

def plot_barplot(data:dict, fileneme, title="ActionType distribution per step"):
    fig, ax = plt.subplots()
    bottom = np.zeros(len(data))
    action_counts = {}
    names = []
    for action_type in ActionType:
        if action_type not in [ActionType.JoinGame, ActionType.QuitGame, ActionType.ResetGame]:
            tmp = np.zeros(len(data))
            names.append(str(action_type))
            for i in range(len(data)):
                tmp[i] = data[i][action_type]
            action_counts[action_type] = tmp
    
    for action_type, values in action_counts.items():
        ax.bar(data.keys(), values, label=str(action_type).lstrip("ActionType."),bottom=bottom)
        #ax.plot(data.keys(), values, label=str(action_type).lstrip("ActionType."))
        bottom += values
    ax.set_title(title)
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
        for i in range(len(play["trajectory"]["actions"])):
            action = Action.from_dict(play["trajectory"]["actions"][i])
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
        for i in range(len(play["trajectory"]["actions"])):
            if i not in actions_per_step.keys():
                actions_per_step[i] = {action_type:0 for action_type in ActionType}
            action = Action.from_dict(play["trajectory"]["actions"][i])
            actions_per_step[i][action.type] += 1
    to_plot = {}
    for i, actions in actions_per_step.items():
        per_step = {}
        for a in actions:
            per_step[a] = actions[a]
        to_plot[i] = per_step
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
                for action_dict in t["trajectory"]["actions"]:
                    action = Action.from_dict(action_dict)
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

    # states_per_step = {}
    # for play in game_plays:
    #     if end_reason and play["end_reason"] != end_reason:
    #         continue
    #     for i,step in enumerate(play["trajectory"]):
    #         if i not in states_per_step.keys():
    #             states_per_step[i] = set()
    #         state = GameState.from_dict(step["s"])
    #         states_per_step[i].add(utils.state_as_ordered_string(state))
    # for i, states in states_per_step.items():
    #     print(f"Step {i}, #different states:{len(states)}")

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
        "Invalid":6
    }
    counts = {
        "Start":0,
        ActionType.ScanNetwork:0,
        ActionType.FindServices:0,
        ActionType.FindData:0,
        ActionType.ExploitService:0,
        ActionType.ExfiltrateData:0,
        "Invalid":0
    }
    transitions = np.zeros([len(counts), len(counts)])
    for play in game_plays:
        if end_reason and play["end_reason"] not in end_reason:
            continue
        previous_action = "Start"
        for action_dict in play["trajectory"]["actions"]:
            counts[previous_action] += 1
            try:
                action =  Action.from_dict(action_dict).type
            except ValueError:
                action = "Invalid"
            transitions[idx_mapping[previous_action], idx_mapping[action]] += 1
            previous_action = action
    # make transitions probabilities
    for action_type, count in counts.items():
        transitions[idx_mapping[action_type]] = transitions[idx_mapping[action_type]]/max(count,1)
    transitions = np.round(transitions, 2)

    fig, ax = plt.subplots()
    _ = ax.imshow(transitions)
    ax.set_xticks(np.arange(len(idx_mapping)), labels=idx_mapping.keys())
    ax.set_yticks(np.arange(len(idx_mapping)), labels=idx_mapping.keys())   
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
         rotation_mode="anchor")
    # Loop over data dimensions and create text annotations.
    for i in range(len(idx_mapping)):
        for j in range(len(idx_mapping)):
            _ = ax.text(j, i, transitions[i, j],
                        ha="center", va="center", color="w")

    ax.set_title(f"Visualization of MDP for {play['model']}")
    fig.tight_layout()
    fig.savefig(os.path.join("figures", f"{filename}_{END_REASON if end_reason else ''}.png"),  dpi=600)

def generate_sankey_from_trajecotries(game_plays:list, filename:str, end_reason=None, probs=True, threshold=0)->dict:
    idx_mapping = {
        "Start":0,
        ActionType.ScanNetwork:1,
        ActionType.FindServices:2,
        ActionType.FindData:3,
        ActionType.ExploitService:4,
        ActionType.ExfiltrateData:5,
        "Invalid":6
    }
    counts = {
        "Start":0,
        ActionType.ScanNetwork:0,
        ActionType.FindServices:0,
        ActionType.FindData:0,
        ActionType.ExploitService:0,
        ActionType.ExfiltrateData:0,
        "Invalid":0
    }
    transitions = np.zeros([len(counts), len(counts)])
    for play in game_plays:
        if end_reason and play["end_reason"] not in end_reason:
            continue
        previous_action = "Start"
        for action_dict in play["trajectory"]["actions"]:
            counts[previous_action] += 1
            action =  Action.from_dict(action_dict).type
            transitions[idx_mapping[previous_action], idx_mapping[action]] += 1
            previous_action = action
    if probs:
        # convert values to probabilities   
        for action_type, count in counts.items():
            transitions[idx_mapping[action_type]] = transitions[idx_mapping[action_type]]/max(count,1)
        transitions = np.round(transitions, 2)
    
    # Create a list of unique labels
    labels = [str(x).lstrip("ActionType.") for x in idx_mapping.keys()]
    labels += labels[1:]
    # Define colors for each node
    node_colors = [
        'rgba(255, 0, 0, 0.8)',
        'rgba(255, 153, 0, 0.8)',
        'rgba(0, 204, 0, 0.8)',
        'rgba(51, 204, 204, 0.8)',
        'rgba(51, 102, 255, 0.8)',
        'rgba(204, 204, 0, 0.8)',
        'rgba(255, 0, 102, 0.8)',
        'rgba(255, 153, 0, 0.8)',
        'rgba(0, 204, 0, 0.8)',
        'rgba(51, 204, 204, 0.8)',
        'rgba(51, 102, 255, 0.8)',
        'rgba(204, 204, 0, 0.8)',
        'rgba(255, 0, 102, 0.8)',
    ]

    # use hard-coded edges for now
    source_indices = [0,0,0,0,0,0,1,1,1,1,1,1,2,2,2,2,2,2,3,3,3,3,3,3,4,4,4,4,4,4,5,5,5,5,5,5,6,6,6,6,6,6,]
    target_indices = [1,2,3,4,5,6,7,8,9,10,11,12,7,8,9,10,11,12,7,8,9,10,11,12,7,8,9,10,11,12,7,8,9,10,11,12,7,8,9,10,11,12,]
    
    # only show transitons with value higher than threshold
    transitions = np.where(transitions < threshold, 0,transitions)
    # no edge leads to start so we can skip the first column of the transition matrix
    values = transitions[:,1:].flatten()
    max_value = max(values)
    opacities = [min(1,1.5*value / max_value)  for value in values]

    # Generate link colors based on source node colors and opacity
    link_colors = []
    for s, opacity in zip(source_indices, opacities):
        color = node_colors[s]
        # Adjust the color's alpha value based on opacity
        rgba_color = color[:-4] + f'{opacity})'
        link_colors.append(rgba_color)
    
    # generate node positions
    valid_nodes = [k for (k,v) in counts.items() if v > 0]
    # add start
    x_pos = [0.001]
    # first column
    x_pos += [0.25 for i in range(len(valid_nodes)-1)] 
    # second column
    x_pos += [0.999 for i in range(len(valid_nodes)-1)]
    # start
    y_pos = [0.5]
    for _ in range(2):
        for node_idx in range(0, len(valid_nodes)-1):
            y_pos.append(0.001 + node_idx*0.999/(len(valid_nodes)-1)) 
    # Create the Sankey diagram
    fig = go.Figure(data=[go.Sankey(
        arrangement='snap',
        valueformat = ".2f",
        valuesuffix = "",
        node=dict(
            pad=5,
            thickness=10,
            line=dict(color="black", width=0.5),
            label=labels,
            color=node_colors,
            x = x_pos,
            y = y_pos,
        ),
        link=dict(
            source=source_indices,
            target=target_indices,
            value=values,
            color=link_colors,
            arrowlen=5,
        )
    )])

    fig.update_layout(title_text=f"ActionType Sankey Diagram - {play['model']}")
    fig.write_image(os.path.join("figures", f"{filename}_{END_REASON if end_reason else ''}.png"))
    fig.update_layout(font_size=18)
    fig.show()
    
def gameplay_graph(game_plays:list, states, actions, end_reason=None)->tuple:
    edges = {}
    for play in game_plays:
        if end_reason and play["end_reason"] not in end_reason:
            continue
        state = utils.state_as_ordered_string(GameState.from_dict(play["trajectory"]["states"][0]))
        for i in range(1, len(play["trajectory"]["actions"])):
            next_state = utils.state_as_ordered_string(GameState.from_dict(play["trajectory"]["states"][i]))
            action = Action.from_dict((play["trajectory"]["actions"][i]))
            if state not in states:
                states[state] = len(states)
            if next_state not in states:
                states[next_state] = len(states)
            if action not in actions:
                actions[action] = len(actions)
            if (states[state],states[next_state]) not in edges:
                edges[states[state], states[next_state]] = {}
            if actions[action] not in edges[states[state], states[next_state]]:
                edges[states[state], states[next_state]][actions[action]] = 0
            edges[states[state], states[next_state]][actions[action]] += 1
            state = next_state
    return edges

def get_graph_stats(edge_list, states, actions)->tuple:
    nodes = set()
    edges = set()
    simple_edges = set()
    node_in_degree = {}
    node_out_degree = {}
    loop_edges = set()
    for (src,dst) in edge_list:
        nodes.add(src)
        nodes.add(dst)
        if src not in node_out_degree.keys():
            node_out_degree[src] = 0
        if dst not in node_in_degree.keys():
            node_in_degree[dst] = 0
        node_out_degree[src] += 1
        node_in_degree[dst] += 1
        simple_edges.add((src,dst))
        for a in edge_list[src, dst]:
            edges.add((src,dst,a))
            if src == dst:
                loop_edges.add((src,dst,a))
    print(f"# Nodes:{len(nodes)}")
    print(f"# Edges:{len(edges)}")
    print(f"# Simple:{len(simple_edges)}")
    print(f"# loops:{len(loop_edges)}")
    print(f"node IN-degree: {np.mean(list(node_in_degree.values()))}+-{np.std(list(node_in_degree.values()))}")
    print(f"node OUT-degree: {np.mean(list(node_out_degree.values()))}+-{np.std(list(node_out_degree.values()))}")
    return nodes, edges, simple_edges, node_in_degree, node_out_degree, loop_edges

def get_change_in_edges(edge_list1, edge_list2):
    removed_edges = {}
    added_edges = {}
    for (src,dst), actions in edge_list1.items():
        if (src, dst) not in edge_list2:
            removed_edges[src,dst] = actions
        else:
            removed = set()
            for a in actions:
                if a not in edge_list2[(src, dst)]:
                    removed.add(a)
            removed_edges[src,dst] = removed
    for (src,dst), actions in edge_list2.items():
        if (src, dst) not in edge_list1:
            added_edges[src,dst] = actions
        else:
            added = set()
            for a in actions:
                if a not in edge_list1[(src, dst)]:
                    added.add(a)
            added_edges[src,dst] = added
    return added_edges, removed_edges

def get_change_in_nodes(edge_list1, edge_list2):
    original = set()
    new = set()
    for (src, dst) in edge_list1.keys():
        original.add(src)
        original.add(dst)
    for (src, dst) in edge_list2.keys():
        new.add(src)
        new.add(dst)
    return {n for n in new if n not in original}, {n for n in original if n not in new}

def get_graph_modificiation(edge_list1, edge_list2):
    """
    Produces the addition and deletion graphs
    """
    deleted_edges = {}
    for k in edge_list1.keys():
        if k not in edge_list2:
            deleted_edges[k] = set(edge_list1[k].keys())
        else:
            diff = set()
            for a in edge_list1[k].keys():
                if a not in edge_list2[k]:
                    diff.add(a)
            if len(diff) > 0:
                deleted_edges[k] = diff
    added_edges = {}
    for k in edge_list2.keys():
        if k not in edge_list1:
            added_edges[k] = set(edge_list2[k].keys())
        else:
            diff = set()
            for a in edge_list2[k].keys():
                if a not in edge_list1[k]:
                    diff.add(a)
            if len(diff) > 0:
                added_edges[k] = diff
    return added_edges, deleted_edges

if __name__ == '__main__':
    # filter trajectories based on their ending
    END_REASON = None
    #END_REASON = ["goal_reached"]
    #game_plays = read_json("./trajectories/2024-07-03_QAgent_Attacker.jsonl")
    game_plays_optimal= read_json("trajectories/2024-07-25_BaseAgent_Attacker_optimal.jsonl")
    for play in game_plays_optimal:
        play["model"] = "Optimal"

    game_plays_extra_steps = read_json("trajectories/2024-07-25_BaseAgent_Attacker_failed.jsonl")
    for play in game_plays_optimal:
        play["model"] = "Not-optimal"
    states = {}
    actions = {}
    edges_optimal = gameplay_graph(game_plays_optimal, states, actions,end_reason=END_REASON)
    edges_not_optimal = gameplay_graph(game_plays_extra_steps, states, actions,end_reason=END_REASON)
    print(edges_optimal)
    print(edges_not_optimal)
    state_to_id = {v:k for k,v in states.items()}
    action_to_id = {v:k for k,v in states.items()}

    added, deleted = get_graph_modificiation(edges_optimal, edges_not_optimal)
    print("added:", added)
    print("deleted:", deleted)
    get_graph_stats(edges_optimal, state_to_id, action_to_id)
    get_graph_stats(edges_not_optimal, state_to_id, action_to_id)
    # print("optimal")
    # get_graph_stats(edges_optimal, state_to_id, action_to_id)
    # print("sub-optimal")
    # get_graph_stats(edges_not_optimal, state_to_id, action_to_id)



    # print(compute_mean_length(game_plays))
    # get_action_type_barplot_per_step(game_plays, end_reason=END_REASON)
    # get_action_type_histogram_per_step(game_plays, end_reason=END_REASON)
    # generate_mdp_from_trajecotries(game_plays,filename="MDP_visualization_optimal", end_reason=END_REASON)
    # states = {}
    # actions = {}
    # edges_optimal = gameplay_graph(game_plays, states, actions,end_reason=END_REASON)
    # state_to_id = {v:k for k,v in states.items()}
    # action_to_id = {v:k for k,v in states.items()}
    # get_graph_stats(edges_optimal, state_to_id, action_to_id)

    # # load trajectories from files
    # game_plays_q_learning = read_json("./NSG_trajectories_q_agent_marl.experiment0004-episodes-20000.json")
    # for play in game_plays_q_learning:
    #     play["model"] = "Q-learning"
    # game_plays_gpt = read_json("NSG_trajectories_GPT3.json")
    # for play in game_plays_gpt:
    #     play["model"] = "GPT-3.5"
    # game_plays_conceptual = read_json("NSG_trajectories_experiment47-episodes-680000.json")
    # for play in game_plays_conceptual:
    #     play["model"] = "Q-learning-concepts"
    # game_plays_optimal = read_json("NSG_trajectories_optimal.json")
    # for play in game_plays_optimal:
    #     play["model"] = "Optimal"
    

    # # barplot_action_efficiency(
    # #  [game_plays_q_learning, game_plays_conceptual, game_plays_gpt],
    # #  ("Q-learning", "Conceptual-learning", "LLM (GPT 3.5)"),
    # #  end_reason=["goal_reached"],
    # # )
    # # get_action_type_barplot_per_step(game_plays_q_learning, filename="plot_by_action_q_learning.png", end_reason=END_REASON)
    # # get_action_type_barplot_per_step(game_plays_conceptual, filename="plot_by_action_concepts.png", end_reason=END_REASON)
    # # get_action_type_barplot_per_step(game_plays_gpt, filename="plot_by_action_gpt.png", end_reason=END_REASON)
    
    

    # game_plays_combined = game_plays_q_learning + game_plays_gpt+game_plays_conceptual
    # cluster_combined_trajectories(game_plays_combined, filename=f"trajectory_step_with_optimal_comparison_scaled{'_'.join(END_REASON if END_REASON else '')}.png", end_reason=END_REASON,optimal_gamelays=game_plays_optimal)
    # # generate_mdp_from_trajecotries(game_plays_q_learning,filename="MDP_visualization_q_learning", end_reason=END_REASON)
    # # generate_mdp_from_trajecotries(game_plays_gpt,filename="MDP_visualization_gpt", end_reason=END_REASON)
    # # generate_mdp_from_trajecotries(game_plays_conceptual,filename="MDP_visualization_conceptual", end_reason=END_REASON)
    # # generate_mdp_from_trajecotries(game_plays_optimal,filename="MDP_visualization_optimal", end_reason=END_REASON)
    
    # # MODEL COMPARISON
    # states = {}
    # actions = {}

    # edges_optimal = gameplay_graph(game_plays_optimal, states, actions,end_reason=END_REASON)
    # edges_q_learning = gameplay_graph(game_plays_q_learning,states, actions, end_reason=END_REASON)
    # edges_gpt = gameplay_graph(game_plays_gpt,states, actions, end_reason=END_REASON)

    # state_to_id = {v:k for k,v in states.items()}
    # action_to_id = {v:k for k,v in states.items()}
    # print("optimal:")
    # get_graph_stats(edges_optimal, state_to_id, action_to_id)
    # print("Q-learing:")
    # get_graph_stats(edges_q_learning, state_to_id, action_to_id)
    # print("GPT:")
    # get_graph_stats(edges_gpt, state_to_id, action_to_id)

    # # MODEL PROGRESS
    # states = {}
    # actions = {}
    # gameplays_5K = read_json("./NSG_trajectories_q_agent_marl.experiment0004-episodes-5000.json")
    # gameplays_10K = read_json("./NSG_trajectories_q_agent_marl.experiment0004-episodes-10000.json")
    # gameplays_15K = read_json("./NSG_trajectories_q_agent_marl.experiment0004-episodes-15000.json")
    # gameplays_20K = read_json("./NSG_trajectories_q_agent_marl.experiment0004-episodes-20000.json")
    # gameplays_25K  = read_json("./NSG_trajectories_q_agent_marl.experiment0004-episodes-25000.json")

    # edges_5k = gameplay_graph(gameplays_5K, states, actions,end_reason=END_REASON)
    # edges_10k = gameplay_graph(gameplays_10K, states, actions,end_reason=END_REASON)
    # edges_15k = gameplay_graph(gameplays_15K, states, actions,end_reason=END_REASON)
    # edges_20k = gameplay_graph(gameplays_20K, states, actions,end_reason=END_REASON)
    # edges_25k = gameplay_graph(gameplays_25K, states, actions,end_reason=END_REASON)
    # state_to_id = {v:k for k,v in states.items()}
    # action_to_id = {v:k for k,v in actions.items()}

    # print("5K:")
    # get_graph_stats(edges_5k, state_to_id, action_to_id)
    # print("10K:")
    # get_graph_stats(edges_10k, state_to_id, action_to_id)
    # print("15K:")
    # get_graph_stats(edges_15k, state_to_id, action_to_id)
    # print("20K:")
    # get_graph_stats(edges_20k, state_to_id, action_to_id)
    # print("25K:")
    # get_graph_stats(edges_20k, state_to_id, action_to_id)
        
    # print("change from 5k->10k")
    # nodes_added, nodes_removed = get_change_in_nodes(edges_5k, edges_10k)
    # edges_added, edges_removed = get_change_in_edges(edges_5k, edges_10k)
    # print(f"Nodes added: {len(nodes_added)}, removed: {len(nodes_removed)}")
    # print(f"Edgees added: {sum([len(x) for x in edges_added.values()])}, removed: {sum([len(x) for x in edges_removed.values()])}")
    # print("----------------------------------------")
    # print("change from 10k->15k")
    # nodes_added, nodes_removed = get_change_in_nodes(edges_10k, edges_15k)
    # edges_added, edges_removed = get_change_in_edges(edges_10k, edges_15k)
    # print(f"Nodes added: {len(nodes_added)}, removed: {len(nodes_removed)}")
    # print(f"Edgees added: {sum([len(x) for x in edges_added.values()])}, removed: {sum([len(x) for x in edges_removed.values()])}")
    # print("----------------------------------------")
    # print("change from 15k->20k")
    # nodes_added, nodes_removed = get_change_in_nodes(edges_15k, edges_20k)
    # edges_added, edges_removed = get_change_in_edges(edges_15k, edges_20k)
    # print(f"Nodes added: {len(nodes_added)}, removed: {len(nodes_removed)}")
    # print(f"Edgees added: {sum([len(x) for x in edges_added.values()])}, removed: {sum([len(x) for x in edges_removed.values()])}")
    # print("----------------------------------------")
    # print("change from 20k->25k")
    # nodes_added, nodes_removed = get_change_in_nodes(edges_20k, edges_25k)
    # edges_added, edges_removed = get_change_in_edges(edges_20k, edges_25k)
    # print(f"Nodes added: {len(nodes_added)}, removed: {len(nodes_removed)}")
    # print(f"Edgees added: {sum([len(x) for x in edges_added.values()])}, removed: {sum([len(x) for x in edges_removed.values()])}")
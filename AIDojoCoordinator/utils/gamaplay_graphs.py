from trajectory_analysis import read_json
import numpy as np
import os 
import utils
import argparse
import matplotlib.pyplot as plt

from AIDojoCoordinator.game_components import GameState, Action

class TrajectoryGraph:
    def __init__(self)->None:
        self._checkpoints = {}
        self._checkpoint_size = {}
        self._checkpoint_edges = {}
        self._checkpoint_simple_edges = {}
        self._wins_per_checkpoint = {}
        self._state_to_id = {}
        self._id_to_state = {}
        self._action_to_id = {}
        self._id_to_action = {}

    @property
    def num_checkpoints(self)->int:
        return len(self._checkpoints)

    def get_state_id(self, state:GameState)->int:
        """
        Returns state id or creates new one if the state was not registered before
        """
        state_str = utils.state_as_ordered_string(state)
        if state_str not in self._state_to_id.keys():
            self._state_to_id[state_str] = len(self._state_to_id)
            self._id_to_state[self._state_to_id[state_str]] = state
        return self._state_to_id[state_str]
    
    def get_state(self, id:int)->GameState:
        return self._id_to_state[id]

    def get_action_id(self, action:Action)->int:
        """
        Returns action id or creates new one if the state was not registered before
        """
        if action not in self._action_to_id.keys():
            self._action_to_id[action] = len(self._action_to_id)
            self._id_to_action[self._action_to_id[action]] = action
        return self._action_to_id[action]

    def get_action(self, id:int)-> Action:
        return self._id_to_action[id]

    def add_checkpoint(self, trajectories:list, end_reason=None)->None:
        # Add complete trajectory list
        wins = []
        edges = {}
        simple_edges = {}
        self._checkpoint_size[self.num_checkpoints] = len(trajectories)
        for play in trajectories:
            if end_reason and play["end_reason"] not in end_reason:
                continue
            if len(play["trajectory"]["actions"]) == 0:
                continue
            if play["end_reason"] == "goal_reached":
                wins.append(1)
            else:
                wins.append(0)
            # get the id of the first state
            state_id = self.get_state_id(GameState.from_dict(play["trajectory"]["states"][0]))
            # iterate over the trajectory
            assert len(play["trajectory"]["states"]) == len(play["trajectory"]["actions"]) +1
            for i in range(1, len(play["trajectory"]["states"])):
                next_state_id = self.get_state_id(GameState.from_dict(play["trajectory"]["states"][i]))
                action_id = self.get_action_id(Action.from_dict((play["trajectory"]["actions"][i-1])))
                # fullgraph
                if (state_id, next_state_id, action_id) not in edges:
                    edges[state_id, next_state_id, action_id] = 0
                edges[state_id, next_state_id, action_id] += 1
                
                #simplified graph
                if (state_id, next_state_id)not in simple_edges:
                    simple_edges[state_id, next_state_id] = 0
                simple_edges[state_id, next_state_id] += 1
                state_id = next_state_id
        self._checkpoint_simple_edges[self.num_checkpoints] = simple_edges
        self._checkpoint_edges[self.num_checkpoints] = edges
        self._wins_per_checkpoint[self.num_checkpoints] = np.array(wins)
        self._checkpoints[self.num_checkpoints] = trajectories

    def get_checkpoint_wr(self, checkpoint_id:int)->tuple:
        if checkpoint_id not in self._wins_per_checkpoint:
            raise IndexError(f"Checkpoint id '{checkpoint_id}' not found!")
        else:
            return np.mean(self._wins_per_checkpoint[checkpoint_id]), np.std(self._wins_per_checkpoint[checkpoint_id])

    def get_wr_progress(self)->dict:
        ret = {}
        for i in self._wins_per_checkpoint.keys():
            wr, std = self.get_checkpoint_wr(i)
            ret[i] = {"wr":wr, "std":std}
            print(f"Checkpoint {i}: WR={wr}±{std}")
        return ret

    def get_graph_stats_progress(self):
        ret = {}
        print("Checkpoint,\tWR,\tEdges,\tSimpleEdges,\tNodes,\tLoops,\tSimpleLoops")
        for i in self._wins_per_checkpoint.keys():
            data = self.get_checkpoint_stats(i)
            ret[i] = data
            print(f'{i},\t{data["winrate"]},\t{data["num_edges"]},\t{data["num_simplified_edges"]},\t{data["num_nodes"]},\t{data["num_loops"]},\t{data["num_simplified_loops"]}')
        return ret

    def plot_graph_stats_progress(self, filedir="figures", filename="trajectory_graph_stats.png"):
        data = self.get_graph_stats_progress()
        wr = [data[i]["winrate"] for i in range(len(data))]
        num_nodes = [data[i]["num_nodes"] for i in range(len(data))]
        num_edges = [data[i]["num_edges"] for i in range(len(data))]
        num_simle_edges = [data[i]["num_simplified_edges"] for i in range(len(data))]
        num_loops = [data[i]["num_loops"] for i in range(len(data))]
        num_simplified_loops  =  [data[i]["num_simplified_loops"] for i in range(len(data))]
        checkpoints = range(len(wr)) 
        plt.plot(checkpoints, num_nodes, label='Number of nodes')
        plt.plot(checkpoints, num_edges, label='Number of edges')
        plt.plot(checkpoints, num_simle_edges, label='Number of simplified edges')
        plt.plot(checkpoints, num_loops, label='Number of loops')
        plt.plot(checkpoints, num_simplified_loops, label='Number of simplified loops')

        plt.title("Graph statistics per checkpoint")
        plt.yscale('log')
        plt.xlabel("Checkpoints")
        # Show legend
        plt.legend()

        # Save the figure as an image file
        plt.savefig(os.path.join(filedir, filename))

    def get_checkpoint_stats(self, checkpoint_id:int)->dict:
        if checkpoint_id not in self._wins_per_checkpoint:
            raise IndexError(f"Checkpoint id '{checkpoint_id}' not found!")
        else:
            data = {}
            data["winrate"] = np.mean(self._wins_per_checkpoint[checkpoint_id])
            data["winrate_std"] = np.std(self._wins_per_checkpoint[checkpoint_id])
            data["num_edges"] = len(self._checkpoint_edges[checkpoint_id])
            data["num_simplified_edges"] = len(self._checkpoint_simple_edges[checkpoint_id])
            data["num_loops"] = len([edge for edge in self._checkpoint_edges[checkpoint_id].keys() if edge[0]==edge[1]])
            data["num_simplified_loops"] = len([edge for edge in self._checkpoint_simple_edges[checkpoint_id].keys() if edge[0]==edge[1]])
            node_set = set([src_node for src_node,_,_ in self._checkpoint_edges[checkpoint_id].keys()]) | set([dst_node for _,dst_node,_ in self._checkpoint_edges[checkpoint_id].keys()])
            data["num_nodes"] = len(node_set)
            return data

    def get_graph_structure_progress(self)->dict:

        all_edges = set().union(*(inner_dict.keys() for inner_dict in self._checkpoint_edges.values()))
        super_graph = {key:np.zeros(self.num_checkpoints) for key in all_edges}
        for i, edge_list in self._checkpoint_edges.items():
            for edge in edge_list:
                super_graph[edge][i] = 1
        return super_graph

    def get_graph_structure_probabilistic_progress(self)->dict:
        # collect all edeges from all checkpoints
        all_edges = set().union(*(inner_dict.keys() for inner_dict in self._checkpoint_edges.values()))
        # prepare data straucture for the probabiliites per edge
        super_graph = {key:np.zeros(self.num_checkpoints) for key in all_edges}
        for i, edges in self._checkpoint_edges.items():
            total_edge_count_cp = sum(edges.values())
            # print(f"Processing timestamp {i}")
            # # total_out_edges_use = {}
            # # for (src, _, _), frequency in edge_list.items():
            # #     if src not in total_out_edges_use:
            # #         total_out_edges_use[src] = 0
            # #     total_out_edges_use[src] += frequency
            # # for (src,dst,edge), value in edge_list.items():
            # #     super_graph[(src,dst,edge)][i] = value/total_out_edges_use[src]
            # src_nodes = set([x for (x, _, _ ) in edge_list.keys()])
            # print(f"\t{len(src_nodes)} source nodes")
            # num_outgoing_edges  = {}
            # for node in src_nodes:
            #     num_outgoing_edges[node] = sum([v for k,v in edge_list.items() if k[0] == node])
            #     print(f"\t{num_outgoing_edges[node]}")
            # for (src,dst,action), occurence in edge_list.items():
            #     print(f"\tedge:{(src,dst,self._id_to_action[action])}, occurence={occurence}, prob={occurence/num_outgoing_edges[src]}")
            #     super_graph[(src,dst,action)][i] = occurence/num_outgoing_edges[src]
            for edge, occurence in edges.items():
                super_graph[edge][i] = occurence/total_edge_count_cp
        return super_graph
    def calculate_source_node_likelihoods(self) -> dict:
        """
        Calculates the likelihood of each edge originating from its source node 
        in each checkpoint.

        Returns:
            source_likelihoods (dict): A nested dictionary where the outer keys are checkpoint numbers,
                                    and the inner dictionaries map edges to their likelihoods.
        """
        all_edges = set().union(*(inner_dict.keys() for inner_dict in self._checkpoint_edges.values()))
        # prepare data straucture for the probabiliites per edge
        source_likelihoods = {key:np.zeros(self.num_checkpoints) for key in all_edges}

        for checkpoint, edges in self._checkpoint_edges.items():
            # Map to store total occurrences of edges for each source node
            source_totals = {}
            
            # Calculate total occurrences for each source node
            for (source, destination, action), count in edges.items():
                if source not in source_totals:
                    source_totals[source] = 0
                source_totals[source] += count
            
            # Calculate likelihoods for each edge

            for (source, destination, action), count in edges.items():
                if source_totals[source] > 0:
                    source_likelihoods[(source, destination, action)][checkpoint] = count / source_totals[source]
        return source_likelihoods
    
    def calculate_edge_play_likelihoods(self) -> dict:
        """
        Calculates the likelihood of each edge being present in a play for each checkpoint.

        Returns:
            play_likelihoods (dict): A nested dictionary where the outer keys are checkpoint numbers,
                                    and the inner dictionaries map edges to their likelihoods.
        """
        all_edges = set().union(*(inner_dict.keys() for inner_dict in self._checkpoint_edges.values()))
        # prepare data straucture for the probabiliites per edge
        play_likelihoods = {key:np.zeros(self.num_checkpoints) for key in all_edges}
        for checkpoint, edges in self._checkpoint_edges.items():
            # Get the total number of trajectories (plays) in this checkpoint
            total_plays = self._checkpoint_size.get(checkpoint, 0)
            if total_plays == 0:
                continue  # Skip checkpoints with no trajectories
            
            # Calculate likelihood for each edge
            for edge, count in edges.items():
                play_likelihoods[edge][checkpoint] = min(count / total_plays, 1)

        return play_likelihoods
    def get_graph_entropies(self)->dict:
        def compute_entropy(probs, epsilon_value=1e-10):
            probs = np.array(probs)
            normalized_probs = probs / np.sum(probs)
            entropy = -np.sum(normalized_probs * np.log(normalized_probs +epsilon_value))  # Avoid log(0)
            return entropy
        probabilistic_graph = self.get_graph_structure_probabilistic_progress
        edge_entropy = {}
        for e, probs in probabilistic_graph:
            edge_entropy[e] = compute_entropy(probs)
        
def gameplay_graph(game_plays:list, states, actions, end_reason=None)->tuple:
    edges = {}
    nodes_timestamps = {}
    wins = []
    for play in game_plays:
        if end_reason and play["end_reason"] not in end_reason:
            continue
        if len(play["trajectory"]["actions"]) == 0:
            continue
        if play["end_reason"] == "goal_reached":
            wins.append(1)
        else:
            wins.append(0)
        state = utils.state_as_ordered_string(GameState.from_dict(play["trajectory"]["states"][0]))
        #print(f'Trajectory len: {len(play["trajectory"]["actions"])}')
        for i in range(1, len(play["trajectory"]["actions"])):
            next_state = utils.state_as_ordered_string(GameState.from_dict(play["trajectory"]["states"][i]))
            action = Action.from_dict((play["trajectory"]["actions"][i]))
            if state not in states:
                states[state] = len(states)
            if next_state not in states:
                states[next_state] = len(states)
            if action not in actions:
                actions[action] = len(actions)
            if (states[state],states[next_state], actions[action]) not in edges:
                edges[states[state],states[next_state], actions[action]] = 0
            edges[states[state], states[next_state], actions[action]] += 1
            if states[state] not in nodes_timestamps.keys():
                nodes_timestamps[states[state]] = set()
            nodes_timestamps[states[state]].add(i-1)
            if states[next_state] not in nodes_timestamps.keys():
                nodes_timestamps[states[next_state]] = set()
            nodes_timestamps[states[next_state]].add(i)
            state = next_state

    return edges, nodes_timestamps, np.mean(wins), np.std(wins)

def get_graph_stats(edge_list, states, actions)->tuple:
    nodes = set()
    edges = set()
    simple_edges = set()
    node_in_degree = {}
    node_out_degree = {}
    loop_edges = set()
    for (src,dst,action) in edge_list:
        nodes.add(src)
        nodes.add(dst)
        if src not in node_out_degree.keys():
            node_out_degree[src] = 0
        if dst not in node_in_degree.keys():
            node_in_degree[dst] = 0
        node_out_degree[src] += 1
        node_in_degree[dst] += 1
        simple_edges.add((src,dst))
        edges.add((src,dst,action))
        if src == dst:
            loop_edges.add((src,dst,action))
    print(f"# Nodes:{len(nodes)}")
    print(f"# Edges:{len(edges)}")
    print(f"# Simple:{len(simple_edges)}")
    print(f"# loops:{len(loop_edges)}")
    print(f"node IN-degree: {np.mean(list(node_in_degree.values()))}+-{np.std(list(node_in_degree.values()))}")
    print(f"node OUT-degree: {np.mean(list(node_out_degree.values()))}+-{np.std(list(node_out_degree.values()))}")
    return nodes, edges, simple_edges, node_in_degree, node_out_degree, loop_edges

def node_set(edge_list)->set:
    nodes = set()
    for (src,dst,action) in edge_list:
        nodes.add(src)
        nodes.add(dst)
    return nodes

def get_graph_modificiation(edge_list1, edge_list2):
    deleted_edges = set(edge_list1.keys())-set(edge_list2.keys())
    added_edges = set(edge_list2.keys())-set(edge_list1.keys())
    deleted_nodes = node_set(edge_list1) - node_set(edge_list2)
    added_nodes = node_set(edge_list2) - node_set(edge_list1)

    return added_edges, deleted_edges, added_nodes, deleted_nodes

if __name__ == '__main__':


    parser = argparse.ArgumentParser()
    # parser.add_argument("--t1", help="Trajectory file #1", action='store', required=True)
    # parser.add_argument("--t2", help="Trajectory file #2", action='store', required=True)
    parser.add_argument("--end_reason", help="Filter options for trajectories", default=None, type=str, action='store', required=False)
    parser.add_argument("--n_trajectories", help="Limit of how many trajectories to use", action='store', default=2000, required=False)
    
    args = parser.parse_args()
       
    tg_blocks = TrajectoryGraph()
    tg_blocks.add_checkpoint(read_json("./trajectories/2025-01-16_experimentsarsa_005-episodes-2000.jsonl",max_lines=args.n_trajectories))
    tg_blocks.add_checkpoint(read_json("./trajectories/2025-01-16_experimentsarsa_005-episodes-4000.jsonl",max_lines=args.n_trajectories))
    tg_blocks.add_checkpoint(read_json("./trajectories/2025-01-16_experimentsarsa_005-episodes-6000.jsonl",max_lines=args.n_trajectories))
    tg_blocks.add_checkpoint(read_json("./trajectories/2025-01-16_experimentsarsa_005-episodes-8000.jsonl",max_lines=args.n_trajectories))
    tg_blocks.add_checkpoint(read_json("./trajectories/2025-01-16_experimentsarsa_005-episodes-10000.jsonl",max_lines=args.n_trajectories))
    tg_blocks.add_checkpoint(read_json("./trajectories/2025-01-16_experimentsarsa_005-episodes-12000.jsonl",max_lines=args.n_trajectories))
    tg_blocks.add_checkpoint(read_json("./trajectories/2025-01-16_experimentsarsa_005-episodes-14000.jsonl",max_lines=args.n_trajectories))
    tg_blocks.add_checkpoint(read_json("./trajectories/2025-01-16_experimentsarsa_005-episodes-16000.jsonl",max_lines=args.n_trajectories))
    tg_blocks.add_checkpoint(read_json("./trajectories/2025-01-16_experimentsarsa_005-episodes-18000.jsonl",max_lines=args.n_trajectories))
    tg_blocks.add_checkpoint(read_json("./trajectories/2025-01-16_experimentsarsa_005-episodes-20000.jsonl",max_lines=args.n_trajectories))
    tg_blocks.add_checkpoint(read_json("./trajectories/2025-01-16_experimentsarsa_005-episodes-22000.jsonl",max_lines=args.n_trajectories))
    tg_blocks.add_checkpoint(read_json("./trajectories/2025-01-16_experimentsarsa_005-episodes-24000.jsonl",max_lines=args.n_trajectories))
    tg_blocks.plot_graph_stats_progress()

    #edge_probabilies_per_cp = tg_blocks.get_graph_structure_probabilistic_progress()
    #edge_probabilies_per_cp = tg_blocks.calculate_source_node_likelihoods()
    edge_play_likelihoods = tg_blocks.calculate_edge_play_likelihoods()
    for k,v in edge_play_likelihoods.items():
        print(f"{k}, {','.join(map(str, v.tolist()))}")
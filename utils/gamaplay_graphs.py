from trajectory_analysis import read_json
import numpy as np
import sys
import os 
import utils
import argparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__) )))
from env.game_components import GameState, Action

class TrajectoryGraph:
    def __init__(self)->None:
        self._checkpoints = {}
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

    def add_checkpoint(self, trajectories:list, end_reason=None)->None:
        # Add complete trajectory list
        wins = []
        edges = {}
        simple_edges = {}
        for play in trajectories:
            if end_reason and play["end_reason"] not in end_reason:
                continue
            if len(play["trajectory"]["actions"]) == 0:
                continue
            if play["end_reason"] == "goal_reached":
                wins.append(1)
            else:
                wins.append(0)
            state_id = self.get_state_id(GameState.from_dict(play["trajectory"]["states"][0]))
            #print(f'Trajectory len: {len(play["trajectory"]["actions"])}')
            for i in range(1, len(play["trajectory"]["actions"])):
                next_state_id = self.get_state_id(GameState.from_dict(play["trajectory"]["states"][i]))
                action_id = self.get_action_id(Action.from_dict((play["trajectory"]["actions"][i])))
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
    parser.add_argument("--n_trajectories", help="Limit of how many trajectories to use", action='store', default=10000, required=False)
    
    args = parser.parse_args()
    # trajectories1 = read_json(args.t1, max_lines=args.n_trajectories)
    # trajectories2 = read_json(args.t2, max_lines=args.n_trajectories)
    # states = {}
    # actions = {}
    
    # graph_t1, g1_timestaps, t1_wr_mean, t1_wr_std = gameplay_graph(trajectories1, states, actions,end_reason=args.end_reason)
    # graph_t2, g2_timestaps, t2_wr_mean, t2_wr_std = gameplay_graph(trajectories2, states, actions,end_reason=args.end_reason)
    
    # state_to_id = {v:k for k,v in states.items()}
    # action_to_id = {v:k for k,v in states.items()}

    # print(f"Trajectory 1: {args.t1}")
    # print(f"WR={t1_wr_mean}±{t1_wr_std}")
    # get_graph_stats(graph_t1, state_to_id, action_to_id)
    # print(f"Trajectory 2: {args.t2}")
    # print(f"WR={t2_wr_mean}±{t2_wr_std}")
    # get_graph_stats(graph_t2, state_to_id, action_to_id)

    # a_edges, d_edges, a_nodes, d_nodes = get_graph_modificiation(graph_t1, graph_t2)
    # print(f"AE:{len(a_edges)},DE:{len(d_edges)}, AN:{len(a_nodes)},DN:{len(d_nodes)}")
    # # print("positions of same states:")
    # # for node in node_set(graph_t1).intersection(node_set(graph_t2)):
    # #     print(g1_timestaps[node], g2_timestaps[node])
    # #     print("-----------------------")
    tg = TrajectoryGraph()
    
    tg.add_checkpoint(read_json("./trajectories/experiment0002/2024-08-02_QAgent_Attacker_experiment0002-episodes-2000.jsonl",max_lines=args.n_trajectories))
    tg.add_checkpoint(read_json("./trajectories/experiment0002/2024-08-02_QAgent_Attacker_experiment0002-episodes-4000.jsonl",max_lines=args.n_trajectories))
    tg.add_checkpoint(read_json("./trajectories/experiment0002/2024-08-02_QAgent_Attacker_experiment0002-episodes-6000.jsonl",max_lines=args.n_trajectories))
    tg.add_checkpoint(read_json("./trajectories/experiment0002/2024-08-02_QAgent_Attacker_experiment0002-episodes-8000.jsonl",max_lines=args.n_trajectories))
    tg.add_checkpoint(read_json("./trajectories/experiment0002/2024-08-02_QAgent_Attacker_experiment0002-episodes-10000.jsonl",max_lines=args.n_trajectories))
    tg.add_checkpoint(read_json("./trajectories/experiment0002/2024-08-02_QAgent_Attacker_experiment0002-episodes-12000.jsonl",max_lines=args.n_trajectories))
    print(tg.num_checkpoints)
    tg.get_wr_progress()

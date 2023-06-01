#Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
from collections import namedtuple
import deepdiff
from frozendict import frozendict
import numpy as np
import netaddr
import json
# Transition between nodes
"""
Transition represents generic actions for attacker in the game. Each transition has a default probabilities
for success and detection (if defensive measures are present). Each transition has default cost and reward (if successful).
Net reward can be computed as follows net_reward = sucess*default_reward - default_cost
"""
Transition = namedtuple("Transition", ["type", "default_success_p", "default_detection_p", "default_reward", "default_cost"])

#List of transitions available for attacker with default parameters
# transitions = {
#     "ScanNetwork": Transition("ScanNetwork",0.9,0.5,1,0.1), #In the beginning we artificially add 3 more networks in both directions
#     "FindServices": Transition("FindServices",0.9,0.6,1,0.1),
#     "FindData": Transition("FindData",0.5,0.9,2,0.1),
#     "ExecuteCodeInService": Transition("ExecuteCodeInService",0.3,0.3,20,0.3),
#     "ExfiltrateData": Transition("ExfiltrateData",0.8,0.8,1000,0.1),
# }
transitions = {
    "ScanNetwork": Transition("ScanNetwork", 0.9, 0.2, 0,1), 
    "FindServices": Transition("FindServices",0.9, 0.3,0,1),
    "FindData": Transition("FindData",0.8, 0.1, 0, 1),
    "ExecuteCodeInService": Transition("ExecuteCodeInService", 0.7, 0.4, 0, 1),
    "ExfiltrateData": Transition("ExfiltrateData",0.8, 0.1, 0, 1),
}

#Actions
"""
Actions are composed of the transition type (see Transition) and additional parameters listed in dictionary
 - ScanNetwork {"target_network": "X.X.X.X/mask" (string)}
 - FindServices {"target_host": "X.X.X.X" (string)}
 - FindData {"target_host": "X.X.X.X" (string)}
 - ExecuteCodeInService {"target_host": "X.X.X.X" (string), "target_service":"service_name" (string)}
 - ExfiltrateData {"target_host": "X.X.X.X" (string), "source_host":"X.X.X.X" (string), "data":"path_to_data" (string)}
"""
#Action = namedtuple("Action", ["transition", "parameters"])
class Action(object):
    
    def __init__(self, transition:str, params:list) -> None:
        self._transition_name = transition
        self._parameters = params
    
    @property
    def transition(self) -> Transition:
        return transitions[self._transition_name]
    @property
    def parameters(self)->dict:
        return self._parameters
    def __str__(self) -> str:
        return f"Action <{self._transition_name}|{self.parameters}>"
    
    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, Action):
            return self.transition == __o.transition and self.parameters == __o.parameters
        return False
    def __hash__(self) -> int:
        return hash(self.transition) + hash("".join(self.parameters))

#Observation - given to agent after taking an action
"""
Observations are given when making a step in the environment.
 - observation: current state of the environment
 - reward: float  value with immediate reward
 - is_terminal: boolean, True if the game ends the current state
 - done: boolean, True if no further interaction is possible (either terminal state or because of timeout)
 - info: dict, can contain additional information about the state
"""
#Observation = namedtuple("Observation", ["observation", "reward", "is_terminal", "done", "info"])
Observation = namedtuple("Observation", ["observation", "reward", "done", "info"])

#Service - agents representation of service found with "FindServices" action
Service = namedtuple("Service", ["name", "type", "version","is_local"])

"""
Game state represents the states in the game state space.

"""
class GameState(object):
    def __init__(self, controlled_hosts:set={}, known_hosts:set={}, known_services:dict={},
    known_data:dict={}, known_networks:set={}) -> None:
        self._controlled_hosts = controlled_hosts
        self._known_networks = known_networks
        self._known_hosts = known_hosts
        self._known_services = known_services
        self._known_data = known_data
    
    @property
    def controlled_hosts(self):
        return self._controlled_hosts

    @property
    def known_hosts(self):
        return self._known_hosts
    
    @property
    def known_services(self):
        return self._known_services
    
    @property
    def known_networks(self):
        return self._known_networks
    
    @property
    def known_data(self):
        return self._known_data
    
    def __str__(self) -> str:
        return f"State<nets:{self.known_networks}; known:{self.known_hosts}; owned:{self.controlled_hosts}; services:{self._known_services}; data:{self._known_data}>"
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, GameState):
            
            #known_nets
            if self.known_networks != other.known_networks:
                return False
            #known_hosts
            if self.known_hosts != other.known_hosts:
                return False
            #controlled_hosts
            if self.controlled_hosts != other.controlled_hosts:
                return False
            #known_services
            if self.known_services != other.known_services:
                return False
            #data
            if self.known_data != other.known_data:
                return False


            # |#known_nets
            # if len(self.known_networks) != len(other.known_networks) or len(self.known_networks.difference(other.known_networks)) != 0:
            #     #print("mismatch in known_nets")
            #     return False
            # #known_hosts
            # if len(self.known_hosts) != len(other.known_hosts) or len(self.known_hosts.difference(other.known_hosts)) != 0:
            #     #print("mismatch in known_hosts")
            #     return False
            # #controlled_hosts
            # if len(self.controlled_hosts) != len(other.controlled_hosts) or len(self.controlled_hosts.difference(other.controlled_hosts)) != 0:
            #     #print("mismatch in owned_nets")
            #     return False
            # #known_services
            # if len(deepdiff.DeepDiff(self.known_services, other.known_services, ignore_order=True)) != 0:
            #     #print("mismatch in known_services")
            #     return False
            # #data
            # if len(deepdiff.DeepDiff(self.known_data, other.known_data, ignore_order=True)) != 0:
            #     #print("mismatch in data")
            #     return False
            return True
        return False
    
    def __hash__(self) -> int:
        return hash(self.known_hosts) + hash(self.known_networks) + hash(self.controlled_hosts) + hash(self.known_data) + hash(self.known_services)
    
    @property
    def as_graph(self):
        node_types = {"network":0, "host":1, "service":2, "datapoint":3}
        graph_nodes = {}
        node_features = []
        controlled = []
        try:
            edges = []
            #add known nets
            for net in self.known_networks:
                graph_nodes[net] = len(graph_nodes)
                node_features.append(node_types["network"])
                controlled.append(0)
            #add known and controlled hosts
            for host in self.known_hosts:
                graph_nodes[host] = len(graph_nodes)
                node_features.append(node_types["host"])
                #add to controlled hosts if needed
                if host in self.controlled_hosts:
                    controlled.append(1)
                else:
                    controlled.append(0)
                #add to proper network if host is in the network
                try:
                    for net in self.known_networks:
                        if host in netaddr.IPNetwork(net):
                            edges.append((graph_nodes[net], graph_nodes[host]))
                            edges.append((graph_nodes[host], graph_nodes[net]))
                except netaddr.core.AddrFormatError as e:
                    print(host, self.known_networks, self.known_hosts, net)
                    print("Error:")
                    print(e)
                    exit()
            #Add known services
            for host,services in self.known_services.items():
                for service in services:
                    graph_nodes[service] = len(graph_nodes)
                    node_features.append(node_types["service"])
                    controlled.append(0)
                    #connect to the proper host
                    try:
                        edges.append((graph_nodes[host], graph_nodes[service]))
                        edges.append((graph_nodes[service], graph_nodes[host]))
                    except KeyError as e:
                        print(self._known_hosts)
                        print(self._known_services)
                        raise e

            #Add known data
            for host,data in self.known_data.items():
                for datapoint in data:
                    graph_nodes[datapoint] = len(graph_nodes)
                    node_features.append(node_types["datapoint"])
                    controlled.append(0)
                    #connect to the proper host
                    edges.append((graph_nodes[host], graph_nodes[datapoint]))
                    edges.append((graph_nodes[datapoint], graph_nodes[host]))

            #print(f"Total Nodes:{total_nodes}")
        except KeyError as e:
            print(f"Error in building graph from {self}: {e}")
        return node_features, controlled, edges, {v:k for k,v in graph_nodes.items()}

    @property
    def as_json(self):
        d = {"nets":list(self.known_networks), "known_hosts":list(self.known_hosts), "controlled_hosts":list(self.controlled_hosts), "known_services":list(self._known_services.items()), "known_data":list(self._known_data.items())}
        return json.dumps(d) 

if __name__ == '__main__':
    # Used for tests

    a = Action("FindServices", ["192.168.1.0"])
    a2 = Action("FindServices", ["192.168.1.0"])
    #print(hash(a), hash(a2))
    
    
    
    # # print(a1, a2, a1==a2)
    s1 = GameState({"192.168.1.0"}, {}, {'213.47.23.195': frozenset([Service(name='bash', type='passive', version='5.0.0'), Service(name='listener', type='passive', version='1.0.0')])},{},{})
    #print(hash(s1))
    s2 = GameState({"192.168.1.0"}, {}, {'213.47.23.195': frozenset([Service(name='listener', type='passive', version='1.0.0'), Service(name='bash', type='passive', version='5.0.0')])}, {},{})
    s3 = GameState({"192.168.1.1"}, {}, {}, {},{})
    #print(s1, s2, s1 == s2)
    q = {}
    if (a,s1) not in q.keys():
        print("missing")
    q[(a,s1)] = 0
    q[(a,s2)] = 1
    print(q)
    q[(a,s3)] = 2
    print(q)
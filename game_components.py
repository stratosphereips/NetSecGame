#Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
# Library of helpful functions and objects to play the net sec game
from collections import namedtuple
import netaddr
import json
from dataclasses import dataclass, field
import enum


class ActionType(enum.Enum):
    #override the __new__ method to enable multiple parameters
    def __new__(cls, *args, **kwds):
        value = len(cls.__members__) + 1
        obj = object.__new__(cls)
        obj._value_ = value  
        return obj    

    def __init__(self, default_success_p:float, default_detection_p:float):
        self.default_success_p = default_success_p
        self.default_detection_p = default_detection_p
    
    #ActionTypes
    ScanNetwork = 0.9, 0.2
    FindServices = 0.9, 0.3
    FindData = 0.8, 0.1
    ExploitService = 0.7, 0.4
    ExfiltrateData = 0.8, 0.1


"""
Service represents the service object in the NetSecGame
"""
@dataclass(frozen=True)
class Service(object):
    name:str
    type:str
    version:str
    is_local:bool

"""
IP represents the ip address object in the NetSecGame
"""
@dataclass(frozen=True)
class IP(object):
    ip:str

    def __repr__(self):
        return self.ip

"""
Network represents the network object in the NetSecGame
"""
@dataclass(frozen=True)
class Network(object):
    ip:str
    mask:int
    
    def __repr__(self):
         return f"{self.ip}/{self.mask}"

    def __str__(self):
         return f"{self.ip}/{self.mask}"


"""
Data represents the data object in the NetSecGame
"""
@dataclass(frozen=True)
class Data(object):
    owner:str
    id:str


# Types of actions
"""
ActionType represents generic action for attacker in the game. Each transition has a default probability
of success and probability of detection (if the defender is present).
Currently 5 action types are implemented:
 - ScanNetwork
 - FindServices
 - FindData
 - ExploitService
 - ExfiltrateData
"""
class ActionType(enum.Enum):
    #override the __new__ method to enable multiple parameters
    def __new__(cls, *args, **kwds):
        value = len(cls.__members__) + 1
        obj = object.__new__(cls)
        obj._value_ = value  
        return obj    

    def __init__(self, default_success_p:float, default_detection_p:float):
        self.default_success_p = default_success_p
        self.default_detection_p = default_detection_p
    
    #ActionTypes
    ScanNetwork = 0.9, 0.2
    FindServices = 0.9, 0.3
    FindData = 0.8, 0.1
    ExploitService = 0.7, 0.4
    ExfiltrateData = 0.8, 0.1

"""
Service represents the service object in the NetSecGame
"""
@dataclass(frozen=True)
class Service(object):
    name:str
    type:str
    version:str
    is_local:bool

"""
IP represents the ip address object in the NetSecGame
"""
@dataclass(frozen=True)
class IP(object):
    ip:str

    def __repr__(self):
        return self.ip

"""
Network represents the network object in the NetSecGame
"""
@dataclass(frozen=True)
class Network(object):
    ip:str
    mask:int
    
    def __repr__(self):
         return f"{self.ip}/{self.mask}"

    def __str__(self):
         return f"{self.ip}/{self.mask}"


"""
Data represents the data object in the NetSecGame
"""
@dataclass(frozen=True)
class Data(object):
    owner:str
    id:str


#Actions
"""
Actions are composed of the action type (see ActionTupe) and additional parameters listed in dictionary
 - ScanNetwork {"target_network": Network object}
 - FindServices {"target_host": IP object}
 - FindData {"target_host": IP object}
 - ExploitService {"target_host": IP object, "target_service": Service object}
 - ExfiltrateData {"target_host": IP object, "source_host": IP object, "data": Data object}
"""
class Action(object):  
    def __init__(self, type: ActionType, params:dict) -> None:
        self._type = type
        self._parameters = params
    
    @property
    def type(self) -> ActionType:
        return self._type
    
    @property
    def parameters(self)->dict:
        return self._parameters

    def __repr__(self) -> str:
        return f"Action <{self._type}|{self._parameters}>"
    
    def __str__(self) -> str:
        return f"Action <{self._type}|{self._parameters}>"
    
    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, Action):
            return self._type == __o.type and self.parameters == __o.parameters
        return False
    
    def __hash__(self) -> int:
        return hash(self._type) + hash("".join(self._parameters))

"""
Game state represents the states in the game state space.
"""
@dataclass(frozen=True)
class GameState(object):
    controlled_hosts:set=field(default_factory=set, hash=True)
    known_hosts:set=field(default_factory=set,  hash=True)
    known_services:dict=field(default_factory=dict, hash=True)
    known_data:dict=field(default_factory=dict,  hash=True)
    known_networks:set=field(default_factory=set,  hash=True)
    
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
                        print(self.known_hosts)
                        print(self.known_services)
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

    def __str__(self) -> str:
        return f"State<nets:{self.known_networks}; known:{self.known_hosts}; owned:{self.controlled_hosts}; services:{self.known_services}; data:{self.known_data}>"
    
    
    def as_json(self):
        d = {"nets":list(self.known_networks), "known_hosts":list(self.known_hosts), "controlled_hosts":list(self.controlled_hosts), "known_services":list(self.known_services.items()), "known_data":list(self.known_data.items())}
        return json.dumps(d) 

# Observation - given to agent after taking an action
"""
Observations are given when making a step in the environment.
 - observation: current state of the environment
 - reward: float  value with immediate reward for last step
 - done: boolean, True if the game ended. 
    No further interaction is possible (either terminal state or because of timeout)
 - info: dict, can contain additional information about the reason for ending
"""
Observation = namedtuple("Observation", ["state", "reward", "done", "info"])


# Main is only used for testing
if __name__ == '__main__':
    # Used for tests
    service_1 = Service("rdp", "passive", "1.067", True)
    service_2 = Service("rdp", "passive", "1.067", True)
    service_3 = Service("sql", "passive", "5.0", True)
    assert (service_1 == service_1 and service_1 is service_1)
    assert (service_1 == service_2)
    assert (service_1 is not service_2)
    assert(service_1 != service_3)

    print(service_1, service_2, service_3)
    IP1 = IP("192.168.1.2")
    IP2 = IP("192.168.1.2")
    IP3 = IP("192.168.0.2")
    assert(IP1 == IP1)
    assert(IP1 == IP2)
    assert(IP2 is not IP1)
    assert(IP1 != IP3)
    
    net1 = Network("192.168.1.0", 32)
    net2 = Network("192.168.1.0", 32)
    net3 = Network("192.168.2.0", 32)
   
    
    d = {net1:[IP1 ,IP2], net3:[]}
    print(d)
    print(len(ActionType))
    for at in ActionType:
        print(at, at.default_success_p, at.default_detection_p)

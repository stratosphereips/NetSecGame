# Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
# Library of helpful functions and objects to play the net sec game
from dataclasses import dataclass, field
import dataclasses
from collections import namedtuple
import json
import enum
import sys
import netaddr
import ipaddress


@dataclass(frozen=True, eq=True, order=True)
class Service():
    """
    Service represents the service object in the NetSecGame
    """
    name: str
    type: str
    version: str
    is_local: bool

"""
IP represents the ip address object in the NetSecGame
"""
@dataclass(frozen=True, eq=True, order=True)
class IP():
    """
    Receives one parameter ip that should be a string
    """
    ip: str

    def __post_init__(self):
        """
        Check if the provided IP is valid
        """
        try:
            ipaddress.ip_address(self.ip)
        except ValueError:
            raise ValueError("Invalid IP address provided")

    def __repr__(self):
        return self.ip

    def is_private(self):
        """
        Return if the IP is private or not
        """
        try:
            return ipaddress.IPv4Network(self.ip).is_private
        except ipaddress.AddressValueError:
            # The IP is a string 
            # In the concepts, 'external' is the string used for external hosts.
            if self.ip != 'external':
                return True
            return False

@dataclass(frozen=True, eq=True)
class Network():
    """
    Network represents the network object in the NetSecGame
    """
    ip: str
    mask: int

    def __repr__(self):
        return f"{self.ip}/{self.mask}"

    def __str__(self):
        return f"{self.ip}/{self.mask}"

    def __lt__(self, other):
        try:
            return netaddr.IPNetwork(str(self)) < netaddr.IPNetwork(str(other))
        except netaddr.core.AddrFormatError:
            return str(self.ip) < str(other.ip)
    
    def __le__(self, other):
        try:
            return netaddr.IPNetwork(str(self)) <= netaddr.IPNetwork(str(other))
        except netaddr.core.AddrFormatError:
            return str(self.ip) <= str(other.ip)
    
    def __gt__(self, other):
        try:
            return netaddr.IPNetwork(str(self)) > netaddr.IPNetwork(str(other))
        except netaddr.core.AddrFormatError:
            return str(self.ip) > str(other.ip)
    
    def is_private(self):
        """
        Return if a network is private or not
        """
        try:
            return ipaddress.IPv4Network(f'{self.ip}/{self.mask}',strict=False).is_private
        except ipaddress.AddressValueError:
            # If we are dealing with strings, assume they are local networks
            return True

"""
Data represents the data object in the NetSecGame
"""
@dataclass(frozen=True, eq=True, order=True)
class Data():
    """
    Class to define dta
    owner is the 'user' owner
    id is the string of the data
    """
    owner: str
    id: str

@enum.unique
class ActionType(enum.Enum):
    """
    ActionType represents generic action for attacker in the game. Each transition has a default probability
    of success and probability of detection (if the defender is present).
    Currently 5 action types are implemented:
    - ScanNetwork
    - FindServices
    - FindData
    - ExploitService
    - ExfiltrateData
    - JoinGame
    - QuitGame
    """

    #override the __new__ method to enable multiple parameters
    def __new__(cls, *args, **kwargs):
        value = len(cls.__members__) + 1
        obj = object.__new__(cls)
        obj._value_ = value
        return obj

    def __init__(self, default_success_p: float):
        self.default_success_p = default_success_p

    @classmethod
    def from_string(cls, string:str):
        match string:
            case "ActionType.ExploitService":
                return ActionType.ExploitService
            case "ActionType.ScanNetwork":
                return  ActionType.ScanNetwork
            case "ActionType.FindServices":
                return ActionType.FindServices
            case "ActionType.FindData":
                return ActionType.FindData
            case "ActionType.ExfiltrateData":
                return ActionType.ExfiltrateData
            case "ActionType.JoinGame":
                return ActionType.JoinGame
            case "ActionType.ResetGame":
                return ActionType.ResetGame
            case "ActionType.QuitGame":
                return ActionType.QuitGame
            case _:
                raise ValueError("Uknown Action Type")

    #ActionTypes
    ScanNetwork = 0.9
    FindServices = 0.9
    FindData = 0.8
    ExploitService = 0.7
    ExfiltrateData = 0.8
    JoinGame = 1
    QuitGame = 1
    ResetGame = 1

@dataclass(frozen=True, eq=True, order=True)
class AgentInfo():
    """
    Receives one parameter ip that should be a string
    """
    name: str
    role: str

    def __repr__(self):
        return f"{self.name}({self.role})"

#Actions
class Action():
    """
    Actions are composed of the action type (see ActionTupe) and additional parameters listed in dictionary
    - ScanNetwork {"target_network": Network object, "source_host": IP object}
    - FindServices {"target_host": IP object, "source_host": IP object,}
    - FindData {"target_host": IP object, "source_host": IP object}
    - ExploitService {"target_host": IP object, "target_service": Service object, "source_host": IP object}
    - ExfiltrateData {"target_host": IP object, "source_host": IP object, "data": Data object}
    """
    def __init__(self, action_type: ActionType, params: dict={}) -> None:
        self._type = action_type
        self._parameters = params

    @property
    def type(self) -> ActionType:
        return self._type
    @property
    def parameters(self)->dict:
        return self._parameters

    @property
    def as_dict(self)->dict:
        params = {}
        for k,v in self.parameters.items():
            if isinstance(v, Service): 
                params[k] = vars(v)
            elif isinstance(v, Data):
                params[k] = vars(v)
            elif isinstance(v, AgentInfo):
                params[k] = vars(v)
            else:
                params[k] = str(v)
        return {"type": str(self.type), "params": params}
    
    @classmethod
    def from_dict(cls, data_dict:dict):
        action_type = ActionType.from_string(data_dict["type"])
        params = {}
        for k,v in data_dict["params"].items():
            match k:
                case "source_host":
                    params[k] = IP(v)
                case "target_host":
                    params[k] = IP(v)
                case "target_network":
                    net,mask = v.split("/")
                    params[k] = Network(net ,int(mask))
                case "target_service":
                    params[k] = Service(**v)
                case "data":
                    params[k] = Data(**v)
                case "agent_info":
                    params[k] = AgentInfo(**v)
                case _:
                    raise ValueError(f"Unsupported Value in {k}:{v}")
        action = Action(action_type=action_type, params=params)
        return action
    
    def __repr__(self) -> str:
        return f"Action <{self._type}|{self._parameters}>"

    def __str__(self) -> str:
        return f"Action <{self._type}|{self._parameters}>"

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, Action):
            return self._type == __o.type and self.parameters == __o.parameters
        return False

    def __hash__(self) -> int:
        sorted_params  = sorted(self._parameters.items(), key= lambda x: x[0])
        sorted_params = [f"{x}{str(y)}" for x,y in sorted_params]
        return hash(self._type) + hash("".join(sorted_params))

    def as_json(self)->str:
        ret_dict = {"action_type":str(self.type)}
        ret_dict["parameters"] = {k:dataclasses.asdict(v) for k,v in self.parameters.items()}
        return json.dumps(ret_dict) 
    


    @classmethod
    def from_json(cls, json_string:str):
        """
        Classmethod to ccreate Action object from json string representation
        """
        parameters_dict = json.loads(json_string)
        action_type = ActionType.from_string(parameters_dict["action_type"])
        parameters = {}
        parameters_dict = parameters_dict["parameters"]
        match action_type:
            case ActionType.ScanNetwork:
                parameters = {"source_host": IP(parameters_dict["source_host"]["ip"]),"target_network": Network(parameters_dict["target_network"]["ip"], parameters_dict["target_network"]["mask"])}
            case ActionType.FindServices:
                parameters = {"source_host": IP(parameters_dict["source_host"]["ip"]), "target_host": IP(parameters_dict["target_host"]["ip"])}
            case ActionType.FindData:
                parameters = {"source_host": IP(parameters_dict["source_host"]["ip"]), "target_host": IP(parameters_dict["target_host"]["ip"])}
            case ActionType.ExploitService:
                parameters = {"target_host": IP(parameters_dict["target_host"]["ip"]),
                              "target_service": Service(parameters_dict["target_service"]["name"],
                                    parameters_dict["target_service"]["type"],
                                    parameters_dict["target_service"]["version"],
                                    parameters_dict["target_service"]["is_local"]),
                                    "source_host": IP(parameters_dict["source_host"]["ip"])}
            case ActionType.ExfiltrateData:
                parameters = {"target_host": IP(parameters_dict["target_host"]["ip"]),
                                "source_host": IP(parameters_dict["source_host"]["ip"]),
                              "data": Data(parameters_dict["data"]["owner"],parameters_dict["data"]["id"])}
            case ActionType.JoinGame:
                parameters = {"agent_info":AgentInfo(parameters_dict["agent_info"]["name"], parameters_dict["agent_info"]["role"])}
            case ActionType.QuitGame:
                parameters = {}
            case ActionType.ResetGame:
                parameters = {}
            case _:
                raise ValueError(f"Unknown Action type:{action_type}")
        action = Action(action_type=action_type, params=parameters)
        return action

@dataclass(frozen=True)
class GameState():
    """
    Game state represents the states in the game state space.
    """
    controlled_hosts: set = field(default_factory=set, hash=True)
    known_hosts: set = field(default_factory=set, hash=True)
    known_services: dict = field(default_factory=dict, hash=True)
    known_data: dict = field(default_factory=dict, hash=True)
    known_networks: set = field(default_factory=set, hash=True)
    
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
                        if str(host) in netaddr.IPNetwork(str(net)):
                            edges.append((graph_nodes[net], graph_nodes[host]))
                            edges.append((graph_nodes[host], graph_nodes[net]))
                except netaddr.core.AddrFormatError as error:
                    print(host, self.known_networks, self.known_hosts)
                    print("Error:")
                    print(error)
                    sys.exit(-1)
            #Add known services
            for host, services in self.known_services.items():
                for service in services:
                    graph_nodes[service] = len(graph_nodes)
                    node_features.append(node_types["service"])
                    controlled.append(0)
                    #connect to the proper host
                    try:
                        edges.append((graph_nodes[host], graph_nodes[service]))
                        edges.append((graph_nodes[service], graph_nodes[host]))
                    except KeyError as error:
                        print(self.known_hosts)
                        print(self.known_services)
                        raise error
            #Add known data
            for host, data in self.known_data.items():
                for datapoint in data:
                    graph_nodes[datapoint] = len(graph_nodes)
                    node_features.append(node_types["datapoint"])
                    controlled.append(0)
                    #connect to the proper host
                    edges.append((graph_nodes[host], graph_nodes[datapoint]))
                    edges.append((graph_nodes[datapoint], graph_nodes[host]))

            #print(f"Total Nodes:{total_nodes}")
        except KeyError as error:
            print(f"Error in building graph from {self}: {error}")
        return node_features, controlled, edges, {v:k for k, v in graph_nodes.items()}

    def __str__(self) -> str:
        return f"State<nets:{self.known_networks}; known:{self.known_hosts}; owned:{self.controlled_hosts}; services:{self.known_services}; data:{self.known_data}>"    

    def as_json(self) -> str:
        """
        Returns json representation of the GameState in string
        """
        ret_dict = self.as_dict
        return json.dumps(ret_dict)

    @property
    def as_dict(self)->dict:
        """
        Returns dict representation of the GameState in string
        """
        ret_dict = {"known_networks":[dataclasses.asdict(x) for x in self.known_networks],
            "known_hosts":[dataclasses.asdict(x) for x in self.known_hosts],
            "controlled_hosts":[dataclasses.asdict(x) for x in self.controlled_hosts],
            "known_services": {str(host):[dataclasses.asdict(s) for s in services] for host,services in self.known_services.items()},
            "known_data":{str(host):[dataclasses.asdict(d) for d in data] for host,data in self.known_data.items()}}
        return ret_dict

    @classmethod
    def from_dict(cls, data_dict:dict):
        state = GameState(known_networks={Network(x["ip"], x["mask"]) for x in data_dict["known_networks"]},
            known_hosts={IP(x["ip"]) for x in data_dict["known_hosts"]},
            controlled_hosts={IP(x["ip"]) for x in data_dict["controlled_hosts"]},
            known_services={IP(k):{Service(s["name"], s["type"], s["version"], s["is_local"])
                for s in services} for k,services in data_dict["known_services"].items()},  
            known_data={IP(k):{Data(v["owner"], v["id"]) for v in values} for k,values in data_dict["known_data"].items()}) 
        return state

    @classmethod
    def from_json(cls, json_string):
        """
        Creates GameState object from json representation in string
        """
        json_data = json.loads(json_string)
        state = GameState(known_networks={Network(x["ip"], x["mask"]) for x in json_data["known_networks"]},
                    known_hosts={IP(x["ip"]) for x in json_data["known_hosts"]},
                    controlled_hosts={IP(x["ip"]) for x in json_data["controlled_hosts"]},
                    known_services={IP(k):{Service(s["name"], s["type"], s["version"], s["is_local"])
                        for s in services} for k,services in json_data["known_services"].items()},  
                    known_data={IP(k):{Data(v["owner"], v["id"]) for v in values} for k,values in json_data["known_data"].items()}) 
        return state


# Observation - given to agent after taking an action
"""
Observations are given when making a step in the environment.
 - observation: current state of the environment
 - reward: float  value with immediate reward for last step
 - end: boolean, True if the game ended. 
    No further interaction is possible (either terminal state or because of timeout)
 - info: dict, can contain additional information about the reason for ending
"""
Observation = namedtuple("Observation", ["state", "reward", "end", "info"])

@enum.unique
class GameStatus(enum.Enum):
    OK = 200
    CREATED = 201
    BAD_REQUEST = 400
    
    @classmethod
    def from_string(cls, string:str):
        match string:
            case "GameStatus.OK":
                return GameStatus.OK
            case "GameStatus.CREATED":
                return GameStatus.CREATED
            case "GameStatus.BAD_REQUEST":
                return GameStatus.BAD_REQUEST
    def __repr__(self) -> str:
        return str(self)
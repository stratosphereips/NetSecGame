# Author Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
# Library of helpful functions and objects to play the net sec game
from dataclasses import dataclass, field, asdict
from typing import Dict, Any
import dataclasses
from collections import namedtuple
import json
import enum
import sys
import netaddr
import ipaddress
import ast


@dataclass(frozen=True, eq=True, order=True)
class Service():
    """
    Service represents the service object in the NetSecGame
    """
    name: str
    type: str = "unknown"
    version: str = "unknown"
    is_local: bool = True

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**data)

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
            raise ValueError(f"Invalid IP address provided: {self.ip}")

    def __repr__(self):
        return self.ip

    def __eq__(self, other):
        if not isinstance(other, IP):
            return NotImplemented
        return self.ip == other.ip
        
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
    @classmethod
    def from_dict(cls, data: dict):
        return cls(**data)
    
    def __hash__(self):
        return hash(self.ip)

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
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(**data)

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
    size: int = 0
    type: str = ""
    content: str = field(default="", compare=False, hash=False)


    def __hash__(self) -> int:
        return hash((self.owner, self.id, self.size, self.type))
    @classmethod
    def from_dict(cls, data: dict):
        return cls(**data)

@enum.unique
class ActionType(enum.Enum):
    ScanNetwork = "ScanNetwork"
    FindServices = "FindServices"
    FindData = "FindData"
    ExploitService = "ExploitService"
    ExfiltrateData = "ExfiltrateData"
    BlockIP = "BlockIP"
    JoinGame = "JoinGame"
    QuitGame = "QuitGame"
    ResetGame = "ResetGame"

    def to_string(self):
        """Convert enum to string."""
        return self.value
    
    def __eq__(self, other):
        # Compare with another ActionType
        if isinstance(other, ActionType):
            return self.value == other.value
        # Compare with a string
        elif isinstance(other, str):
           return self.value == other.replace("ActionType.", "")
        return False

    def __hash__(self):
        # Use the hash of the value for consistent behavior
        return hash(self.value)

    @classmethod
    def from_string(cls, name):
        """Convert string to enum, stripping 'ActionType.' if present."""
        if name.startswith("ActionType."):
            name = name.split("ActionType.")[1]
        try:
            return cls[name]
        except KeyError:
            raise ValueError(f"Invalid ActionType: {name}")

@dataclass(frozen=True, eq=True, order=True)
class AgentInfo():
    """
    Receives one parameter ip that should be a string
    """
    name: str
    role: str

    def __repr__(self):
        return f"{self.name}({self.role})"


    @classmethod
    def from_dict(cls, data: dict):
        return cls(**data)

@dataclass(frozen=True)
class Action:
    """
    Immutable dataclass representing an Action.
    """
    action_type: ActionType
    parameters: Dict[str, Any] = field(default_factory=dict)

    @property
    def as_dict(self) -> Dict[str, Any]:
        """Return a dictionary representation of the Action."""
        params = {}
        for k, v in self.parameters.items():
            if hasattr(v, '__dict__'):  # Handle custom objects like Service, Data, AgentInfo
                params[k] = asdict(v)
            else:
                params[k] = str(v)
        return {"action_type": str(self.action_type), "parameters": params}
    
    @property
    def type(self):
        return self.action_type

    def to_json(self) -> str:
        """Serialize the Action to a JSON string."""
        return json.dumps(self.as_dict)

    @classmethod
    def from_dict(cls, data_dict: Dict[str, Any]) -> "Action":
        """Create an Action from a dictionary."""
        action_type = ActionType.from_string(data_dict["action_type"])
        params = {}
        for k, v in data_dict["parameters"].items():
            match k:
                case "source_host" | "target_host" | "blocked_host":
                    params[k] = IP.from_dict(v)
                case "target_network":
                    params[k] = Network.from_dict(v)
                case "target_service":
                    params[k] = Service.from_dict(v)
                case "data":
                    params[k] = Data.from_dict(v)
                case "agent_info":
                    params[k] = AgentInfo.from_dict(v)
                case "request_trajectory":
                    params[k] = ast.literal_eval(v)
                case _:
                    raise ValueError(f"Unsupported value in {k}: {v}")
        return cls(action_type=action_type, parameters=params)

    @classmethod
    def from_json(cls, json_string: str) -> "Action":
        """Create an Action from a JSON string."""
        data_dict = json.loads(json_string)
        return cls.from_dict(data_dict)

    def __repr__(self) -> str:
        return f"Action <{self.action_type}|{self.parameters}>"

    def __str__(self) -> str:
        return f"Action <{self.action_type}|{self.parameters}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Action):
            return NotImplemented
        return (
            self.action_type == other.action_type and
            self.parameters == other.parameters
        )
    
    def __hash__(self) -> int:
        # Convert parameters to a sorted tuple of key-value pairs for consistency
        sorted_params = tuple(sorted((k, hash(v)) for k, v in self.parameters.items()))
        return hash((self.action_type, sorted_params))

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
    known_blocks: dict = field(default_factory=dict, hash=True)
    
    @property
    def as_graph(self):
        node_types = {"network":0, "host":1, "service":2, "datapoint":3, "blocks": 4}
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
        return f"State<nets:{self.known_networks}; known:{self.known_hosts}; owned:{self.controlled_hosts}; services:{self.known_services}; data:{self.known_data}; blocks:{self.known_blocks}>"    

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
            "known_data":{str(host):[dataclasses.asdict(d) for d in data] for host,data in self.known_data.items()},
            "known_blocks":{str(target_host):[dataclasses.asdict(blocked_host) for blocked_host in blocked_hosts] for target_host, blocked_hosts in self.known_blocks.items()}
                    }
        return ret_dict

    @classmethod
    def from_dict(cls, data_dict:dict):
        if "known_blocks" in data_dict:
            known_blocks = {IP(target_host):{IP(blocked_host["ip"]) for blocked_host in blocked_hosts} for target_host, blocked_hosts in data_dict["known_blocks"].items()}
        else:
            known_blocks = {}
        state = GameState(
            known_networks = {Network(x["ip"], x["mask"]) for x in data_dict["known_networks"]},
            known_hosts = {IP(x["ip"]) for x in data_dict["known_hosts"]},
            controlled_hosts = {IP(x["ip"]) for x in data_dict["controlled_hosts"]},
            known_services = {IP(k):{Service(s["name"], s["type"], s["version"], s["is_local"])
                for s in services} for k,services in data_dict["known_services"].items()},  
            known_data = {IP(k):{Data(v["owner"], v["id"]) for v in values} for k,values in data_dict["known_data"].items()},
            known_blocks = known_blocks
                )
        return state

    @classmethod
    def from_json(cls, json_string):
        """
        Creates GameState object from json representation in string
        """
        json_data = json.loads(json_string)
        state = GameState(
            known_networks = {Network(x["ip"], x["mask"]) for x in json_data["known_networks"]},
            known_hosts = {IP(x["ip"]) for x in json_data["known_hosts"]},
            controlled_hosts = {IP(x["ip"]) for x in json_data["controlled_hosts"]},
            known_services = {IP(k):{Service(s["name"], s["type"], s["version"], s["is_local"])
                for s in services} for k,services in json_data["known_services"].items()},  
            known_data = {IP(k):{Data(v["owner"], v["id"]) for v in values} for k,values in json_data["known_data"].items()},
            known_blocks = {IP(target_host):{IP(blocked_host) for blocked_host in blocked_hosts} for target_host, blocked_hosts in json_data["known_blocks"].items()}
            )
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
    RESET_DONE = 202
    BAD_REQUEST = 400
    FORBIDDEN = 403
    
    @classmethod
    def from_string(cls, string:str):
        match string:
            case "GameStatus.OK":
                return GameStatus.OK
            case "GameStatus.CREATED":
                return GameStatus.CREATED
            case "GameStatus.BAD_REQUEST":
                return GameStatus.BAD_REQUEST
            case "GameStatus.FORBIDDEN":
                return GameStatus.FORBIDDEN
            case "GameStatus.RESET_DONE":
                return GameStatus.RESET_DONE
    def __repr__(self) -> str:
        return str(self)


@enum.unique
class AgentStatus(enum.Enum):
    Playing = "Playing"
    PlayingWithTimeout = "PlayingWithTimeout"
    TimeoutReached = "TimeoutReached"
    ResetRequested = "ResetRequested"
    Success = "Success"
    Fail = "Fail"
    
    def to_string(self):
        """Convert enum to string."""
        return self.value
    
    def __eq__(self, other):
        # Compare with another ActionType
        if isinstance(other, AgentStatus):
            return self.value == other.value
        # Compare with a string
        elif isinstance(other, str):
           return self.value == other.replace("AgentStatus.", "")
        return False

    def __hash__(self):
        # Use the hash of the value for consistent behavior
        return hash(self.value)

    @classmethod
    def from_string(cls, name):
        """Convert string to enum, stripping 'AgentStatus.' if present."""
        if name.startswith("AgentStatus."):
            name = name.split("AgentStatus.")[1]
        try:
            return cls[name]
        except KeyError:
            raise ValueError(f"Invalid AgentStatus: {name}")

@dataclass(frozen=True)
class ProtocolConfig:
    END_OF_MESSAGE = b"EOF"
    BUFFER_SIZE = 8192 
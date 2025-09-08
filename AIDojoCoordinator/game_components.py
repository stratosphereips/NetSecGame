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
    Represents a service in the NetSecGame.

    Attributes:
        name (str): Name of the service.
        type (str): Type of the service. Default `uknown`
        version (str): Version of the service. Default `uknown`
        is_local (bool): Whether the service is local. Default True
    """
    name: str
    type: str = "unknown"
    version: str = "unknown"
    is_local: bool = True

    @classmethod
    def from_dict(cls, data: dict)->"Service":
        """
        Create a Service object from a dictionary.

        Args:
            data (dict): Dictionary with service attributes.

        Returns:
            Service: The created Service object.
        """
        return cls(**data)


@dataclass(frozen=True, eq=True, order=True)
class IP():
    """
    Immutable object representing an IPv4 address in the NetSecGame.

    Attributes:
        ip (str): The IP address in dot-decimal notation.
    """
    ip: str

    def __post_init__(self):
        """
        Verify if the provided IP is valid.

        Raises:
            ValueError: If the IP address is invalid.
        """
        try:
            ipaddress.ip_address(self.ip)
        except ValueError:
            raise ValueError(f"Invalid IP address provided: {self.ip}")

    def __repr__(self)->str:
        """
        Return the string representation of the IP.

        Returns:
            str: The IP address.
        """
        return self.ip

    def __eq__(self, other)->bool:
        """
        Check equality with another IP object.

        Args:
            other (IP): Another IP object.

        Returns:
            is_equal: True if equal, False otherwise.
        """
        if not isinstance(other, IP):
            return NotImplemented
        return self.ip == other.ip
        
    def is_private(self)->bool:
        """
        Check if the IP address is private. Uses ipaddress module.

        Returns:
            is_private: True if the IP is private, False otherwise.
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
    def from_dict(cls, data: dict)->"IP":
        """
        Build the IP object from a dictionary representation.

        Args:
            data (dict): Dictionary with IP attributes.

        Returns:
            IP: The created IP object.
        """
        return cls(**data)
    
    def __hash__(self)->int:
        """
        Compute the hash of the IP.

        Returns:
            hash: The hash value.
        """
        return hash(self.ip)

@dataclass(frozen=True, eq=True)
class Network():
    """
    Immutable object representing an IPv4 network in the NetSecGame.

    Attributes:
        ip (str): IP address of the network.
        mask (int): CIDR mask of the network.
    """
    ip: str
    mask: int

    def __repr__(self)->str:
        """
        Return the string representation of the network.

        Returns:
            str: The network in CIDR notation.
        """
        return f"{self.ip}/{self.mask}"

    def __str__(self)->str:
        """
        Return the string representation of the network.

        Returns:
            str: The network in CIDR notation.
        """
        return f"{self.ip}/{self.mask}"

    def __lt__(self, other)->bool:
        """
        Less-than comparison for networks.

        Args:
            other (Network): Another network.

        Returns:
            bool: True if self < other, False otherwise.
        """
        try:
            return netaddr.IPNetwork(str(self)) < netaddr.IPNetwork(str(other))
        except netaddr.core.AddrFormatError:
            return str(self.ip) < str(other.ip)
    
    def __le__(self, other)->bool:
        """
        Less-than-or-equal comparison for networks.

        Args:
            other (Network): Another network.

        Returns:
            bool: True if self <= other, False otherwise.
        """
        try:
            return netaddr.IPNetwork(str(self)) <= netaddr.IPNetwork(str(other))
        except netaddr.core.AddrFormatError:
            return str(self.ip) <= str(other.ip)
    
    def __gt__(self, other)->bool:
        """
        Greater-than comparison for networks.

        Args:
            other (Network): Another network.

        Returns:
            bool: True if self > other, False otherwise.
        """
        try:
            return netaddr.IPNetwork(str(self)) > netaddr.IPNetwork(str(other))
        except netaddr.core.AddrFormatError:
            return str(self.ip) > str(other.ip)
    
    def is_private(self)->bool:
        """
        Check if the network is private. Uses ipaddress module.

        Returns:
            bool: True if the network is private, False otherwise.
        """
        try:
            return ipaddress.IPv4Network(f'{self.ip}/{self.mask}',strict=False).is_private
        except ipaddress.AddressValueError:
            # If we are dealing with strings, assume they are local networks
            return True
    
    @classmethod
    def from_dict(cls, data: dict)->"Network":
        """
        Build the Network object from a dictionary.

        Args:
            data (dict): Dictionary with network attributes.

        Returns:
            Network: The created Network object.
        """
        return cls(**data)

@dataclass(frozen=True, eq=True, order=True)
class Data():
    """
    Represents a data object in the NetSecGame.

    Attributes:
        owner (str): Owner of the data. 
        id (str): Identifier of the data.
        size (int): Size of the data. Default = 0
        type (str): Type of the data. Default = ""
        content (str): Content of the data. Default = ""
    """
    owner: str
    id: str
    size: int = field(compare=False, hash=False, default=0)
    type: str = ""
    content: str = field(compare=False, hash=False, repr=False, default_factory=str)

    def __hash__(self) -> int:
        """
        Compute the hash of the Data object.

        Returns:
            int: The hash value.
        """
        return hash((self.owner, self.id, self.type))
    @classmethod
    def from_dict(cls, data: dict)->"Data":
        """
        Build the Data object from a dictionary.

        Args:
            data (dict): Dictionary with data attributes.

        Returns:
            Data: The created Data object.
        """
        return cls(**data)

@enum.unique
class ActionType(enum.Enum):
    """
    Enum representing possible action types in the NetSecGame.
    """
    ScanNetwork = "ScanNetwork"
    FindServices = "FindServices"
    FindData = "FindData"
    ExploitService = "ExploitService"
    ExfiltrateData = "ExfiltrateData"
    BlockIP = "BlockIP"
    JoinGame = "JoinGame"
    QuitGame = "QuitGame"
    ResetGame = "ResetGame"

    def to_string(self)->str:
        """
        Convert the ActionType enum to string.

        Returns:
            str: The string representation.
        """
        return self.value
    
    def __eq__(self, other)->bool:
        """
        Compare ActionType with another ActionType or string.

        Args:
            other (ActionType or str): The object to compare.

        Returns:
            bool: True if equal, False otherwise.
        """
        # Compare with another ActionType
        if isinstance(other, ActionType):
            return self.value == other.value
        # Compare with a string
        elif isinstance(other, str):
           return self.value == other.replace("ActionType.", "")
        return False

    def __hash__(self)->int:
        """
        Compute the hash of the ActionType.

        Returns:
            int: The hash value.
        """
        # Use the hash of the value for consistent behavior
        return hash(self.value)

    @classmethod
    def from_string(cls, name)->"ActionType":
        """
        Convert a string to an ActionType enum. Strips 'ActionType.' if present.

        Args:
            name (str): The string representation.

        Returns:
            ActionType: The corresponding ActionType.

        Raises:
            ValueError: If the string does not match any ActionType.
        """
        if name.startswith("ActionType."):
            name = name.split("ActionType.")[1]
        try:
            return cls[name]
        except KeyError:
            raise ValueError(f"Invalid ActionType: {name}")

@dataclass(frozen=True, eq=True, order=True)
class AgentInfo():
    """
    Represents agent information.

    Attributes:
        name (str): Name of the agent.
        role (str): Role of the agent.
    """
    name: str
    role: str

    def __repr__(self)->str:
        """
        Return the string representation of the AgentInfo.

        Returns:
            str: The agent info as a string.
        """
        return f"{self.name}({self.role})"


    @classmethod
    def from_dict(cls, data: dict)->"AgentInfo":
        """
        Build the AgentInfo object from a dictionary.

        Args:
            data (dict): Dictionary with agent info attributes.

        Returns:
            AgentInfo: The created AgentInfo object.
        """
        return cls(**data)

@dataclass(frozen=True)
class Action:
    """
    Immutable dataclass representing an Action.

    Attributes:
        action_type (ActionType): The type of action.
        parameters (Dict[str, Any]): Parameters for the action.
    """
    action_type: ActionType
    parameters: Dict[str, Any] = field(default_factory=dict)

    @property
    def as_dict(self) -> Dict[str, Any]:
        """
        Return a dictionary representation of the Action.

        Returns:
            Dict[str, Any]: The action as a dictionary.
        """
        params = {}
        for k, v in self.parameters.items():
            if hasattr(v, '__dict__'):  # Handle custom objects like Service, Data, AgentInfo
                params[k] = asdict(v)
            elif isinstance(v, bool):  # Handle boolean values
                params[k] = v
            else:
                params[k] = str(v)
        return {"action_type": str(self.action_type), "parameters": params}
    
    @property
    def type(self)->ActionType:
        """
        Return the action type.

        Returns:
            ActionType: The action type.
        """
        return self.action_type
    
    def to_json(self) -> str:
        """
        Serialize the Action to a JSON string.

        Returns:
            str: The JSON string representation.
        """
        return json.dumps(self.as_dict)

    @classmethod
    def from_dict(cls, data_dict: Dict[str, Any]) -> "Action":
        """
        Create an Action from a dictionary.

        Args:
            data_dict (Dict[str, Any]): The action as a dictionary.

        Returns:
            Action: The created Action object.

        Raises:
            ValueError: If an unsupported parameter is encountered.
        """
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
                case "request_trajectory" | "randomize_topology":
                    if isinstance(v, bool):
                        params[k] = v
                    else:
                        params[k] = ast.literal_eval(v)
                case _:
                    raise ValueError(f"Unsupported value in {k}: {v}")
        return cls(action_type=action_type, parameters=params)

    @classmethod
    def from_json(cls, json_string: str) -> "Action":
        """
        Create an Action from a JSON string.

        Args:
            json_string (str): The JSON string representation.

        Returns:
            Action: The created Action object.
        """
        data_dict = json.loads(json_string)
        return cls.from_dict(data_dict)

    def __repr__(self) -> str:
        """
        Return the string representation of the Action.

        Returns:
            str: The action as a string.
        """
        return f"Action <{self.action_type}|{self.parameters}>"

    def __str__(self) -> str:
        """
        Return the string representation of the Action.

        Returns:
            str: The action as a string.
        """
        return f"Action <{self.action_type}|{self.parameters}>"

    def __eq__(self, other: object) -> bool:
        """
        Check equality with another Action object.

        Args:
            other (object): Another Action object.

        Returns:
            bool: True if equal, False otherwise.
        """
        if not isinstance(other, Action):
            return NotImplemented
        return (
            self.action_type == other.action_type and
            self.parameters == other.parameters
        )
    
    def __hash__(self) -> int:
        """
        Compute the hash of the Action.

        Returns:
            int: The hash value.
        """
        # Convert parameters to a sorted tuple of key-value pairs for consistency
        sorted_params = tuple(sorted((k, hash(v)) for k, v in self.parameters.items()))
        return hash((self.action_type, sorted_params))

@dataclass(frozen=True)
class GameState():
    """
    Represents the state of the game.

    Attributes:
        controlled_hosts (set): Controlled hosts.
        known_hosts (set): Known hosts.
        known_services (dict): Known services.
        known_data (dict): Known data.
        known_networks (set): Known networks.
        known_blocks (dict): Known blocks.
    """
    controlled_hosts: set = field(default_factory=set, hash=True)
    known_hosts: set = field(default_factory=set, hash=True)
    known_services: dict = field(default_factory=dict, hash=True)
    known_data: dict = field(default_factory=dict, hash=True)
    known_networks: set = field(default_factory=set, hash=True)
    known_blocks: dict = field(default_factory=dict, hash=True)
    
    @property
    def as_graph(self)->tuple:
        """
        Build a graph representation of the game state.

        Returns:
            tuple: (node_features, controlled, edges, node_index_map)
        """
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
        """
        Return the string representation of the GameState.

        Returns:
            str: The game state as a string.
        """
        return f"State<nets:{self.known_networks}; known:{self.known_hosts}; owned:{self.controlled_hosts}; services:{self.known_services}; data:{self.known_data}; blocks:{self.known_blocks}>"    

    def as_json(self) -> str:
        """
        Return the JSON representation of the GameState.

        Returns:
            str: The JSON string.
        """
        ret_dict = self.as_dict
        return json.dumps(ret_dict)

    @property
    def as_dict(self)->dict:
        """
        Return the dictionary representation of the GameState.

        Returns:
            dict: The game state as a dictionary.
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
    def from_dict(cls, data_dict:dict)->"GameState":
        """
        Create a GameState from a dictionary.

        Args:
            data_dict (dict): The game state as a dictionary.

        Returns:
            GameState: The created GameState object.
        """
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
            known_data = {IP(k):{Data(v["owner"], v["id"], v["size"], v["type"], v["content"]) for v in values} for k,values in data_dict["known_data"].items()},
            known_blocks = known_blocks
                )
        return state

    @classmethod
    def from_json(cls, json_string)->"GameState":
        """
        Create a GameState from a JSON string.

        Args:
            json_string (str): The JSON string.

        Returns:
            GameState: The created GameState object.
        """
        json_data = json.loads(json_string)
        state = GameState(
            known_networks = {Network(x["ip"], x["mask"]) for x in json_data["known_networks"]},
            known_hosts = {IP(x["ip"]) for x in json_data["known_hosts"]},
            controlled_hosts = {IP(x["ip"]) for x in json_data["controlled_hosts"]},
            known_services = {IP(k):{Service(s["name"], s["type"], s["version"], s["is_local"])
                for s in services} for k,services in json_data["known_services"].items()},  
            known_data = {IP(k):{Data(v["owner"], v["id"], v["size"], v["type"], v["content"]) for v in values} for k,values in json_data["known_data"].items()},
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
    """
    Enum representing possible game statuses.
    """
    OK = 200

    CREATED = 201
    RESET_DONE = 202
    BAD_REQUEST = 400
    FORBIDDEN = 403
    
    @classmethod
    def from_string(cls, string:str)->"GameStatus":
        """
        Convert a string to a GameStatus enum.

        Args:
            string (str): The string representation.

        Returns:
            GameStatus: The corresponding GameStatus.
        """
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
        """
        Return the string representation of the GameStatus.

        Returns:
            str: The game status as a string.
        """
        return str(self)


@enum.unique
class AgentStatus(enum.Enum):
    """
    Enum representing possible agent statuses.
    """
    Playing = "Playing"
    PlayingWithTimeout = "PlayingWithTimeout"
    TimeoutReached = "TimeoutReached"
    ResetRequested = "ResetRequested"
    Success = "Success"
    Fail = "Fail"
    
    def to_string(self)->str:
        """
        Convert the AgentStatus enum to string.

        Returns:
            str: The string representation.
        """
        return self.value
    
    def __eq__(self, other)->bool:
        """
        Compare AgentStatus with another AgentStatus or string.

        Args:
            other (AgentStatus or str): The object to compare.

        Returns:
            bool: True if equal, False otherwise.
        """
        # Compare with another ActionType
        if isinstance(other, AgentStatus):
            return self.value == other.value
        # Compare with a string
        elif isinstance(other, str):
           return self.value == other.replace("AgentStatus.", "")
        return False

    def __hash__(self)->int:
        """
        Compute the hash of the AgentStatus.

        Returns:
            int: The hash value.
        """
        # Use the hash of the value for consistent behavior
        return hash(self.value)

    @classmethod
    def from_string(cls, name)->"AgentStatus":
        """
        Convert a string to an AgentStatus enum.

        Args:
            name (str): The string representation.

        Returns:
            AgentStatus: The corresponding AgentStatus.

        Raises:
            ValueError: If the string does not match any AgentStatus.
        """
        if name.startswith("AgentStatus."):
            name = name.split("AgentStatus.")[1]
        try:
            return cls[name]
        except KeyError:
            raise ValueError(f"Invalid AgentStatus: {name}")

@dataclass(frozen=True)
class ProtocolConfig:
    """
    Configuration for protocol constants.

    Attributes:
        END_OF_MESSAGE (bytes): End-of-message marker.
        BUFFER_SIZE (int): Buffer size for messages.
    """
    END_OF_MESSAGE = b"EOF"
    BUFFER_SIZE = 8192 
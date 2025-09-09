## NetSecGame Architecture
The Network Security Game(NSG) works as a game server - agents connect to it via TCP sockets and interact with the environment using the standard RL communication loop: Agent submits actinon and recieves new observation of the environment. The NSG supports real-time, highly customizable multi-agent simulations.

## Game Components
The following classes are used in the game to hold information about the state of the game. They are used both in the [Actions](#actions) and [GameState](#gamestate). See the API Reference for [GameComponents](game_components.md)
### Building blocks
#### IP
IP is immutable object that represents an IPv4 object in the NetSecGame. It has a single parameter of the address in a dot-decimal notation (4 octet represeted as decimal value separeted by dots).

Example: 
```python
 ip = IP("192.168.1.1")
```

#### Network
Network is immutable object that represents an IPv4 network object in the NetSecGame. It has 2 parameters:
- `network_ip:str` representing the IPv4 address of the network.
- `mask:int` representing the mask in the CIDR notation.

Example: 
```python
net = Network("192.168.1.0", 24)
```
#### Service
Service class holds information about services running in hosts. Each Service has four parameters:
- `name`:str  - Name of the service (e.g., "SSH")
- `type`:str - `passive` or `active`. Currently not being used.
- `version`:str - version of the service.
- `is_local`:bool - flag specifying if the service is local only. (if `True`, service is NOT visible without controlling the host).

Example: 
```python
s = Service('postgresql', 'passive', '14.3.0', False)
```

#### Data
Data class holds information about datapoints (files) present in the NetSecGame.
Each data instance has two parameters:
- `owner`:str - specifying the user who owns this datapoint
- `id`: str - unique identifier of the datapoint in a host
- `size`: int - size of the datapoint (optional, default=0)
- `type`: str - identification of a type of the file (optional, default="")
- `content`: str - content of the data (optional, default="")

Examples:
```python
d1 = Data("User1", "DatabaseData")
d2 = Data("User1", "DatabaseData", size=42, type="txt", "SecretUserDatabase")
```

### GameState
GameState is an object that represents a view of the NetSecGame environment in a given state. It is constructed as a collection of 'assets' available to the agent. GameState has following parts:
- `known_networks`: Set of [Network](#network) objects that the agent is aware of
- `known_hosts`: Set of [IP](#ip) objects that the agent is aware of
- `controlled_hosts`: Set of [IP](#ip) objetcs that the agent has control over. Note that `controlled_hosts` is a subset of `known_hosts`.
- `known_services`: Dictionary of services that the agent is aware of.
The dictionary format: {`IP`: {`Service`}} where [IP](#ip) object is a key and the value is a set of [Service](#service) objects located in the `IP`.
- `known_data`: Dictionary of data instances that the agent is aware of. The dictionary format: {`IP`: {`Data`}} where [IP](#ip) object is a key and the value is a set of [Data](#data) objects located in the `IP`.
- `known_blocks`: Dictionary of firewall blocks the agent is aware of. It is a dictionary with format: {`target_IP`: {`blocked_IP`, `blocked_IP`}}. Where `target_IP` is the [IP](#ip) where the FW rule was applied (usually a router) and `blocked_IP` is the IP address that is blocked. For now the blocks happen in both input and output direction simultaneously.


### Actions
Actions are the objects sent by the agents to the environment. Each action is evaluated by NetSecGame and executed if
1. It is a valid Action
2. Can be processed in the current state of the environment

In all cases, when an agent sends an action to NetSecGame, it is given a response.

#### Action format
The Action consists of two parts
1. ActionType - specifying the class of the action
2. parameters - dictionary with specific parameters related to the used ActionType

#### List of ActionTypes
- **JoinGame**, params={`agent_info`:AgentInfo(`<name>`, `<role>`)}: Used to register agent in a game with a given `<role>`.
- **QuitGame**, params={}: Used for termination of agent's interaction.
- **ResetGame**, params={`request_trajectory`:`bool` (default=`False`),  `randomize_topology`=`bool` (default=`True`)}: Used for requesting reset of the game to it's initial position. If `request_trajectory = True`, the coordinator will send back the complete trajectory of the previous run in the next message. If `randomize_topology`=`True`, the agent request topology to be changed in the next episode. NOTE: the topology is changed only if (i) the `use_dynamic_ips` is set to `True` in the task configuration AND all active agents ask for the change.
---
- **ScanNetwork**, params{`source_host`:`<IP>`, `target_network`:`<Network>`}: Scans the given `<Network>` from a specified source host. Discovers ALL hosts in a network that are accessible from `<IP>`. If successful, returns set of discovered `<IP>` objects.
- **FindServices**, params={`source_host`:`<IP>`, `target_host`:`<IP>`}: Used to discover ALL services running in the `target_host` if the host is accessible from `source_host`. If successful, returns a set of all discovered `<Service>` objects.
- **FindData**, params={`source_host`:`<IP>`, `target_host`:`<IP>`}: Searches `target_host` for data. If `source_host` differs from `target_host`, success depends on accessability from the `source_host`. If successful, returns a set of all discovered `<Data>` objects.
- **ExploitService**, params={`source_host`:`<IP>`, `target_host`:`<IP>`, `taget_service`:`<Service>`}: Exploits `target_service` in a specified `target_host`. If successful, the attacker gains control of the `target_host`.
- **ExfiltrateData**, params{`source_host`:`<IP>`, `target_host`:`<IP>`, `data`:`<IP>`}: Copies `data` from the `source_host` to `target_host` IF both are controlled and `target_host` is accessible from `source_host`.

### Action preconditions and effects
In the following table, we describe the effects of selected actions and their preconditions. Note that if the preconditions are not satisfied, the actions's effects are not applied.

| Action | Params | Preconditions | Effects |
|----------------------|----------------------|----------------------|----------------------|
| ScanNetwork| `source_host`, `target_network`| `source_host` &isinv; `controlled_hosts`| extends `known_networks`|
|FindServices| `source_host`, `target_host`| `source_host` &isinv; `controlled_hosts`| extends `known_services` AND `known_hosts`|
|FindData| `source_host`, `target_host`| `source_host`, `target_host` ∈ `controlled_hosts`| extends `known_data`|
|Exploit Service | `source_host`, `target_host`, `target_service`|`source_host` &isinv; `controlled_hosts`| extends `controlled_hosts` with `target_host`|
ExfiltrateData| `source_host`,`target_host`, `data` |`source_host`, `target_host` ∈ `controlled_hosts` AND `data` ∈ `known_data`| extends `known_data[target_host]` with `data`|
|BlockIP | `source_host`, `target_host`, `blockedIP`|`source_host` &isinv; `controlled_hosts`| extends `known_blocks[target_host]` with `blockedIP`|

#### Assumption and Conditions for Actions
1. When playing the `ExploitService` action, it is expected that the agent has discovered this service before (by playing `FindServices` in the `target_host` before this action)
2. The `Find Data` action finds all the available data in the host if successful.
3. The `Find Data` action requires ownership of the target host.
4. Playing `ExfiltrateData` requires controlling **BOTH** source and target hosts
5. Playing `Find Services` can be used to discover hosts (if those have any active services)
6. Parameters of `ScanNetwork` and `FindServices` can be chosen arbitrarily (they don't have to be listed in `known_newtworks`/`known_hosts`)

### Observations
After submitting Action `a` to the environment, agents receive an `Observation` in return. Each observation consists of 4 parts:
- `state`:`Gamestate` - with the current view of the environment [state](#gamestate)
- `reward`: `int` - with the immediate reward agent gets for playing Action `a`
- `end`:`bool` - indicating if the interaction can continue after playing Action `a`
- `info`: `dict` - placeholder for any information given to the agent (e.g., the reason why `end is True` )
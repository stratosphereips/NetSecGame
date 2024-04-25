# Game Components
Here you can see the details of all components of the NetSetEnvironment and their usage. These components are located in [game_components.py](/env/game_components.py).

## Building blocks
Following classes are used in the game to hold information about the state of the game. They are used both in the [Actions](#actions) and [GameState](#gamestate).

### IP
IP is immutable object that represents an IPv4 object in the NetSecGame. It has a single parameter of the address in a dot-decimal notation (4 octet represeted as decimal value separeted by dots).

Example: `ip = IP("192.168.1.1")`

### Network
Network is immutable object that represents a IPv4 network object in the NetSecGame. It has 2 parameters:
- `network_ip:str` representing the IPv4 address of the network.
- `mask:int` representing the mask in the CIDR notation.

Example: `net = Network("192.168.1.0", 24)`

## Service
Service class holds information about services running in hosts. Each Service has four parameters:
- `name`:str  - Name of the service (e.g. "SSH")
- `type`:str - `passive` or `active`. Currently not being used.
- `version`:str - version of the service.
- `is_local`:bool - flag specifying if the service is local only. (if `True`, service is NOT visible wihtout controlling the host).

Example: `s = Service('postgresql', 'passive', '14.3.0', False)`

## Data
Data class holds information about datapoints (files) present in the NetSecGame. Datapoints DO NOT hold the content of files.
Each data instance has two parameters:
- `owner`:str - specifying the user who ownes this datapoint
- `id`: str - unique identifier of the datapoint in a host
- `size`: int - size of the datapoint (optional, default=0)
- `type`: str - indetification of a type of the file (optional, default="")

Example:`Data("User1", "DatabaseData")`

## GameState
GameState is a object which represents a view of the NetSecGame environment in a given state. It is constructed as a collection of 'assets' available to the agent. GameState has following parts:
- `known_networks`: Set of [Network](#network) objects that the agent is aware of
- `known_hosts`: Set of [IP](#ip) objects that the agent is aware of
- `controlled_hosts`: Set of [IP](#ip) objetcs that the agent has control over. Note that `controlled_hosts` is a subset of `known_hosts`.
- `known_services`: Dictionary of services that the agent is aware of.
The dictonary format: {`IP`: {`Service`}} where [IP](#ip) object is a key and the value is a set of [Service](#service) objects located in the `IP`.
- `known_data`: Dictionary of data instances that the agent is aware of. The dictonary format: {`IP`: {`Data`}} where [IP](#ip) object is a key and the value is a set of [Data](#data) objects located in the `IP`.


## Actions
Actions are the objects send by the agents to the environment. Each action is evaluated by AIDojo and executed if
1. Is a valid Action
2. Can be processed in the current state of the environment

In all cases, when an agent sends action to AIDojo, it is given a response.
### Action format
The Action class is defined in `env.game_components.py`. It has two basic parts:
1. ActionType:Enum
2. parameters:dict

ActionType is unique Enum that determines what kind of action is agent playing. Parameters are passed in a dictionary as follows.
### List of actions
- **JoinGame**, params={`agent_info`:AgentInfo(\<name\>, \<role\>)}: Used to register agent in a game with a given \<role\>.
- **QuitGame**, params={}: Used for termination of agent's interaction.
- **ResetGame**, params={}: Used for requesting reset of the game to it's initial position.
---
- **ScanNetwork**, params{`source_host`:\<IP\>, `target_network`:\<Network\>}: Scans the given \<Network\> from a specified source host. Discovers ALL hosts in a network which are accessible from \<IP\>. If successful, returns set of discovered \<IP\> objects.
- **FindServices**, params={`source_host`:\<IP\>, `target_host`:\<IP\>}: Used to discover ALL services running in the `target_host` if the host is accessible from `source_host`. If sucessful, returns set of all dicovered \<Service\> objects.
- **FindData**, params={`source_host`:\<IP\>, `target_host`:\<IP\>}: Searches `target_host` for data. If `source_host` differs from `target_host` success depends on accessability from the `source_host`. If sucessful, returns set of all discovered \<Data\> objects.
- **ExploitService**, params={`source_host`:\<IP\>, `target_host`:\<IP\>, `taget_service`:\<Service\>}: Exploits `target_service` in a specified `target_host`. If sucessful, the attacker gains control of the `target_host`.
- **ExfiltrateData**, params{`source_host`:\<IP\>, `target_host`:\<IP\>, `data`:\<Data\>}: Copies `data` from the `source_host` to `target_host` IF both are controlled and `target_host` is accessible from `source_host`.

### Action preconditons and effects
In the following table, we describe effects of selected actions and their preconditions. Note that if the preconditions are not satisfied, the actions's effects are not applied.

| Action | Params | Preconditions | Effects |
|----------------------|----------------------|----------------------|----------------------|
| ScanNetwork| `source_host`, `target_network`| `source_host` &isinv; `controlled_hosts`| extends `known_networks`|
|FindServices| `source_host`, `target_host`| `source_host` &isinv; `controlled_hosts`| extends `known_services` AND `known_hosts`|
|FindData| `source_host`, `target_host`| `source_host`, `target_host` ∈ `controlled_hosts`| extends `known_data`|
|Exploit Service | `source_host`, `target_host`, `target_service`|`source_host` &isinv; `controlled_hosts`| extends `controlled_hosts` with `target_host`|
ExfiltrateData| `source_host`,`target_host`, `data` |`source_host`, `target_host` ∈ `controlled_hosts` AND `data` ∈ `known_data`| extends `known_data[target_host]` with `data`|

#### Assumption and Conditions for Actions
1. When playing the `ExploitService` action, it is expected that the agent has discovered this service before (by playing `FindServices` in the `target_host` before this action)
2. The `Find Data` action finds all the available data in the host if successful.
3. The `Find Data` action requires ownership of the target host.
4. Playing `ExfiltrateData` requires controlling **BOTH** source and target hosts
5. Playing `Find Services` can be used to discover hosts (if those have any active services)
6. Parameters of `ScanNetwork` and `FindServices` can be chosen arbitrarily (they don't have to be listed in `known_newtworks`/`known_hosts`)

## Observations
After submitting Action `a` to the environment, agents receives an `Observation` in return. Each observation consists of 4 parts:
- `state`:`Gamestate` - with the current view of the environment [state](#gamestate)
- `reward`: `int` - with the imedeate reward agent gets for playing Action `a`
- `end`:`bool` - indicating if the intaraction can continue after playing Action `a`
- `info`: `dict` - placeholder for any information given to the agent (e.g. the reason why `end is True` )
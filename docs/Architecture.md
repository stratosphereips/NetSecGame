# Architecture

The NetSecEnv game is using the client-server architecture. The Server runs the [Coordinator](/docs/Coordinator.md) which manages:
 - creation of the game server and communication with agents.
 - processing agent request (see [Actions](/docs/Components.md)) and responses (see [Observations](/docs/Components.md))
 - communication with the game engine and forwarding messages between the agents and the game engine

<img src="/docs/figures/architecture_diagram.jpg" alt="Architecture overview" width="30%"/>

 ## Network Security Environment
The environment internally tracks all objects available in the wolrd and their interactions. Following data structures are used for that purpose:
- `self._ip_to_hostname` - Mapping of `IP`:`host_name`(str) of all nodes in the environment
- `self._networks` - A `dict` of the networks present in the environment. Keys: `Network` objects, values `set` of `IP` objects.
- `self._services` - Dict of all services in the environment. Keys: hostname (`str`), values: `set` of `Service` objetcs.
- `self._data` - Dict of all services in the environment. Keys: hostname (`str`), values `set` of `Service` objetcs.

 
 
 ## Agents
 Agents are separate programs that can interact with the NetSecEnv vie TCP sockets. See the [NetSecGameAgents](/NetSecGameAgents) repository for details on the agents.

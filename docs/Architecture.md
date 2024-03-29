# Architecture

The NetSecEnv game is using the client-server architecture. The Server runs the [Coordinator](/docs/Coordinator.md) which manages:
 - creation of the game server and communication with agents.
 - processing agent request (see [Actions](/docs/Components.md)) and responses (see [Observations](/docs/Components.md))
 - communication with the game engine and forwarding messages between the agents and the game engine

<img src="/docs/figures/architecture_diagram.jpg" alt="Architecture overview" width="30%"/>

 ## Agents
 Agents are separate programs that can interact with the NetSecEnv vie TCP sockets. See the [NetSecGameAgents](/NetSecGameAgents) repository for details on the agents.

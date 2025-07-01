# Game Coordinator
Coordinator is the centerpiece of the game orchestration. It provides an interface between the agents and the worlds.

In detail it handles:
1. World initialiazation
2. Registration of new agents in the game
3. Agent-World communication (message verification and forwarding)
4. Recording (and storing) trajectories of agents (optional)
4. Detection of episode ends (either by reaching timout or agents reaching their respective goals)
5. Assigning rewards for each action and at the end of each episode
6. Removing agents from the game
7. Registering the GameReset requests and handelling the game resets.

To facilitate the communication the coordinator uses a TCP server to which agents connect. The communication is asynchronous and depends of the
::: AIDojoCoordinator.coordinator.AgentServer
::: AIDojoCoordinator.coordinator.GameCoordinator
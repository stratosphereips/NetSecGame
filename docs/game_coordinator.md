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

## Connction to other game components
Coordinator, having the role of the middle man in all communication between the agent and the world uses several queues for massing passing and handelling.

1. `Action queue` is a queue in which the agents submit their actions. It provides N:1 communication channel in which the coordinator receives the inputs.
2. `Answer queues` is a separeate queue **per agent** in which the results of the actions are send to the agent.

## Episode
The episode starts with sufficient amount of agents registering in the game. Each agent role has a maximum allowed number of steps defined in the task configuration. An episode ends if all agents reach the goal 

::: AIDojoCoordinator.coordinator.AgentServer
::: AIDojoCoordinator.coordinator.GameCoordinator
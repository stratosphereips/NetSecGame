# Coordinator
Coordinator is the centerpiece of the game orchestration. It provides an interface between the agents and the AIDojo world.

1. Registration of new agents in the game
2. Verification of agents' action format
3. Recording (and storing) trajectories of agents
4. Detection of episode ends (either by reaching timout or agents reaching their respective goals)
5. Assigning rewards for each action and at the end of each episode
6. Removing agents from the game
7. Registering the GameReset requests and handelling the game resets.

## Connction to other game components
Coordinator, having the role of the middle man in all communication between the agent and the world uses several queues for massing passing and handelling.

1. `Action queue` is a queue in which the agents submit their actions. It provides N:1 communication channel in which the coordinator receives the inputs.
2. `Answer queues` is a separeate queue **per agent** in which the results of the actions are send to the agent.


## Main components of the coordinator
`self._actions_queue`: asycnio queue for agents -> coordinator communication
`self._answer_queues`: dictionary of asycnio queues for coordinator -> agent communication (1 queue per agent)
`self._world_action_queue`: asycnio queue for coordinator -> world  queue communication
`self._world_response_queue`: asycnio queue for world -> coordinator  queue communication
`self.task_config`: Object with the configuration of the scenario
`self.ALLOWED_ROLES`: list of allowed agent roles [`Attacker`, `Defender`, `Benign`]
`self._world`: Instance of `AIDojoWorld`. Implements the dynamics of the world   
`self._CONFIG_FILE_HASH`: hash of the configuration file used in the interaction (scenario, topology, etc.). Used for better reproducibility of results
`self._starting_positions_per_role`: dictionary of starting position of each agent type from `self.ALLOWED_ROLES`
`self._win_conditions_per_role`: dictionary of goal state for each agent type from `self.ALLOWED_ROLES`
`self._goal_description_per_role`: dictionary of textual description of goal of each agent type from `self.ALLOWED_ROLES`
`self._steps_limit_per_role`: dictionary of maximum allowed steps per episode for of each agent type from `self.ALLOWED_ROLES`
`self._use_global_defender`: Inditaction of presence of Global defender (deprecated)

### Agent information components
`self.agents`: information about connected agents {`agent address`: (`agent_name`,`agent_role`)}
`self._agent_steps`: step counter for each agent in the current episode
`self._reset_requests`: dictionary where requests for episode reset are collected (the world resets only if **all** active agents request reset)
`self._randomize_topology_requests`: dictionary where requests for topology randomization are collected (the world randomizes the topology only if **all** active agents request reset)
`self._agent_observations`: current observation per agent
`self._agent_starting_position`: starting position (with wildcards, see [configuration](../README.md#task-configuration)) per agent
`self._agent_states`: current GameState per agent 
`self._agent_last_action`: last Action per agent
`self._agent_statuses`: status of each agent. One of AgentStatus
`self._agent_rewards`: dictionary of final reward of each agent in the current episod. Only agent's which can't participate in the ongoing episode are listed.
`self._agent_trajectories`: complete trajectories for each agent in the ongoing episode


## Episode
The episode starts with sufficient amount of agents registering in the game. Each agent role has a maximum allowed number of steps defined in the task configuration. An episode ends if all agents reach the goal 
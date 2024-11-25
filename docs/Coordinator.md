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

1. `Actions queue` is a queue in which the agents submit their actions. It provides N:1 communication channel in which the coordinator receives the inputs.
2. `Answer queue` is a separeate queue **per agent** in which the results of the actions are send to the agent.
3.  
<img src="/docs/figures/message_passing_coordinator.jpg" alt="Message passing overview" width="30%"/>


## Main components of the coordinator
`self._actions_queue`: asycnio queue for agent -> aidojo_world communication
`self._answers_queue`: asycnio queue for aidojo_world -> agent communication
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
`self._reset_requests`: dictionary where requests for episode reset are collected (the world resets only if ALL agents request reset)
`self._agent_observations`: current observation per agent
`self._agent_starting_position`: starting position (with wildcards, see [configuration](../README.md#task-configuration)) per agent
`self._agent_states`: current GameState per agent 
`self._agent_statuses`: status of each agent. One of following options:
    - `playing`: agent is registered and can participate in current episode. Can't influence the episode termination
    - `playing_active`: agent is registered and can participate in current episode. It has `goal` and `max_steps` defined and can influence the termination of the episode
    - `goal_reached`: agent has reached it's goal in this episode. It can't perform any more actions until the interaction is resetted.
    - `blocked`: agent has been blocked. It can't perform any more actions until the interaction is resetted.
    - `max_steps`: agent has reached it's maximum allowed steps. It can't perform any more actions until the interaction is resetted.


`self._agent_rewards`: dictionary of final reward of each agent in the current episod. Only agent's which can't participate in the ongoing episode are listed.
`self._agent_trajectories`: complete trajectories for each agent in the ongoing episode

## The format of the messages to the agents is
    {
    "to_agent": address of client, 
    "status": {
        "#players": number of players,
        "running": true or false,
        "time": time in game,
        } ,
    "message": Generic text messages (optional),
    "state": (optional) {
        "observation": observation_object,
        "ended": if the game ended or not,
        "reason": reason for ending
    }
    }
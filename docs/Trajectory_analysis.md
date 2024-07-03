# Trajectories and Trajectory analusis
Trajectories capture interactions of agents in AI Dojo. They can be stored in a file for future analysis using the configuration option `save_trajectories: True` in `env` section of the task configuration file. Trajectories are stored in a JSON format, one JSON object per line using [jsonlines](https://jsonlines.readthedocs.io/en/latest/). 

### Example of the trajectory 
Below we show an example of a trajectory consisting only from 1 step. Starting from state *S1*, the agent takes action*A1* and moves to state *S2* and is awarded with immediate reward `r = -1`:
```json
{
    "agent_name": "ExampleAgent",
    "agent_role": "Attacker",
    "end_reason": "goal_reached",
    "trajectory":
        {
            "states":[
                "<DictRepresentation of State 1>",
                "<DictRepresentation of State 2>"
                ],
            "actions":[
                "<DictRepresentation of Action 1>"
                ],
            "rewards":[-1]
        }
}
```
`agent_name` and `agent_role` are provided by the agent upon registration in the game. `end_reason` identifies how did the episode end. Currently there are four options:
1. `goal_reached` - the attacker succcessfully reached the goal state and won the game
2. `detected` - the attacker was detected by the defender subsequently lost the game
3. `max_steps` - the agent used the max allowed amount of steps and the episode was terminated
4. `None` - the episode was interrupted before ending and the trajectory is incomplete.

## Trajectory analysis


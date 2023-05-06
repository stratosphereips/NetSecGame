# Network Security Game

As part of the AiDojo project, the Network Security Game is a python tool that builds a simulated local network using the Cyst simulator, and then trains reinforcement learning (RL) algorithms on how to better attack the network.

## How does it work
1. There is a pre-configured Cyst network environment in the file `scenarios/scenario_configuration.py`
2. There are some pre-implemented RL models in the files `q_agent.py`, `naive_q_learning.py`, and `double_q_learning.py`.
3. When you run the network_security_game.py tool, it loads the environment into Cyst and starts the training of the RL algorithms.
4. It outputs the results in xxx
5. You can plot the results with the tool `plot_generation.py`.


## Install and Dependencies
To run this code you need an environment and access to cyst code. However, the venv needs to be created for your own user

- If you don't have your environment

```bash
python -m venv ai-dojo-venv-<yourusername>
```

- The environment can be activated with

```bash
source ai-dojo-venv<yourusername>/bin/activate
```

- Install the requirements with 

```bash
python3 -m pip install -r requirements.txt
```

## Python Environment
Be careful of which python environment are you using. If using the venv here you may need to install pagackes as

    ai-dojo-venv-sebas/bin/pip install frozendict

## Run

The game is played and started by running the differnt agents.

To run the Q learning agent:

```bash
python q_agent.py --episodes 100
```


## Game Environment
The game has several components

File `network_security_game.py`

File `game_components.py`

File `scenarios/scenario_configuration.py`
Defines the
- Hosts
    - Features of the hosts, such as services, operating system, etc.
    - Features of the services running in the hsots, such as versions, etc.
    - Users 

hosts and their characteristics, the services they run, the users they have and their security levels, the data they have, and in the router/FW all the rules of which host can access what



is defined by the topogoly of the network and the rules, services and actions. This can be found in the files in folder `scenarios`.


The file `scenarios/scenario_configuration.py` corresponds to the final and large scenario.
The file `scenarios/smaller_scenario_configuration.py` corresponds to a small scenario for testing.
The file `scenarios/tiny_scenario_configuration.py` corresponds to a tiny scenario for testing.

### Verification of actions
The game environment now has a function called ```get_valid_actions(state)```, which returns the valid actions for a given state. This allows the agents to always know the actions that can be played and therefore there should not be any check in the game env about if the action is possible or not.


## Agents
Currently the implemented agents are:

- Q learning agent in `q_agent.py`
- Double Q learning agent in `double_q_agent.py`
- Naive Q learning agent in `naive_q_agent.py`
- Random agent in `random_agent.py`

## Assumptions:
* We work with close world assumntion - only entities defined exist in the simulation
* No actions have delete effect (attacker does not give up ownership of nodes, does not forget nodes and services and when data is transfered we assume its copied - present in both nodes)
* Scan Network action means scan COMPLETE given network
* Access to Data is represented as a pair of host_ip:path_to_data
* Find Data action finds all available data if successful
* Attacker has to know about data before exflitration is possible
* Attacker has to own or at least know about a host to try to Find Data
* Since the qtable is being constructed in real time when new states are returned (and not hold in memory completely), then the agents must have a way to estimate the value of new yet-unknown states. This is equivalent to have an initialized qtable upon start. Therefore our agents assume a state value of 0 if the state is new.

## Actions for the Attacker
| Action name          | Description                                                              | Preconditions                         | Effects                                          |
|----------------------|--------------------------------------------------------------------------|---------------------------------------|--------------------------------------------------|
| ScanNetwork          | Scans complete range of given network                                    | network + mask                        | extends 'known_hosts'                            |
| FindServices         | Scans given host for running services                                    | host IP                               | extends 'known_services' with host:service pairs |
| ExecuteCodeInService | Runs exploit in service to gain control                                  | host:service pair                     | extends 'controlled_hosts'                       |
| Find Data            | Runs code to discover data either in given service or in controlled host | host:service pair  OR controlled host | extends 'known_data' with host:data pairs        |
| Exfiltrate data      | Runds code to move data from host to host                                | host:data pair + known_host (target)  | extends 'known_data with "target:data" pair      |

## Usage
### Loading Topology
First step to initialize the environment is loading a YAML with topology. `env.read_topology(filename)` has to be run before any other methods to properly set up the environment!

#### Setting a goal conditions
Goal is defined by a dictionary with following keys:
* `known_networks` (list)
* `known_hosts` (list)
* `controlled_hosts` (list)
* `known_services` (dict of host:service pairs)
* `known_data` (dict of host:path pairs)

#### Defining starting position of the attacker
First GameState is created using a dictionary similar to the one used for goal conditions. At least ONE controlled host has to be given to the attacker. Any item in `controlled_hosts` is copied to `known_hosts` so there is no need to include these in both lists. `known_networks` extended with a list of ALL networks accessible from the `controlled_hosts`.

#### Defining Defender position
Defender postion is defined with a dictionary of `host`:`detector` pairs where detectors are located. Each `detector` is a nested dictionary with at least following keys:
* `scope` (either `global` if the detector is monitoring whole host or `sevice` if ONLY particular service is monitored)
TBD

### Initializing the Environment
After loading the topology, `env.initialize()` can be used to prepare the environment for interaction. `win_conditions`, `defender_positions` and `attacker_start_position` have to be given with `max_steps` being optional parameter for limitig the interaction length. `env.initialize()` returns the Observation which contains the GameState.

### Interaction with the Environment
Interaction with the environment is done using the `env.step(action:Action)` method which returns Observation with `next_state`, `reward`, `is_terminal`, `done` and `info` values. Once the terminal state or timeout is reached, no more interaction is possible untile `env.reset()`.

### Restarting the environment
`env.reset()` can be used for reseting the environment to the original state. That is to the state after `env.initialize()` was called. In other words, `env.current_state` is replace with `attacker_start_position` and `step_counter` is set to zero.



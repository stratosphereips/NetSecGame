# NetSecGame
[![Python Checks](https://github.com/stratosphereips/game-states-maker/actions/workflows/python-checks.yml/badge.svg)](https://github.com/stratosphereips/game-states-maker/actions/workflows/python-checks.yml)
[![Autotag](https://github.com/stratosphereips/game-states-maker/actions/workflows/autotag.yml/badge.svg)](https://github.com/stratosphereips/game-states-maker/actions/workflows/autotag.yml)

The NetSecGame (Network Security Game) is a framework of reinceforcement learning environment and agents to train and evalate network security attacks and defenses. It builds a simulated local network using the [CYST](https://pypi.org/project/cyst/) network simulator, adds many conditions on the environment and can train reinforcement learning (RL) algorithms on how to better attack and defend the network.


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

- If you use conda use
```bash
conda create --name aidojo python==3.10
conda activate aidojo
python3 -m pip install -r requirements.txt
```

## Starting the environment
The environment should be created by an agent upon starting. The properties of the environment can be defined in a YAML file.
When created, the environment:
1. reads the configuration file
2. loads the network configuraion from the config file
3. reads the defender type from the configuraion
4. creates starting position and goal position following the config file

## Run the agents

The game is played and started by running the differnt agents.

To run the Q learning agent with default configuration for 100 episodes:

```bash
python agents/q_learning/q_agent.py --episodes 100
```

## Components of the NetSecGame Environment
The NetSecGame environment has several components

- File `env/network_security_game.py`. Implements the game environment
- File `env/game_components.py`. Implements a library with objects and functions that help the game env
- Files in the `env/scenarios` folder, such as `env/scenarios/scenario_configuration.py`. Implements the configuration of hosts, data, services, and connnections in the network game. It is taken from Cyst.
- Files such as `agent/q_learning/q_agent.py` that implement the RL agents.

The default configuration is defined in two places:
1. The network environment 

    It is defined in the files in the `env/scenarios` folder.

2. The configuration of the run

    This is defined in a configuration file in the directory on the agent. 

## Tensorboard logs

The logs for tensorboard are stored for all agents in `agents/tensorboard-logs/`.


## Testing the environment

It is advised after every change you test if the env is running correctly by doing

```bash
tests/run_all_tests.sh
```

This will load and run the unit tests in the `tests` folder.


## Definition of the network topology
The network topology and rules are defined using a Cyst simulator configuration. Cyst defines a complex network configuration, and this game does not use all Cyst features for now. The important ones for us are:

- Server hosts (are a NodeConf in CYST)
    - Interfaces, each with one IP address
    - Users that can login to the host
    - Active and passive services
    - Data in the server
    - To which network is connected
- Client host (are a Node in CYST)
    - Interfaces, each with one IP address
    - To which network is connected
    - Active and passive services if any
    - Data in the client
- Router (are a RouterConf in CYST)
    - Interfaces, each with one IP address
    - Networks
    - Allowed connections between hosts
- Internet host (as external router) (are a Node in RouterConf)
    - Interfaces, each with one IP address
    - Which host can connect

Very important is that we made an addition to the NodeConfig objects in our Cyst configuration to include the property 'note' with the text 'can_start_attacker'. Meaning that the game env will take these host as candidates for the random start position.


## Agents Implemented
Currently the implemented agents are:

- Q learning agent in `agents/q_learning/`
- Double Q learning agent in `agents/double_q_learning/`
- Naive Q learning agent in `agents/naive_q_learning/`
- Random agent in `agents/random/`
- Interactive agent in `agents/interactive/`
- LLM agent in `agents/llm/`
- LLM QA agent in `agents/llm_qa/`
- GNN Reinforce agent in `agents/gnn_reinforce/`

## Assumptions of the NetSecGame
1. We work with the closed-world assumption. Only the defined entities exist in the simulation.
2. No actions have a "delete" effect (the attacker does not give up ownership of nodes, does not forget nodes or services, and when data is transfered we assume its copied and therefore present in both nodes).
3. If the attacker does a successful action in the same step that the defender successfully detects the action, the priority goes to the defender. The reward is a penalty and the game ends.
4. If you want to exfiltrate data to an external IP, that IP must be in the 'controlled_hosts' part of the configuration. Or the agent will not controll that IP.

### Assumption for actions
1. When playing `ExploitService` action, it is expected that the agent has discovered this service before (by playing `FindServices` in the `target_host` prior to this action)
2. The `Find Data` action finds all the available data in the host if successful.

## Actions for the Attacker
| Action name          | Description                                                              | Parameters                         | Effects                                          |
|----------------------|--------------------------------------------------------------------------|---------------------------------------|--------------------------------------------------|
| Scan Network          | Scans the given network for active hosts | network, mask                        | extends 'known_hosts'                            |
| Find Services         | Scans given host for running services                                    | target IP                               | extends 'known_services' with host:service pairs |
| Exploit Service | Runs exploit in service to gain control                                  | target IP, target service                     | extends 'controlled_hosts'                       |
| Find Data            | Runs code to discover data either in given service or in controlled host | target IP, target service | extends 'known_data' with host:data pairs        |
| Exfiltrate data      | Runds code to move data from host to host                                | source IP, data, target IP  | extends 'known_data with "target:data" pair      |

### Conditions on the actions
For each action to succed there are some conditions that must be fulfilled:
- Scan Network: The target network should be in the list of known networks by the agent.
- Find Services: The target IP should be in the list of known hosts.
- Exploit Service: The target IP should be in the list of known hosts. The service should be in the list of known services.
- Find Data: The target IP should be in the list of known hosts and in the list of controlled hosts. The service should be in the list of known services. 
- Exfiltrate Data: The source IP should be in the list of known hosts and in the list of controlled hosts. The target IP should be in the list of known hosts and in the list of controlled hosts. The data should be in the list of known data. 

In particular there are some actions that are possible, such as Scan a network that you don't know.


## Configuration of the game and agents
All the configuration of the environment and agents is done from the configuration file that is on the directory of the agents. For example, for the agent q_learning it is stored in the file `agents/q_learning/netsecenv-task.yaml`.

The configuration is a yaml file and allows for the setting of 
- random seeds (fixed or `random`)
- the start position of the agent (state) in `start_position`:
    - each component of the state can be either fixed (e.g. 'known_data'={IP(X.X.X.X):\[Data(owner, data_id)\]})
    - or randomized (e.g. 'known_data'={IP(X.X.X.X):\['random'\]})

- the description of the goal state in `goal`:
    - each component of the state can be either fixed (e.g. 'known_data'={IP(X.X.X.X):\[Data(owner, data_id)\]})
    - or randomized (e.g. 'known_data'={IP(X.X.X.X):\['random'\]})
- in case there are any `random` fields, if the random assignment should be done at the beginning of *EVERY* episode `randomize_goal_every_episode:True`
- the scenario with the topology (`scenario`)
- the max steps (`max_steps`)
- if all interaction (serialized replay_buffer) should be stored (`store_replay_buffer`)
- if all network and ip addresses should be randomized every episode while keeping the same topology defined in `scenario`(`use_dynamic_addresses`)
- probability of detection of each action
- probability of success of each action
- type of defender (selection from):
    - `NoDefender` (default)
    - `StochasticDefender`
    - `StochasticWithThreshold`
(see Defenders for details)

## Actions for the defender
In this version of the game the defender does not have actions and it is not an agent. It is an omnipresent entity in the network that can detect actions from the attacker. This follows the logic that in real computer networks the admins have tools that consume logs from all computers at the same time and they can detect actions from a central position (such as a SIEM). The defender has, however, probabilities to detect or not each action, which are defined in the file `game_components.py`.



# Code adaptation for new configurations
The code can be adapted to new configurations of games and for new agents.

### Verification of actions
The game environment has a function called ```get_valid_actions(state)```, which returns the valid actions for a given state. This allows the agents to always know the actions that can be played and therefore there should not be any check in the game env about if the action is possible or not.


## State of the game
The state of the game is an object with the following parts:
* `known_networks` (set of networks known to the attacker)
* `known_hosts` (set of hosts known to the attacker)
* `controlled_hosts` (set of hosts controlled by the attacker)
* `known_services` (dict of host:service pairs. A service is a port)
* `known_data` (dict of host:path pairs. path is where the data was found)

An observation is the object received by an agent that has its view of the state, the reward, if the game ended and information about the observation.

## Defining starting position of the attacker
The initial network configuration must assign at least **one** controlled host to the attacker in the network. Any item in `controlled_hosts` is copied to `known_hosts` so there is no need to include these in both sets. `known_networks` is also extended with a set of **all** networks accessible from the `controlled_hosts`.

## Defining defender position
The defender can be present in the network or not. In case you defined in the configuration of the game that the defender is present (see below), then the detection probabilities of each actions are taken into account. If the defender is not present, then there is no detection and the game can only end in two ways: timeout or the goal of the attacker was acchieved.

## Initializing the Environment
Each agent must initialize the game environment with options. The function is:

```python
state = env.initialize(win_conditions=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps)
```

The `goal` is defined as a dictionary of conditions that must be met for the attacker to win. Example:

```python
goal = {
    "known_networks":set(),
    "known_hosts":set(),
    "controlled_hosts":set(),
    "known_services":{},
    "known_data":{IP("213.47.23.195"):{Data("User1", "DataFromServer1")}}
}
```
Empty set() mean that any value is ok. So it doesn't matter which networks are known, or hosts known or host controlled, or known servi ces. Only that the known data "DataFromServer1" is *successfully* exfiltrated to IP 213.47.23.195 using user "User1".

The start position of the attacker is defined in a dictionary. For example:

```python
attacker_start = {
    "known_networks":set(),
    "known_hosts":set(),
    "controlled_hosts":{IP("213.47.23.195"), IP("192.168.2.2")},
    "known_services":{},
    "known_data":{}
}
```
An empty set() means no values. The set of `controlled_hosts` must be filled with 1. the external command and control host for exfiltration and 2. if the agent starts from a deterministic host, then add it here. The IP where exfiltration must happen must be controlled by the attacker or otherwise it will not succeed. To force the starting position of the attacker to be random in the network, just put random_start=True in the environment initialization. When the game starts, the known networks and known hosts of the attacker are updated to include the controlled hosts and the network where the controlled hosts is.

The `defender_position` parameter in the initialization of the env can only be for now `True` or `False`.

## Interaction with the Environment
Each agent can interact with the environment using the `env.step(action:Action)` method which returns an Observation with `next_state`, `reward`, `is_terminal`, `done` and `info` values. Once the terminal state or timeout is reached, no more interaction is possible untile `env.reset()`.

## Restarting the environment
`env.reset()` can be used for reseting the environment to the original state. That is to the state after `env.initialize()` was called. In other words, `env.current_state` is replaced with `attacker_start_position` and `step_counter` is set to zero.
The environment is also resetted after initialization.


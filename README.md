# NetSecGame

The NetSecGame (Network Security Game) is a framework of reinceforcement learning environment and agents to train and evalate network security attacks and defenses. It builds a simulated local network using the Cyst network simulator, adds many conditions on the environment and can train reinforcement learning (RL) algorithms on how to better attack and defend the network.


## How does it work
You run an agent python file, which:
- defines the attacker's goal, position of attacker and presence of defender.
- initializes the game env 
    - the env loads the network configuration from configuration files.
- receives an observation and reward from the envirionment
- decides which action to do based on its logic
- trains and evaluates every some episodes
- tests at the end for some episodes
- saves the policy to disk
- creates a log file
- creates tensorboard files

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

    This is defined inside each agent by a set of dictionaries that define if the defender is present, if the start position of the agent is random, etc.


## Testing the environment

It is advised after every change you test if the env is running correctly by doing

```bash
tests/run_all_tests.sh
```

This will load and run the unit tests in the `tests` folder.




## Definition of the network topology
The network topology and rules are defined using a Cyst simulator configuration. Cyst defines a complex network configuration, and this game does not use all Cyst features for now. The important ones for us are:

- Server hosts (are a Node in Cyst)
    - Interfaces, each with one IP address
    - Users that can login to the host
    - Active and passive services
    - Data in the server
    - To which network is connected
- Client host (are a Node in Cyst)
    - Interfaces, each with one IP address
    - To which network is connected
    - Active and passive services if any
    - Data in the client
- Router (are a Node in RouterConf)
    - Interfaces, each with one IP address
    - Networks
    - Allowed connections between hosts
- Internet host (as external router) (are a Node in RouterConf)
    - Interfaces, each with one IP address
    - Which host can connect


Very important is that we made an addition to the NodeConfig objects in our Cyst configuration to include the property 'note' with the text 'can_start_attacker'. Meaning that the game env will take these host as candidates for the random start position.


## Agents Implemented
Currently the implemented agents are:

- Q learning agent in `q_agent.py`
- Double Q learning agent in `double_q_agent.py`
- Naive Q learning agent in `naive_q_agent.py`
- Random agent in `random_agent.py`

## Assumptions of the NetSecGame
1. We work with the closed-world assumption. Only the defined entities exist in the simulation.
2. No actions have a "delete" effect (the attacker does not give up ownership of nodes, does not forget nodes or services, and when data is transfered we assume its copied and therefore present in both nodes).
4. The `Find Data` action finds all the available data in the host if successful.
5. If the attacker does a successful action in the same step that the defender successfully detects the action, the priority goes to the defender. The reward is a penalty and the game ends.
6. If you want to exfiltrate data to an external IP, that IP must be in the 'controlled_hosts' part of the configuration. Or the agent will not controll that IP.

## Actions for the Attacker
| Action name          | Description                                                              | Preconditions                         | Effects                                          |
|----------------------|--------------------------------------------------------------------------|---------------------------------------|--------------------------------------------------|
| ScanNetwork          | Scans the given network for active hosts | network + mask                        | extends 'known_hosts'                            |
| FindServices         | Scans given host for running services                                    | host IP                               | extends 'known_services' with host:service pairs |
| ExecuteCodeInService | Runs exploit in service to gain control                                  | host:service pair                     | extends 'controlled_hosts'                       |
| Find Data            | Runs code to discover data either in given service or in controlled host | host:service pair  OR controlled host | extends 'known_data' with host:data pairs        |
| Exfiltrate data      | Runds code to move data from host to host                                | host:data pair + known_host (target)  | extends 'known_data with "target:data" pair      |

## Actions for the defender
In this version of the game the defender does not have actions and it is not an agent. It is an omnipresent entity in the network that can detect actions from the attacker. This follows the logic that in real computer networks the admins have tools that consume logs from all computers at the same time and they can detect actions from a central position (such as a SIEM). The defender has, however, probabilities to detect or not each action, which are defined in the file `game_components.py`.



# Code adaptation for new configurations
The code can be adapted to new configurations of games and for new agents.

### Verification of actions
The game environment has a function called ```get_valid_actions(state)```, which returns the valid actions for a given state. This allows the agents to always know the actions that can be played and therefore there should not be any check in the game env about if the action is possible or not.


## State of the game
The state of the game is an object with the following parts:
* `known_networks` (list of networks known to the attacker)
* `known_hosts` (list of hosts known to the attacker)
* `controlled_hosts` (list of hosts controlled by the attacker)
* `known_services` (dict of host:service pairs. A service is a port)
* `known_data` (dict of host:path pairs. path is where data was found)

An observation is the object received by an agent that has its view of the state, the reward, if the game ended and information about the observation.

## Defining starting position of the attacker
The initial network configuration must assign at least **one** controlled host to the attacker in the network. Any item in `controlled_hosts` is copied to `known_hosts` so there is no need to include these in both lists. `known_networks` is also extended with a list of **all** networks accessible from the `controlled_hosts`.

## Defining defender position
The defender can be present in the network or not. In case you defined in the configuration of the game that the defender is present (see below), then the detection probabilities of each actions are taken into account. If the defender is not present, then there is no detection and the game can only end in two ways: timeout or the goal of the attacker was acchieved.

## Initializing the Environment
Each agent must initialize the game environment with options. The function is:

```python
state = env.initialize(win_conditons=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps)
```

The `goal` is defined as a dictionary of conditions that must be met for the attacker to win. Example:

```python
goal = {
    "known_networks":set(),
    "known_hosts":set(),
    "controlled_hosts":set(),
    "known_services":{},
    "known_data":{"213.47.23.195":{("User1", "DataFromServer1")}}
       }
```
Empty set() mean that any value is ok. So it doesn't matter which networks are known, or hosts known or host controlled, or known servi ces. Only that the known data "DataFromServer1" is *successfully* exfiltrated to IP 213.47.23.195 using user "User1".

The start position of the attacker is defined in a dictionary. For example:

```python
attacker_start = {
    "known_networks":set(),
    "known_hosts":set(),
    "controlled_hosts":{"213.47.23.195","192.168.2.2"},
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


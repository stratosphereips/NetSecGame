# NetSecGame
[![Python Checks](https://github.com/stratosphereips/game-states-maker/actions/workflows/python-checks.yml/badge.svg)](https://github.com/stratosphereips/game-states-maker/actions/workflows/python-checks.yml)
[![Autotag](https://github.com/stratosphereips/game-states-maker/actions/workflows/autotag.yml/badge.svg)](https://github.com/stratosphereips/game-states-maker/actions/workflows/autotag.yml)

The NetSecGame (Network Security Game) is a framework for training and evaluation of AI agents in the network security tasks (both offensive and defensive). It builds a simulated local network using the [CYST](https://pypi.org/project/cyst/) network simulator, adds many conditions on the environment and can train reinforcement learning (RL) algorithms on how to better attack and defend the network. Examples of implemented agents can be seen in the submodule [NetSecGameAgents](https://github.com/stratosphereips/NetSecGameAgents/tree/main).

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

## Architecture
The architecture of the environment can be seen [here](docs/Architecture.md).

## Components of the NetSecGame Environment
The NetSecGame environment has several components in the following files:

- File `env/network_security_game.py` implements the game environment
- File `env/game_components.py` implements a library with objects used in the environment. See [detailed explanation](docs/Components.md) of the game components.
- File `utils/utils.py` is a collection of utils functions which the agents can use
- Files in the `env/scenarios` folder, such as `env/scenarios/scenario_configuration.py`. Implements the network game's configuration of hosts, data, services, and connections. It is taken from CYST.
The [scenarios](#definition-of-the-network-topology) define the **topology** of a network (number of hosts, connections, networks, services, data, users, firewall rules, etc.) while the [task-configuration](#task-configuration) is to be used for definition of the exact task for the agent in one of the scenarios (with fix topology).
- Agents compatible with the NetSecGame are located in a separate repository [NetSecGameAgents](https://github.com/stratosphereips/NetSecGameAgents/tree/main)

### Assumptions of the NetSecGame
1. NetSecGame works with the closed-world assumption. Only the defined entities exist in the simulation.
2. If the attacker does a successful action in the same step that the defender successfully detects the action, the priority goes to the defender. The reward is a penalty, and the game ends.
(From commit d6d4ac9, July 18th, 2024, the new action BlockIP removes controlled hosts from the state of others. So the state can get smaller)

- The action FindServices finds the new services in a host. If in a subsequent call to FindServices there are less services, they completely replace the list of previous services found. That is, each list of services is the final one, and no memory of previous open services is retained.

### Assumption and Conditions for Actions
1. When playing the `ExploitService` action, it is expected that the agent has discovered this service before (by playing `FindServices` in the `target_host` before this action)
2. The `Find Data` action finds all the available data in the host if successful.
3. The `Find Data` action requires ownership of the target host.
4. Playing `ExfiltrateData` requires controlling **BOTH** source and target hosts
5. Playing `Find Services` can be used to discover hosts (if those have any active services)
6. Parameters of `ScanNetwork` and `FindServices` can be chosen arbitrarily (they don't have to be listed in `known_newtworks`/`known_hosts`)
7. The `BlockIP` action needs its three parameters (Source host, Target host, and Blocked host) to be in the controlled list of the Agent. 

### Actions for the defender
The defender does have the action to block an IP address in a target host. 


> [!NOTE]  
> The global defender, available in the previous environment versions, will not be supported in the future. To enable backward compatibility, the global defender functionality can be enabled by adding `use_global_defender: True` to the configuration YAML file in the `env` section. This option is disabled by default.

The actions are:
- BlockIP(). That takes as parameters:
  - "target_host": IP object where the block will be applied.
  - "source_host": IP object from which this action is executed.
  - "blocked_host": IP object to block in ANY direction as seen in the target_host.


### Starting the game
The environment should be created before starting the agents. The properties of the environment can be defined in a YAML file. The game server can be started by running:
```python3 coordinator.py```

When created, the environment:
1. reads the configuration file
2. loads the network configuration from the config file
3. reads the defender type from the configuration
4. creates starting position and goal position following the config file
5. starts the game server in a specified address and port

### Interaction with the Environment
When the game server is created, [agents](https://github.com/stratosphereips/NetSecGameAgents/tree/main) connect to it and interact with the environment. In every step of the interaction, agents submits an [Action](./docs/Components.md#actions) and receives [Observation](./docs/Components.md#observations) with `next_state`, `reward`, `is_terminal`, `end`, and `info` values. Once the terminal state or timeout is reached, no more interaction is possible until the agent asks for a game reset. Each agent should extend the `BaseAgent` class in [agents](https://github.com/stratosphereips/NetSecGameAgents/tree/main).


## Configuration
The NetSecEnv is highly configurable in terms of the properties of the world, tasks, and agent interaction. Modification of the world is done in the YAML configuration file in two main areas:
1. Environment (`env` section) controls the properties of the world (taxonomy of networks, maximum allowed steps per episode, probabilities of action success, etc.)
2. Task configuration defines the agents' properties (starting position, goal)

### Environment configuration
The environment part defines the properties of the environment for the task (see the example below). In particular:
- `random_seed` - sets seed for any random processes in the environment
- `scenario` - sets the scenario (network topology) used in the task (currently, `scenario1_tiny`, `scenario1_small`, and `scenario1` are available)
- `max_steps` - sets the maximum number of steps an agent can make before an episode is terminated
- `store_replay_buffer` - if `True`, interaction of the agents is serialized and stored in a file
- `use_dynamic_addresses` - if `True`, the network and IP addresses defined in `scenario` are randomly changed at the beginning of **EVERY** episode (the network topology is kept as defined in the `scenario`. Relations between networks are kept, IPs inside networks are chosen at random based on the network IP and mask)
- `  use_firewall` - if `True` firewall rules defined in `scenario` are used when executing actions. When `False`, the firewall is ignored, and all connections are allowed (Default)
- `goal_reward` - sets reward which agent gets when it reaches the goal (default 100)
- `detection_reward` - sets the reward that which agent gets when it is detected (default -50)
- `step_reward` - sets reward which agent gets for every step taken (default -1)
- `actions` - defines the probability of success for every ActionType

```YAML
env:
  random_seed: 42
  scenario: 'scenario1'
  max_steps: 15
  use_dynamic_addresses: False
  use_firewall: True
  goal_reward: 100
  detection_reward: -5
  step_reward: -1
  actions:
    scan_network:
      prob_success: 0.9
    find_services:
      prob_success: 0.9
    exploit_services:
      prob_success: 0.7
    find_data:
      prob_success: 0.8
    exfiltrate_data:
      prob_success: 0.8
```

## Task configuration
The task configuration part (section `coordinator[agents]`) defines the starting and goal position of the attacker and the type of defender that is used.

### Attacker configuration (`attackers`)
Configuration of the attacking agents. Consists of two parts:
1. Goal definition (`goal`) which describes the `GameState` properties that must be fulfilled to award `goal_reward` to the attacker:
    - `known_networks:`(set)
    - `known_hosts`(set)
    - `controlled_hosts`(set)
    - `known_services`(dict)
    - `known_data`(dict)

     Each of the parts can be empty (not part of the goal, exactly defined (e.g., `known_networks: [192.168.1.0/24, 192.168.3.0/24]`) or include the keyword `random` (`controlled_hosts: [213.47.23.195, random]`, `known_data: {213.47.23.195: [random]}`.
    Additionally,  if `random` keyword is used in the goal definition, 
    `randomize_goal_every_episode`. If set to `True`, each keyword `random` is replaced with a randomly selected, valid option at the beginning of **EVERY** episode. If set to `False`, randomization is performed only **once** when the environment is 
2. Definition of starting position (`start_position`), which describes the `GameState` in which the attacker starts. It consists of:
    - `known_networks:`(set)
    - `known_hosts`(set)
    - `controlled_hosts`(set)
    - `known_services`(dict)
    - `known_data`(dict)

    The initial network configuration must assign at least **one** controlled host to the attacker in the network. Any item in `controlled_hosts` is copied to `known_hosts`, so there is no need to include these in both sets. `known_networks` is also extended with a set of **all** networks accessible from the `controlled_hosts`

Example attacker configuration:
```YAML
agents:
  Attacker:
    goal:
      randomize_goal_every_episode: False
      known_networks: []
      known_hosts: []
      controlled_hosts: []
      known_services: {192.168.1.3: [Local system, lanman server, 10.0.19041, False], 192.168.1.4: [Other system, SMB server, 21.2.39421, False]}
      known_data: {213.47.23.195: ["random"]}
      known_blocks: {'all_routers': 'all_attackers'}

    start_position:
      known_networks: []
      known_hosts: []
      # The attacker must always at least control the CC if the goal is to exfiltrate there
      # Example of fixing the starting point of the agent in a local host
      controlled_hosts: [213.47.23.195, random]
      # Services are defined as a target host where the service must be, and then a description in the form 'name, type, version, is_local'
      known_services: {}
      known_data: {}
      known_blocks: {}
```
### Defender configuration (`defenders`)
Currently, the defender **is** a separate agent.

If you want a defender in the game, you must connect a defender agent. For playing without a defender, leave the section empty.

Example of defender configuration:
```YAML
   Defender:
      goal:
        description: "Block all attackers"
        is_any_part_of_goal_random: False
        known_networks: []
        known_hosts: []
        controlled_hosts: []
        known_services: {}
        known_data: {}
        known_blocks: {'any_routers': 'all_attackers_controlled_hosts'}

      start_position:
        known_networks: [all_local]
        known_hosts: [all_local]
        controlled_hosts: [all_local]
        known_services: {all_local}
        known_data: {all_local}
        blocked_ips: {}
        known_blocks: {}
```

As in other agents, the description is only a text for the agent, so it can know what is supposed to do to win. In this example, the goal of the defender is determined by a state where the known blocks can be applied in any router's firewall and must include all the controlled hosts of all the attackers. These are `magic` words that will push the coordinator to check these positions without revealing them to the defender.


## Definition of the network topology
The network topology and rules are defined using a [CYST](https://pypi.org/project/cyst/) simulator configuration. Cyst defines a complex network configuration, and this environment does not use all Cyst features for now. CYST components currently used are:

- Server hosts (are a NodeConf in CYST)
    - Interfaces, each with one IP address
    - Users that can log in to the host
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
- Internet host (as an external router) (are a Node in RouterConf)
    - Interfaces, each with one IP address
    - Which host can connect
- Exploits
    - which service is the exploit linked to

### Scenarios
In the current state, we support a single scenario: Data exfiltration to a remote C&C server.

#### Data exfiltration to a remote C&C
For the data exfiltration we support 3 variants. The full scenario contains 5 clients (where the attacker can start) and 5 servers where the data that is supposed to be exfiltrated can be located. *scenario1_small* is a variant with a single client (the attacker always starts there) and all 5 servers. *scenario1_tiny* contains only a single server with data. The tiny scenario is trivial and intended only for debugging purposes.
<table>
  <tr><th>Scenario 1</th><th>Scenario 1 - small</th><th>Scenario 1 -tiny</th></tr>
  <tr><td><img src="readme_images/scenario_1.png" alt="Scenario 1 - Data exfiltration" width="300"></td><td><img src="readme_images/scenario 1_small.png" alt="Scenario 1 - small" width="300"</td><td><img src="readme_images/scenario_1_tiny.png" alt="Scenario 1 - tiny" width="300"></td></tr>
</table>

## Trajectory storing and analysis
The trajectory is a sequence of GameStates, Actions, and rewards in one run of a game. It contains the complete information of the actions played by the agent, the rewards observed and their effect on the state of the environment. Trajectory visualization and analysis tools are described in [Trajectory analysis tools](./docs/Trajectory_analysis.md)

Trajectories performed by the agents can be stored in a file using the following configuration:
```YAML
env:
  save_trajectories: True
```
> [!CAUTION]
> Trajectory files can grow very fast. It is recommended to use this feature on evaluation/testing runs only. By default, this feature is not enabled.
## Testing the environment

It is advised after every change you test if the env is running correctly by doing

```bash
tests/run_all_tests.sh
```
This will load and run the unit tests in the `tests` folder. 

## Code adaptation for new configurations
The code can be adapted to new configurations of games and for new agents. See [Agent repository](https://github.com/stratosphereips/NetSecGameAgents/tree/main) for more details.

## About us
This code was developed at the [Stratosphere Laboratory at the Czech Technical University in Prague](https://www.stratosphereips.org/).

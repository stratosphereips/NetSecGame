# Network Security Game
[![Python Checks](https://github.com/stratosphereips/game-states-maker/actions/workflows/python-checks.yml/badge.svg)](https://github.com/stratosphereips/game-states-maker/actions/workflows/python-checks.yml)
[![Autotag](https://github.com/stratosphereips/game-states-maker/actions/workflows/autotag.yml/badge.svg)](https://github.com/stratosphereips/game-states-maker/actions/workflows/autotag.yml)
[![Docs](https://github.com/stratosphereips/game-states-maker/actions/workflows/deploy-docs.yml/badge.svg)](https://stratosphereips.github.io/NetSecGame/)
[![Docker Publish](https://github.com/stratosphereips/game-states-maker/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/stratosphereips/game-states-maker/actions/workflows/docker-publish.yml)


The NetSecGame (Network Security Game) is a framework for training and evaluation of AI agents in network security tasks (both offensive and defensive). It is built with [CYST](https://pypi.org/project/cyst/) network simulator and enables rapid development and testing of AI agents in highly configurable scenarios. Examples of implemented agents can be seen in the submodule [NetSecGameAgents](https://github.com/stratosphereips/NetSecGameAgents/tree/main).

## Installation Guide
It is recommended to run the environment in the Docker container. The up-to-date image can be found in [Dockerhub](https://hub.docker.com/r/stratosphereips/netsecgame).
```bash
docker pull stratosphereips/netsecgame
```
#### Building the image locally
Optionally, you can build the image locally with:
```bash 
docker build -t netsecgame:local .
```

### Installing from source
In case you need to modify the envirment and run directly, we recommed to insall it in a virtual environemnt (Python vevn or Conda):
#### Python venv
1. Create new virtual environment
```bash
python -m venv <venv-name>
```
2. Activate newly created venv
```bash
source <venv-name>/bin/activate
```

#### Conda
1.  Create new conda environment
```bash
conda create --name aidojo python==3.12
```
2. Activate newly created conda env
```bash
conda activate aidojo
```

### After preparing virutual environment, install using pip:
```bash
pip install -e .
```

## Quick Start
A task configuration YAML file is required for starting the NetSecGame environment.  For the first step, the example task configuration is recommended:

### Example Configuration
```yaml
# Example of the task configuration for NetSecGame
# The objective of the Attacker in this task is to locate specific data
# and exfiltrate it to a remote C&C server.
# The scenario starts AFTER the initial breach of the local network
# (the attacker controls 1 local device + the remote C&C server).

coordinator: 
  agents: 
    Attacker: # Configuration of 'Attacker' agents
      max_steps: 25 # timout set for the role `Attacker`
      goal: # Definition of the goal state
        description: "Exfiltrate data from Samba server to remote C&C server."
        is_any_part_of_goal_random: True
        known_networks: []
        known_hosts: []
        controlled_hosts: []
        known_services: {}
        known_data: {213.47.23.195: [[User1,DataFromServer1]]} # winning condition
        known_blocks: {}
      start_position: # Definition of the starting state (keywords "random" and "all" can be used)
        known_networks: []
        known_hosts: []
        controlled_hosts: [213.47.23.195, random] # keyword 'random' will be replaced by randomly selected IP during initilization
        known_services: {}
        known_data: {}
        known_blocks: {}

    Defender:
      goal:
        description: "Block all attackers"
        is_any_part_of_goal_random: False
        known_networks: []
        known_hosts: []
        controlled_hosts: []
        known_services: {}
        known_data: {}
        known_blocks: {213.47.23.195: 'all_attackers'}

      start_position:
        known_networks: []
        known_hosts: []
        controlled_hosts: []
        known_services: {}
        known_data: {}
        blocked_ips: {}
        known_blocks: {}

env: # Environment configuraion
  scenario: 'two_networks_tiny' # use the smallest topology for this example
  use_global_defender: False # Do not use global SIEM Defender
  use_dynamic_addresses: False # Do not randomize IP addresses
  use_firewall: True # Use firewall
  save_trajectories: False # Do not store trajectories
  required_players: 1 # Minimal amount of agents requiered to start the game
  rewards: # Configurable reward function
    success: 100
    step: -1
    fail: -10
    false_positive: -5 
```
For detailed configuration instructions, please refer to the [Configuration Documentation](https://stratosphereips.github.io/NetSecGame/configuration/).


### Starting the NetSecGame
With the configuration ready the environment can be started in selected port
#### In Docker container
```bash
docker run -d --rm --name nsg-server\
  -v $(pwd)/examples/example_task_configuration.yaml:/netsecgame/netsecenv_conf.yaml \
  -v $(pwd)/logs:/netsecgame/logs \
  -p 9000:9000 stratosphereips/netsecgame
  --debug_level="INFO"
```
`--name nsg-server`: specifies the name of the container

`-v <your-configuration-yaml>:/netsecgame/netsecenv_conf.yaml` : Mapping of the configuration file

`-v $(pwd)/logs:/netsecgame/logs`: Mapping of the folder where logs are stored

` -p <selected-port>:9000`: Mapping of the port in which the server runs

`--debug_level` is an optional parameter to control the logging level `--debug_level=["DEBUG", "INFO", "WARNING", "CRITICAL"]` (defaul=`"INFO"`):
##### Running on Windows (with Docker desktop)
When running on Windows, Docker desktop is required.
```cmd
docker run -d --rm --name netsecgame-server ^
  -p 9000:9000 ^
  -v "%cd%\examples\example_task_configuration.yaml:/netsecgame/netsecenv_conf.yaml" ^
  -v "%cd%\logs:/netsecgame/logs" ^
  stratosphereips/netsecgame:latest
  --debug_level="INFO"
```

#### Locally
The environment can be started locally with from the root folder of the repository with following command:
```bash
python3 -m netsecgame.game.worlds.NetSecGame \
  --task_config=./examples/example_task_configuration.yaml \
  --game_port=9000
  --debug_level="INFO"
```
Upon which the game server is created on `localhost:9000` to which the agents can connect to interact in the NetSecGame.

## Documentation
You can find user documentation at [https://stratosphereips.github.io/NetSecGame/](https://stratosphereips.github.io/NetSecGame/)

### Components of the NetSecGame Environment
The architecture of the environment can be seen [here](docs/Architecture.md).
The NetSecGame environment has several components in the following files:
```
├── netsecgame/
|	├── agents/
|		├── base_agent.py # Basic agent class. Defines the API for agent-server communication
|	├── game/
|		├── scenarios/
|		    ├── tiny_scenario_configuration.py
|		    ├── smaller_scenario_configuration.py
|		    ├── scenario_configuration.py
|		    ├── three_net_scenario.py
|		├── worlds/
|   		├── NetSecGame.py # (NSG) basic simulation 
|   		├── RealWorldNetSecGame.py # Extension of `NSG` - runs actions in the *network of the host computer*
|   		├── CYSTCoordinator.py # Extension of `NSG` - runs simulation in CYST engine.
|   		├── WhiteBoxNetSecGame.py # Extension of `NSG` - provides agents with full list of actions upon registration.
|		├── agent_server.py # Agent server implementation
|		├── config_parser.py # NSG task configuration parser
|		├── configuration_manager.py # Helper tool to collect and parse query configuration of the game.
|		├── coordinator.py # Core game server. Not to be run as stand-alone world (see worlds/)
|	    ├── global_defender.py # Stochastic (non-agentic defender)
|	├── game_components.py # contains basic building blocks of the environment
|	├── utils/
|		├── utils.py
|		├── log_parser.py
|		├── gamaplay_graphs.py
|		├── actions_parser.py

```
#### Directory Details
- `coordinator.py`: Basic coordinator class. Handles agent communication and coordination. **Does not implement dynamics of the world** and must be extended (see examples in `worlds/`).
- `game_components.py`: Implements a library with objects used in the environment. See [detailed explanation](./docs/game_components.md) of the game components.
- `global_defender.py`: Implements a global (omnipresent) defender that can be used to stop agents. Simulation of SIEM.

##### **`worlds/`**
Modules for different world configurations:
- `NetSecGame.py`: Coordinator for the Network Security Game.
- `RealWorldNetSecGame.py`: Real-world NSG coordinator (actions are executed in the *real network*).
- `CYSTCoordinator.py`: Coordinator for CYST-based simulations (requires CYST running).

##### **`scenarios/`**
Predefined scenario configurations:
- `tiny_scenario_configuration.py`: A minimal example scenario.
- `smaller_scenario_configuration.py`: A compact scenario configuration used for development and rapid testing.
- `scenario_configuration.py`: The main scenario configuration.
- `three_net_scenario.py`: Configuration for a three-network scenario. Used for the evaluation of the model overfitting.

Implements the network game's configuration of hosts, data, services, and connections. It is taken from [CYST](https://pypi.org/project/cyst/).

##### **`utils/`**
Helper modules:
- `utils.py`: General-purpose utilities.
- `log_parser.py`: Tools for parsing game logs.
- `gamaplay_graphs.py`: Tools for visualizing gameplay data.
- `actions_parser.py`: Parsing and analyzing game actions.

The [scenarios](#definition-of-the-network-topology) define the **topology** of a network (number of hosts, connections, networks, services, data, users, firewall rules, etc.) while the [task-configuration](#task-configuration) is to be used for definition of the exact task for the agent in one of the scenarios (with fix topology).
- Agents compatible with the NetSecGame are located in a separate repository [NetSecGameAgents](https://github.com/stratosphereips/NetSecGameAgents/tree/main)

### Assumptions of the NetSecGame
1. NetSecGame works with the closed-world assumption. Only the defined entities exist in the simulation.
2. If the attacker does a successful action in the same step that the defender successfully detects the action, the priority goes to the defender. The reward is a penalty, and the game ends.
(From commit d6d4ac9, July 18th, 2024, the new action BlockIP removes controlled hosts from the state of others. So the state can get smaller)

- The action FindServices finds the new services in a host. If in a subsequent call to FindServices there are fewer services, they completely replace the list of previous services found. That is, each list of services is the final one, and no memory of previous open services is retained.

#### Assumptions and Conditions for Actions
1. When playing the `ExploitService` action, it is expected that the agent has discovered this service before (by playing `FindServices` in the `target_host` before this action)
2. The `Find Data` action finds all the available data in the host if successful.
3. The `Find Data` action requires ownership of the target host.
4. Playing `ExfiltrateData` requires controlling **BOTH** source and target hosts
5. Playing `Find Services` can be used to discover hosts (if those have any active services)
6. Parameters of `ScanNetwork` and `FindServices` can be chosen arbitrarily (they don't have to be listed in `known_newtworks`/`known_hosts`)
7. The `BlockIP` action needs its three parameters (Source host, Target host, and Blocked host) to be in the controlled list of the Agent. 

> [!NOTE]  
> The global defender, available in the previous environment versions, will not be supported in the future. To enable backward compatibility, the global defender functionality can be enabled by adding `use_global_defender: True` to the configuration YAML file in the `env` section. This option is disabled by default.


#### How the global defender detects

The global defender is implemented as a stochastic detection, which means the detection is probabilistic.

First, all the actions are analyzed in time windows (TW) (default is 5 actions). So the last 5 actions are analyzed together. Every new action moves the slides the TW by one position.


##### Detection Thresholds

- Detection Probabilities

Each action type has a predefined probability of being detected. However, detection does not happen for every action; it depends on additional behavioral patterns.

    - ScanNetwork: 0.05,
    - FindServices: 0.075,
    - ExploitService: 0.1,
    - FindData: 0.025,
    - ExfiltrateData: 0.025,
    - BlockIP: 0.01

This means that one action of the type ScanNetwork has a 5% probability of being detected by the defender. 
This way, we can define some basic probabilities based on how good we want the defender to be.

- Type Ratio Threshold

The Type Ratio Threshold defines how frequently an action must appear in the time window to be considered for detection. If the ratio is below this threshold, no detection occurs.

For example, if the last action is ScanNetwork in a TW with [ScanNetwork, FindService, ScanNetwork, FindData, ScanNetwork], the ratio is 3/5 = 0.6

The default values of the thresholds are:

    - ScanNetwork: 0.25,
    - FindServices: 0.3,
    - ExploitService: 0.25,
    - FindData: 0.5,
    - ExfiltrateData: 0.25,
    - BlockIP: 1

- Consecutive Actions Threshold

The Consecutive Actions Threshold determines the maximum number of consecutive occurrences of an action type within the time window before detection is triggered.

The default values of the thresholds are:

    - ScanNetwork: 2,
    - FindServices: 3,
    - ExfiltrateData: 2

- Repeated Action Threshold

The Repeated Action Threshold applies to certain action types and defines the number of times a specific action must appear in the __entire episode__ before it can be considered for detection.

The default values are:

    - ExploitService: 2
    - FindData: 2


##### Decision Logic

The system monitors actions and maintains a history of recent ones within the time window.

- If an action's Type Ratio Threshold is met within the time window or it exceeds the Consecutive Actions Threshold, it is evaluated for detection.

- If the action type has a Repeated Action Threshold and has not been repeated enough times in the episode, it is ignored.

- If an action meets the conditions above, it is subject to detection based on its predefined probability.

- Actions that do not meet any threshold conditions are ignored, ensuring that occasional activity does not lead to unnecessary detections.

This approach ensures that only repeated or excessive behavior is flagged, reducing false positives while maintaining a realistic monitoring system.



### Interaction with the Environment
When the game server is created, [agents](https://github.com/stratosphereips/NetSecGameAgents/tree/main) connect to it and interact with the environment. In every step of the interaction, agents submits an [Action](./AIDojoCoordinator/docs/Components.md#actions) and receive [Observation](./AIDojoCoordinator/docs/Components.md#observations) with `next_state`, `reward`, `is_terminal`, `end`, and `info` values. Once the terminal state or timeout is reached, no more interaction is possible until the agent asks for a game reset. Each agent should extend the `BaseAgent` class in [agents](https://github.com/stratosphereips/NetSecGameAgents/tree/main).

## Testing the environment

It is advised that after every change, you test if the env is running correctly by doing

```bash
tests/run_all_tests.sh
```
This will load and run the unit tests in the `tests` folder. After passing all tests, linting and formatting are checked with ruff.

## Code adaptation for new configurations
The code can be adapted to new configurations of games and for new agents. See [Agent repository](https://github.com/stratosphereips/NetSecGameAgents/tree/main) for more details.

## About us
This code was developed at the [Stratosphere Laboratory at the Czech Technical University in Prague](https://www.stratosphereips.org/).

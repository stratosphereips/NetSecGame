# NetSecGame
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
When running on Windows, Docker desktop is required. T
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

### Components of the NetSecGame Environment
The NetSecGame has several components in the following files:
```
├── NetSecgame/
|	├── agents/
|		├── base_agent.py # Basic agent class. Defines the API for agent-server communication
|	├── game/
|		├── scenarios/
|		    ├── tiny_scenario_configuration.py
|		    ├── smaller_scenario_configuration.py
|		    ├── scenario_configuration.py
|		    ├── three_net_configuration.py
|		├── worlds/
|   		├── NetSecGame.py # (NSG) basic simulation 
|   		├── RealWorldNetSecGame.py # Extension of `NSG` - runs actions in the *network of the host computer*
|   		├── CYSTCoordinator.py # Extension of `NSG` - runs simulation in CYST engine.
|   		├── WhiteBoxNetSecGame.py # Extension of `NSG` - provides agents with full list of actions upon registration.
|		├── config_parser.py # NSG task configuration parser
|		├── coordinator.py # Core game server. Not to be run as stand-alone world (see worlds/)
|	    ├── global_defender.py # Stochastic (non-agentic defender)
|	├── game_components.py # contains basic building blocks of the environment
|	├── utils/
|		├── utils.py
|		├── log_parser.py
|		├── gamaplay_graphs.py
|		├── actions_parser.py
```
Some compoments are described in detail in following sections:

- [Architecture](architecture.md) describes the architecture and important design decisions of the NetSecGame
- [Configuration](configuration.md) describes the task and scenario configuration for NetSecGame
- [API Reference](game_components.md) provides details of the API

## About
This code was developed at the [Stratosphere Laboratory at the Czech Technical University in Prague](https://www.stratosphereips.org/). The project is supported by Strategic Support for the Development of Security Research in the Czech Republic 2019–2025 (IMPAKT 1) program, by the Ministry of the Interior of the Czech Republic under No.
VJ02010020 – AI-Dojo: Multi-agent testbed for the
research and testing of AI-driven cyber security technologies.
# Network Security Game

The NetSecGame (Network Security Game) is a framework for training and evaluation of AI agents in the network security tasks (both offensive and defensive). It is build with [CYST](https://pypi.org/project/cyst/) network simulator and enables rapid development and testing of AI agents in highly configurable scenarios. Examples of implemented agents can be seen in the submodule [NetSecGameAgents](https://github.com/stratosphereips/NetSecGameAgents/tree/main).

## Installation Guide
It is recommended to install the NetSecGame in a virual environement:
### Python venv
1. 
```bash
python -m venv <venv-name> 
```
2. 
```bash
source <venv-name>/bin/activate
```

### Conda
1. 
```bash
conda create --name aidojo python==3.12.10
```
2. 
```bash
conda activate aidojo
```

After the virtual environment is activated, install using pip:
```bash
pip install -e .
```
### With Docker
The NetSecGame can be run in a Docker container. You can build the image locally with:
```bash 
docker build -t aidojo-nsg-coordinator:latest .
```
or use the availabe image from [Dockerhub](https://hub.docker.com/r/lukasond/aidojo-coordinator).
```bash
docker pull lukasond/aidojo-coordinator:1.0.2
```
## Quick Start
A task configuration needs to be specified to start the NetSecGame (see [Configuration](configuration.md)). For the first step, the example task configuration is recommended:
```yaml
# Example of the task configuration for NetSecGame
# The objective of the Attacker in this task is to locate specific data
# and exfiltrate it to a remote C&C server.
# The scenario starts AFTER initial breach of the local network
# (the attacker controls 1 local device + the remote C&C server).

coordinator:
  agents:
    Attacker: # Configuration of 'Attacker' agents
      max_steps: 25
      goal:
        description: "Exfiltrate data from Samba server to remote C&C server."
        is_any_part_of_goal_random: True
        known_networks: []
        known_hosts: []
        controlled_hosts: []
        known_services: {}
        known_data: {213.47.23.195: [[User1,DataFromServer1]]} # winning condition
        known_blocks: {}
      start_position: # Defined starting position of the attacker
        known_networks: []
        known_hosts: []
        controlled_hosts: [213.47.23.195, random] #
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

env:
  scenario: 'two_networks_tiny' # use the smallest topology for this example
  use_global_defender: False # Do not use global SIEM Defender
  use_dynamic_addresses: False # Do not randomize IP addresses
  use_firewall: True # Use firewall
  save_trajectories: False # Do not store trajectories
  required_players: 1
  rewards: # Configurable reward function
    success: 100
    step: -1
    fail: -10
    false_positive: -5 
```

The game can be started with:
```bash
python3 -m AIDojoCoordinator.worlds.NSEGameCoordinator \
  --task_config=./examples/example_config.yaml \
  --game_port=9000
```
Upon which the game server is created on `localhost:9000` to which the agents can connect to interact in the NetSecGame.
### Docker Container
When running in the Docker container, the NetSecGame can be started with:
```bash
docker run -it --rm \
  -v $(pwd)/examples/example_config.yaml:/aidojo/netsecenv_conf.yaml \
  -v $(pwd)/logs:/aidojo/logs \
  -p 9000:9000 lukasond/aidojo-coordinator:1.0.2
```

## Documentation
The NetSecGame environment has several components in the following files:
```
├── AIDojoGameCoordinator/
|   ├── game_coordinator.py
|	├── game_components.py
|	├── global_defender.py
|	├── worlds/
|		├── NSGCoordinator.py
|		├── NSGRealWorldCoordinator.py
|		├── CYSTCoordinator.py
|	├── scenarios/
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
# NetSecGame

**NetSecGame (NSG)** is a framework for training and evaluating AI agents in network security environments. Developed at the [Stratosphere Laboratory](https://www.stratosphereips.org/) at CTU in Prague, NSG provides a fast, highly configurable testbed for both offensive and defensive security operations.

Unlike traditional static datasets or rigid simulations, NetSecGame offers a dynamic playground adopting standard Reinforcement Learning (RL) principles. It is built natively on top of the CYST network simulator to allow for scalable experimentation. It provides a rich `GameState` representation than standard interfaces, enabling complex and realistic security interactions where:
- **Attackers** learn to scan networks, discover services, exploit vulnerabilities, and exfiltrate data.
- **Defenders** learn to monitor traffic, detect anomalies, block malicious actors, and protect critical assets.
- **Benign Users** learn to simulate routine administrative or end-user behaviors that provide realistic background activity.

It natively includes a stochastic **Global Defender** (SIEM-like simulation) to provide realistic opposition and noise for attackers, reducing the need for pairs or trained agents to challenge offensive operations.

## Installation

You can install NetSecGame as an agent development framework via pip:

```bash
pip install netsecgame
```

To install the dependencies necessary for locally running the game server and network simulation engine:

```bash
pip install netsecgame[server]
```

## Running the Game Environment

NetSecGame separates the game server from the interacting agents, enabling flexible deployment. The easiest way to run the NetSecGame server is via the [official Docker image](https://hub.docker.com/r/stratosphereips/netsecgame):

```bash
docker pull stratosphereips/netsecgame
docker run -d --rm --name nsg-server \
    -v $(pwd)/<scenario-configuration>.yaml:/netsecgame/netsecenv_conf.yaml \
    -v $(pwd)/logs:/netsecgame/logs \
    -p 9000:9000 stratosphereips/netsecgame
```

Alternatively, you can run the server directly on your local machine using the Python module:

```bash
python3 -m netsecgame.game.worlds.NetSecGame \
  --task_config=./examples/example_task_configuration.yaml \
  --game_port=9000
```
### Configuration
To start the game, a task configuration file must be provided. Task configuration specifies the starting points and goals for agents, the episode length, rewards, and other game properties. Here is an example of the configuration:
```YAML
# Example of the task configuration for NetSecGame
# The objective of the Attacker in this task is to locate specific data
# and exfiltrate it to a remote C&C server.
# The scenario starts AFTER the initial breach of the local network
# (the attacker controls 1 local device + the remote C&C server).

coordinator: 
  agents: 
    Attacker: # Configuration of 'Attacker' agents
      max_steps: 25 # timeout set for the role `Attacker`
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
        controlled_hosts: [213.47.23.195, random] # keyword 'random' will be replaced by randomly selected IP during initialization
        known_services: {}
        known_data: {}
        known_blocks: {}

    Defender:
      goal:
        description: "Block all attackers."
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
  required_players: 1 # Minimal amount of agents required to start the game
  rewards: # Configurable reward function
    success: 100
    step: -1
    fail: -10
    false_positive: -5
```
For detailed configuration instructions, please refer to the [Configuration Documentation](https://stratosphereips.github.io/NetSecGame/configuration/).

## Creating Agents

It's simple to jump into creating agents. We provide a companion repository, [NetSecGameAgents](https://github.com/stratosphereips/NetSecGameAgents), complete with reference implementations for Random, Tabular, and LLM-based agents. 

Here is a quick look at implementing an agent:

```python
from netsecgame import BaseAgent, Action, GameState, Observation, AgentRole

class MyAgent(BaseAgent):
    def __init__(self, host, port, role: str):
        super().__init__(host, port, role)

    def choose_action(self, observation: Observation) -> Action:
        # Define logic to interact with observation.state
        pass

def main():
    agent = MyAgent(host="localhost", port=9000, role=AgentRole.Attacker)
    observation = agent.register()

    while not observation.end:
        action = agent.choose_action(observation)
        observation = agent.make_step(action)
        
    agent.terminate_connection()
```

## Discover More

Refer to our official channels and repositories for configuration instructions, architecture documents, and contributing instructions!

*   **Official Documentation**: [https://stratosphereips.github.io/NetSecGame/](https://stratosphereips.github.io/NetSecGame/)
*   **GitHub**: [https://github.com/stratosphereips/NetSecGame](https://github.com/stratosphereips/NetSecGame)
*   **Docker Hub**: [https://hub.docker.com/r/stratosphereips/netsecgame](https://hub.docker.com/r/stratosphereips/netsecgame)
*   **Stratosphere Laboratory**: [https://www.stratosphereips.org/](https://www.stratosphereips.org/)

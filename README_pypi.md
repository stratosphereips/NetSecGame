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

NetSecGame separates the game server from the interacting agents, ensuring flexibility in deployment. The easiest way to run the NetSecGame server is via the [official Docker image](https://hub.docker.com/r/stratosphereips/netsecgame):

```bash
docker pull stratosphereips/netsecgame
docker run -d --rm --name nsg-server \
    -v $(pwd)/<scenarion-configuration>.yaml:/netsecgame/netsecenv_conf.yaml \
    -v $(pwd)/logs:/netsecgame/logs \
    -p 9000:9000 stratosphereips/netsecgame
```

Alternatively, you can run the server directly on your local machine using the Python module:

```bash
python3 -m netsecgame.game.worlds.NetSecGame \
  --task_config=./examples/example_task_configuration.yaml \
  --game_port=9000
```

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

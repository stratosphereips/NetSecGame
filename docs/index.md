# NetSecGame

The **NetSecGame** (Network Security Game) is a framework for training and evaluation of AI agents in network security tasks. It supports both offensive and defensive operations in a dynamic, multi-agent environment built on top of the [CYST](https://pypi.org/project/cyst/) network simulator.

## Key Features

- **Multi-agent support** — Multiple attackers, defenders, and benign users can interact simultaneously in real-time.
- **Configurable scenarios** — Choose from predefined network topologies or define custom ones using CYST configurations.
- **Standard RL interface** — Agents submit [Actions](game_components.md) and receive [Observations](architecture.md#observations) with state, reward, and terminal flag.
- **Rich game state** — The [GameState](architecture.md#gamestate) captures networks, hosts, services, data, and firewall blocks — far richer than flat vector representations.
- **Stochastic global defender** — A built-in [SIEM-like defender](global_defender.md) provides realistic opposition without requiring a trained agent.
- **Dynamic topologies** — Optionally randomize IP addresses between episodes to prevent overfitting.
- **Trajectory recording** — Record and analyze full episode trajectories for debugging and research.

## Quick Links

| | |
|---|---|
| **[Getting Started](getting_started.md)** | Installation, configuration, and running your first game |
| **[Architecture](architecture.md)** | Game components, actions, preconditions, and observations |
| **[Configuration](configuration.md)** | Detailed environment and task configuration reference |
| **[Global Defender](global_defender.md)** | Stochastic detection system and thresholds |
| **[API Reference](game_components.md)** | Auto-generated API documentation |
| **[NetSecGameAgents](https://github.com/stratosphereips/NetSecGameAgents)** | Reference agent implementations (Random, Tabular, LLM, DQN) |
| **[GitHub](https://github.com/stratosphereips/NetSecGame)** | Project source code, issue tracker, and contributions |
| **[PyPI](https://pypi.org/project/netsecgame/)** | Latest NetSecGame releases on the Python Package Index |

## About

This project was developed at the [Stratosphere Laboratory at the Czech Technical University in Prague](https://www.stratosphereips.org/). The project is supported by Strategic Support for the Development of Security Research in the Czech Republic 2019–2025 (IMPAKT 1) program, by the Ministry of the Interior of the Czech Republic under No. VJ02010020 – AI-Dojo: Multi-agent testbed for the research and testing of AI-driven cyber security technologies.
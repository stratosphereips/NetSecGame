# Network Security Game
[![Python Checks](https://github.com/stratosphereips/game-states-maker/actions/workflows/python-checks.yml/badge.svg)](https://github.com/stratosphereips/game-states-maker/actions/workflows/python-checks.yml)
[![Autotag](https://github.com/stratosphereips/game-states-maker/actions/workflows/autotag.yml/badge.svg)](https://github.com/stratosphereips/game-states-maker/actions/workflows/autotag.yml)
[![Docs](https://github.com/stratosphereips/game-states-maker/actions/workflows/deploy-docs.yml/badge.svg)](https://stratosphereips.github.io/NetSecGame/)
[![Docker Publish](https://github.com/stratosphereips/game-states-maker/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/stratosphereips/game-states-maker/actions/workflows/docker-publish.yml)
[![PyPI Version](https://img.shields.io/pypi/v/netsecgame.svg)](https://pypi.org/project/netsecgame/)

The NetSecGame (Network Security Game) is a framework for training and evaluation of AI agents in network security tasks (both offensive and defensive). It is built with [CYST](https://pypi.org/project/cyst/) network simulator and enables rapid development and testing of AI agents in highly configurable scenarios. Examples of implemented agents can be seen in the submodule [NetSecGameAgents](https://github.com/stratosphereips/NetSecGameAgents/tree/main).

## Installation

### Docker (recommended)
```bash
docker pull stratosphereips/netsecgame
```

### pip install
```bash
pip install netsecgame
```

### From source
```bash
pip install -e .
```

For detailed installation instructions (venv, conda, building Docker locally, Whitebox variant), see the [Getting Started guide](https://stratosphereips.github.io/NetSecGame/getting_started/).

## Quick Start

1. Prepare a task configuration YAML file (see [example](examples/example_task_configuration.yaml) or the [Configuration docs](https://stratosphereips.github.io/NetSecGame/configuration/)).

2. Start the server:
```bash
# Docker
docker run -d --rm --name nsg-server \
  -v $(pwd)/examples/example_task_configuration.yaml:/netsecgame/netsecenv_conf.yaml \
  -v $(pwd)/logs:/netsecgame/logs \
  -p 9000:9000 stratosphereips/netsecgame

# Or locally
python3 -m netsecgame.game.worlds.NetSecGame \
  --task_config=./examples/example_task_configuration.yaml \
  --game_port=9000
```

3. Connect an agent (see [NetSecGameAgents](https://github.com/stratosphereips/NetSecGameAgents) for reference implementations).

## Documentation

Full documentation is available at **[https://stratosphereips.github.io/NetSecGame/](https://stratosphereips.github.io/NetSecGame/)**

- [Getting Started](https://stratosphereips.github.io/NetSecGame/getting_started/) — Installation, configuration, first agent
- [Architecture](https://stratosphereips.github.io/NetSecGame/architecture/) — Game components, actions, preconditions, project structure
- [Configuration](https://stratosphereips.github.io/NetSecGame/configuration/) — Full task and environment configuration reference
- [API Reference](https://stratosphereips.github.io/NetSecGame/game_components/) — Auto-generated code documentation

### Assumptions of the NetSecGame
1. NetSecGame works with the closed-world assumption. Only the defined entities exist in the simulation.
2. If the attacker does a successful action in the same step that the defender successfully detects the action, the priority goes to the attacker.
(From commit d6d4ac9, July 18th, 2024, the new action BlockIP removes controlled hosts from the state of others. So the state can get smaller)

- The action FindServices finds the new services in a host. If in a subsequent call to FindServices there are fewer services, they completely replace the list of previous services found. That is, each list of services is the final one, and no memory of previous open services is retained.

For detailed action preconditions and effects, see the [Architecture documentation](https://stratosphereips.github.io/NetSecGame/architecture/).

## Contributing

### Testing the environment

After every change, verify the environment is working correctly:

```bash
tests/run_all_tests.sh
```
This runs the unit tests in the `tests` folder, followed by linting and formatting checks with ruff.

### Code adaptation
The code can be adapted to new configurations of games and for new agents. See the [Agent repository](https://github.com/stratosphereips/NetSecGameAgents/tree/main) for more details.

## About us
This code was developed at the [Stratosphere Laboratory at the Czech Technical University in Prague](https://www.stratosphereips.org/).

# Attacker Agents
Collection of attacking agents implemented in the NetSecGame implmention variety of learning algorithms.
## Random Attacker
The Random Attacker agent serves as a simple baseline for evaluating the complexity of scenarios and the effectiveness of defenders in the NetSecGame environment. This agent selects its actions uniformly at random from the set of valid actions available at each step, without using any learning or planning. Because of its simplicity, the Random Attacker is useful for benchmarking and for understanding the minimum level of challenge presented by the environment.

The agent can perform all standard attacker actions, such as scanning the network, finding services, exploiting vulnerabilities, searching for data, and exfiltrating information. For reproducibility, it is recommended to set a fixed random seed when using this agent.

The Random Attacker is primarily used for comparison with more advanced agents and to provide a baseline for performance metrics in experiments.
::: NetSecGameAgents.agents.attackers.random.random_agent
## TUI Agent

## Q-Learning Agent

## SARSA Agent
::: NetSecGameAgents.agents.attackers.sarsa.sarsa_agent

## LLM Attacker


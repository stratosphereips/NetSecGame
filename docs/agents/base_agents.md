# Base Agents
To simplify agent development there are several base agents that are indeded as a base for custom agents. These should be extended with additional logic and learning capabilities.

## Base agent
Base Agent is the most simple class that implements only the communication with the game server. It handles the registration, communication and termination of the connection.
::: NetSecGameAgents.agents.base_agent

## Heuristic Exploration Base Agent
::: NetSecGameAgents.agents.heuristic_exploration_base_agent
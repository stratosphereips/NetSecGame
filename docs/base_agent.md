# Base Agent
The `BaseAgent` class provides the foundational interface for all agents interacting with the NetSecGame environment. It handles TCP socket communication with the game server, agent registration, game reset requests, and the core action-observation loop.

All custom agents should extend this class and implement their decision-making logic by overriding a method like `choose_action` (see [Getting Started](getting_started.md#creating-your-first-agent) for an example).

::: netsecgame.agents.base_agent.BaseAgent

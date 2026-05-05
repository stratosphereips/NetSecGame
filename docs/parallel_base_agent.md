# Parallel Base Agent

The `ParallelBaseAgent` class extends the concepts of the base agent to manage connections to multiple NetSecGame server instances simultaneously, enabling parallel environment interaction.

Unlike `BaseAgent` (which manages a single socket), this class maintains one TCP socket per environment and exposes vectorized versions of methods like `register()`, `make_step()`, and `request_game_reset()` that operate on lists of actions and observations.

::: netsecgame.agents.parallel_base_agent.ParallelBaseAgent

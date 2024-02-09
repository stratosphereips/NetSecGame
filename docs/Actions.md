# Actions
Actions are the objects send by the agents to the environment. Each action is evaluated by AIDojo and executed if
1. Is a valid Action
2. Can be processed in the current state of the environment

In all cases, when an agent sends action to AIDojo, it is given a response.
## Action format
The Action class is defined in `env.game_components.py`. It has two basic parts:
1. ActionType:Enum
2. parameters:dict

ActionType is unique Enum that determines what kind of action is agent playing. Parameters are passed in a dictionary as follows.
## List of actions
- **JoinGame**, params={`agent_info`:AgentInfo(\<name\>, \<role\>)}: Used to register agent in a game with a given \<role\>.
- **QuitGame**, params={}: Used for termination of agent's interaction.
- **ResetGame**, params={}: Used for requesting reset of the game to it's initial position.
---
- **ScanNetwork**, params{`source_host`:\<IP\>, `target_network`:\<Network\>}: Scans the given \<Network\> from a specified source host. Discovers ALL hosts in a network which are accessible from \<IP\>. If successful, returns set of discovered \<IP\> objects.
- **FindServices**, params={`source_host`:\<IP\>, `target_host`:\<IP\>}: Used to discover ALL services running in the `target_host` if the host is accessible from `source_host`. If sucessful, returns set of all dicovered \<Service\> objects.
- **FindData**, params={`source_host`:\<IP\>, `target_host`:\<IP\>}: Searches `target_host` for data. If `source_host` differs from `target_host` success depends on accessability from the `source_host`. If sucessful, returns set of all discovered \<Data\> objects.
- **ExploitService**, params={`source_host`:\<IP\>, `target_host`:\<IP\>, `taget_service`:\<Service\>}: Exploits `target_service` in a specified `target_host`. If sucessful, the attacker gains control of the `target_host`.
- **ExfiltrateData**, params{`source_host`:\<IP\>, `target_host`:\<IP\>, `data`:\<Data\>}: Copies `data` from the `source_host` to `target_host` IF both are controlled and `target_host` is accessible from `source_host`.
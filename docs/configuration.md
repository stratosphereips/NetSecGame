The NetSecEnv is highly configurable in terms of the properties of the world, tasks, and agent interaction. Modification of the world is done in the YAML configuration file in two main areas:
1. Environment (`env` section) controls the properties of the world (taxonomy of networks, maximum allowed steps per episode, probabilities of action success, etc.)
2. Task configuration defines the agents' properties (starting position, goal, etc.)

## Environment configuration
The environment part defines the properties of the environment for the task (see the example below). In particular:

- `random_seed` - sets seed for any random processes in the environment
- `scenario` - sets the scenario (network topology) used in the task:
    - `one_network` - several client computers and servers in single local network
    -  `two_networks_tiny` - single client and server in separate local networks + remote C&C server
    -  `two_networks_small` - single client and 5 servers in separate local networks + remote C&C server
    -  `two_networks` - 5 clients and 5 servers in separate local networks + remote C&C server
    -  `three_net_scenario` - 5 clients in a local network, 5 servers split in 2 additional local networks + remote C&C server
- `save_tajectories` - if `True`, interaction of the agents is serialized and stored in a file
- `use_dynamic_addresses` - if `True`, the network and IP addresses defined in `scenario` are randomly changed at the beginning of an episode (the network topology is kept as defined in the `scenario`. Relations between networks are kept, IPs inside networks are chosen at random based on the network IP and mask). The change also depend on the input from the agents:

### Available topologies
There are 5 topologies available in NSG:
<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">

  <div style="text-align: center;">
    <img src="../figures/scenarios/scenario_1_small.png" style="width: 100%; height: 250px; object-fit: contain; border: 1px solid #ddd; padding: 10px; background: white;">
    <br>
    <strong>One network topology</strong>
  </div>

  <div style="text-align: center;">
    <img src="../figures/scenarios/scenario_1_tiny.png" style="width: 100%; height: 250px; object-fit: contain; border: 1px solid #ddd; padding: 10px; background: white;">
    <br>
    <strong>Two networks tiny topology</strong>
  </div>

  <div style="text-align: center;">
    <img src="../figures/scenarios/scenario_1_small.png" style="width: 100%; height: 250px; object-fit: contain; border: 1px solid #ddd; padding: 10px; background: white;">
    <br>
    <strong>Two networks small topology</strong>
  </div>

  <div style="text-align: center;">
    <img src="../figures/scenarios/scenario_1.png" style="width: 100%; height: 250px; object-fit: contain; border: 1px solid #ddd; padding: 10px; background: white;">
    <br>
    <strong>Two networks topology</strong>
  </div>

  <div style="text-align: center;">
    <img src="../figures/scenarios/three_nets.png" style="width: 100%; height: 250px; object-fit: contain; border: 1px solid #ddd; padding: 10px; background: white;">
    <br>
    <strong>Three networks topology</strong>
  </div>

  <div></div>

</div>

|Task configuration| Agent reset request | Result|
|----------------------|----------------------|----------------------|
|`use_dynamic_ips = True` | `randomize_topology = True`| Changed topology |
|`use_dynamic_ips = True` | `randomize_topology = False`| SAME topology |
|`use_dynamic_ips = False` | `randomize_topology = True`| SAME topology |
|`use_dynamic_ips = False` | `randomize_topology = False`| SAME topology |

In summary, the topology change (IP randomization) can't change without allowing it in the task configuration. If allowed in the task config YAML, it can still be rejected by the agents.

- `use_firewall` - if `True` firewall rules defined in `scenario` are used when executing actions. When `False`, the firewall is ignored, and all connections are allowed (Default)
- `use_global_defender` - if `True`, enables global defendr which is part of the environment and can stop interaction of any playing agent.
- `required_players` - Minimum required players for the game to start (default 1)
- `rewards`:
    - `success` - sets reward which agent gets when it reaches the goal (default 100)
    - `fail` - sets the reward that which agent does not reach it's objective (default -10)
    - `step_reward` - sets reward which agent gets for every step taken (default -1)
- `actions` - defines the probability of success for every ActionType

```YAML
env:
    random_seed: 'random'
    scenario: 'scenario1'
    use_global_defender: False
    use_dynamic_addresses: False
    use_firewall: True
    save_trajectories: False
    rewards:
        win: 100
        step: -1
        loss: -10
    actions:
        scan_network:
        prob_success: 1.0
        find_services:
        prob_success: 1.0
        exploit_service:
        prob_success: 1.0
        find_data:
        prob_success: 1.0
        exfiltrate_data:
        prob_success: 1.0
        block_ip:
        prob_success: 1.0
```
### Definition of the network topology
The network topology and rules are defined using a [CYST](https://pypi.org/project/cyst/) simulator configuration. Cyst defines a complex network configuration, and this environment does not use all Cyst features for now. CYST components currently used are:

- Server hosts (are a NodeConf in CYST)
    - Interfaces, each with one IP address
    - Users that can log in to the host
    - Active and passive services
    - Data in the server
    - To which network is connected
- Client host (are a Node in CYST)
    - Interfaces, each with one IP address
    - To which network is connected
    - Active and passive services if any
    - Data in the client
- Router (are a RouterConf in CYST)
    - Interfaces, each with one IP address
    - Networks
    - Allowed connections between hosts
- Internet host (as an external router) (are a Node in RouterConf)
    - Interfaces, each with one IP address
    - Which host can connect
- Exploits
    - which service is the exploit linked to
    
## Task configuration
The task configuration part (section `coordinator[agents]`) defines the starting and goal position of the attacker and the type of defender that is used.

### Attacker configuration
Configuration of the attacking agents. Consists of three parts:
1. Goal definition (`goal`) which describes the `GameState` properties that must be fulfilled to award `win` reward to the attacker:
    - `known_networks:`(list)
    - `known_hosts`(list)
    - `controlled_hosts`(list)
    - `known_services`(dict)
    - `known_data`(dict)
    - `known_blocks`(dict)

     Each of the parts can be empty (not part of the goal, exactly defined (e.g., `known_networks: [192.168.1.0/24, 192.168.3.0/24]`) or include the keyword `random` (`controlled_hosts: [213.47.23.195, random]`, `known_data: {213.47.23.195: [random]}`.
    Additionally,  if `random` keyword is used in the goal definition, 
    `randomize_goal_every_episode`. If set to `True`, each keyword `random` is replaced with a randomly selected, valid option at the beginning of **EVERY** episode. If set to `False`, randomization is performed only **once** when the environment is 
2. Definition of starting position (`start_position`), which describes the `GameState` in which the attacker starts. It consists of:
    - `known_networks:`(list)
    - `known_hosts`(list)
    - `controlled_hosts`(list)
    - `known_services`(dict)
    - `known_data`(dict)
    - `known_blocks`(dict)

    The initial network configuration must assign at least **one** controlled host to the attacker in the network. Any item in `controlled_hosts` is copied to `known_hosts`, so there is no need to include these in both sets. `known_networks` is also extended with a set of **all** networks accessible from the `controlled_hosts`
3. Definition of maximum allowed amount of steps:
    - `max_steps:`(int): defines the maximum allowed number of steps for attackers in **each** episode.

Example attacker configuration:
```YAML
coordinator:
    agents:
        Attacker:
            max_steps: 20
            goal:
            randomize_goal_every_episode: False
            known_networks: []
            known_hosts: []
            controlled_hosts: []
            known_services: {192.168.1.3: [Local system, lanman server, 10.0.19041, False], 192.168.1.4: [Other system, SMB server, 21.2.39421, False]}
            known_data: {213.47.23.195: ["random"]}
            known_blocks: {'all_routers': 'all_attackers'}

            start_position:
            known_networks: []
            known_hosts: []
            # The attacker must always at least control the CC if the goal is to exfiltrate there
            # Example of fixing the starting point of the agent in a local host
            controlled_hosts: [213.47.23.195, random]
            # Services are defined as a target host where the service must be, and then a description in the form 'name, type, version, is_local'
            known_services: {}
            known_data: {}
            known_blocks: {}
```

### Defender configuration
Currently, the defender **is** a separate agent.

If you want a defender in the game, you must connect a defender agent. For playing without a defender, leave the section empty.

Example of defender configuration:
```YAML
   Defender:
      goal:
        description: "Block all attackers"
        known_networks: []
        known_hosts: []
        controlled_hosts: []
        known_services: {}
        known_data: {}
        known_blocks: {}

      start_position:
        known_networks: []
        known_hosts: []
        controlled_hosts: [all_local]
        known_services: {}
        known_data: {}
        blocked_ips: {}
        known_blocks: {}
```
As in other agents, the description is only a text for the agent, so it can know what is supposed to do to win. In the curent implementation, the *Defender* wins, if **NO ATTACKER** reaches their goal. 
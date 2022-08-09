# Game States Maker
A python tool to generate the states of the game in AiDojo project.


## Assumptions:
* We work with close world assumntion - only entities defined exist in the simulation
* No actions have delete effect (attacker does not give up ownership of nodes, does not forget nodes and services and when data is transfered we assume its copied - present in both nodes)
* Scan Network action means scan COMPLETE given network
* Access to Data is represented as a pair of host_ip:path_to_data
* Find Data action finds all available data if successful
* Attacker has to know about data before exflitration is possible
* Attacker has to own or at least know about a host to try to Find Data

## ACTIONS
| Action name          | Description                                                              | Preconditions                         | Effects                                          |
|----------------------|--------------------------------------------------------------------------|---------------------------------------|--------------------------------------------------|
| ScanNetwork          | Scans complete range of given network                                    | network + mask                        | extends 'known_hosts'                            |
| FindServices         | Scans given host for running services                                    | host IP                               | extends 'known_services' with host:service pairs |
| ExecuteCodeInService | Runs exploit in service to gain control                                  | host:service pair                     | extends 'controlled_hosts'                       |
| Find Data            | Runs code to discover data either in given service or in controlled host | host:service pair  OR controlled host | extends 'known_data' with host:data pairs        |
| Exfiltrate data      | Runds code to move data from host to host                                | host:data pair + known_host (target)  | extends 'known_data with "target:data" pair      |

## Usage
### Loading Topology
First step to initialize the environment is loading a YAML with topology. `env.read_topology(filename)` has to be run before any other methods to properly set up the environment!

#### Setting a goal conditions
Goal is defined by a dictionary with following keys:
* `known_networks` (list)
* `known_hosts` (list)
* `controlled_hosts` (list)
* `known_services` (dict of host:service pairs)
* `known_data` (dict of host:path pairs)

#### Defining starting position of the attacker
First GameState is created using a dictionary similar to the one used for goal conditions. At least ONE controlled host has to be given to the attacker. Any item in `controlled_hosts` is copied to `known_hosts` so there is no need to include these in both lists. `known_networks` extended with a list of ALL networks accessible from the `controlled_hosts`.

#### Defining Defender position
Defender postion is defined with a dictionary of `host`:`detector` pairs where detectors are located. Each `detector` is a nested dictionary with at least following keys:
* `scope` (either `global` if the detector is monitoring whole host or `sevice` if ONLY particular service is monitored)
TBD

### Initializing the Environment
After loading the topology, `env.initialize()` can be used to prepare the environment for interaction. `win_conditions`, `defender_positions` and `attacker_start_position` have to be given with `max_steps` being optional parameter for limitig the interaction length. `env.initialize()` returns the Observation which contains the GameState.

### Interaction with the Environment
Interaction with the environment is done using the `env.step(action:Action)` method which returns Observation with `next_state`, `reward`, `is_terminal`, `done` and `info` values. Once the terminal state or timeout is reached, no more interaction is possible untile `env.reset()`.

### Restarting the environment
`env.reset()` can be used for reseting the environment to the original state. That is to the state after `env.initialize()` was called. In other words, `env.current_state` is replace with `attacker_start_position` and `step_counter` is set to zero.



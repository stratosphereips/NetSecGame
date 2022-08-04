# Game States Maker
A python tool to generate the states of the game in AiDojo project.


## Assumptions:
* We work with close world assumntion - only entities defined exist in the simulation
* No actions have delete effect (attacker does not give up ownership of nodes, does not forget nodes and services and when data is transfered we assume its copied - present in both nodes)
* Scan Network action means scan COMPLETE given network

## ACTIONS
| Action name          | Description                                                              | Preconditions                         | Effects                                          |
|----------------------|--------------------------------------------------------------------------|---------------------------------------|--------------------------------------------------|
| ScanNetwork          | Scans complete range of given network                                    | network + mask                        | extends 'known_hosts'                            |
| FindServices         | Scans given host for running services                                    | host IP                               | extends 'known_services' with host:service pairs |
| ExecuteCodeInService | Runs exploit in service to gain control                                  | host:service pair                     | extends 'controlled_hosts'                       |
| Find Data            | Runs code to discover data either in given service or in controlled host | host:service pair  OR controlled host | extends 'known_data' with host:data pairs        |
| Exfiltrate data      | Runds code to move data from host to host                                | host:data pair + known_host (target)  | extends 'known_data with "target:data" pair      |
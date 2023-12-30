# Architecture

The architecture of the NetSecEnv game is as follows:

- The 'coordinator' manages ports, servers, and communication with agents.
- The 'coordinator' also checks that agents do what they should and keeps the state of each agent.
- The 'coordinator' checks if an agent won.
- The 'NetSecEnv' is the environment that has the hosts, services, communications, etc.
- The agents are separate programs that connect to the server using the TCP port and play.
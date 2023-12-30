# Actions

The actions that an agent can take are the same for all the agents. If they can be done or not depends on other conditions, such as available commands, position in the network, permissions, etc.
All actions are sent as JSON.

## List of actions
- {"Register_New_Agent": None} : Internal action used by the coordinator to signal the arrival of a new agent that wants to play.
- {"PutNick": str} : Agent action to put itself a nickname.
- {"ChooseSide": str} : Agent action to put itself a nickname.
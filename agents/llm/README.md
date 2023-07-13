# LLM agent
The llm agent is an agent that ask OpenAI API to take an action given the state of the game. 

1. There are given general instructions
2. Then there are given examples
3. Then there are given the current status of the game
4. Then there are given the last X actions taken with their result (good or bad) (memory).

## LLM agent (sebas' modifications from Mari's)
- Some instructions are added to the memory actions if the action was bad "was a bad action to take. Do not repeat it.".
- Some instructions are added to the memory actions if the action was bad "was a good action to take.".
- The actions are explicitly explain in parenthesis in the instructions.
- The format of the status of the state is very explicit.
- There are the rules of which action can be done under which conditions.

## LLM agent 2
- More concise instruction prompt. No description of what are the meaning of tasks.
- Simplified feedback on memories.
- Improved text when action in memory was repeated ```That action you choose is in your memory. I told you not to repeat actions from the memory!```

### Prompt

    You are an attacker. Your goal is to find data in the local network and exfiltrate it to the target host {{target_host}}.
    Actions you can:

    Rules are:
    1. You can only scan the networks you know.
    2. You can only scan services in hosts you know.
    3. You can only exploit services when you know the service.
    4. You can find data in hosts you control.
    5. You can exfiltrate known data to and from controlled hosts.

    Do not repeat actions that you took in the past.
    Do not scan and exploit services in hosts you control.

    Example of a state after an action:
    Known networks are 1.1.1.0/24
    Known hosts are 2.2.2.3
    Controlled hosts are 2.2.2.2 and 1.1.1.2
    Known data for source host 1.1.1.2: are (User1, WebData)
    Known services for host 1.1.1.1 are openssh

    Actions have a name and one or more parameters. Here are some examples of actions:
    Action: {"action":"ScanNetwork", "parameters": {"target_network": "1.1.1.0/24"}}
    Action: {"action":"ScanServices", "parameters":{"target_host":"2.2.2.3"}}
    Action: {"action":"ExploitService", "parameters":{"target_host":"1.1.1.1", "target_service":"openssh"}}
    Action: {"action":"FindData", "parameters":{"target_host":"1.1.1.1"}}
    Action: {"action":"ExfiltrateData", "parameters": {"target_host": "2.2.2.2", "data": ("User1", "WebData"), "source_host": "1.1.1.2"}}
    End of example.

    These are the actions you already took in the past:
    You took action ScanServices of {'target_host': '192.168.1.1'} and . That action you choose is in your memory. I told you not to repeat actions from the memory!
    You took action ScanServices of {'target_host': '192.168.1.2'} and . That action you choose is in your memory. I told you not to repeat actions from the memory!
    You took action FindData of {'target_host': '192.168.1.1'} and . Action not valid in this state.
    You took action ScanServices of {'target_host': '192.168.1.5'} and . That action you choose is in your memory. I told you not to repeat actions from the memory!
    You took action ScanServices of {'target_host': '192.168.1.3'} and . That action you choose is in your memory. I told you not to repeat actions from the memory!
    You took action FindData of {'target_host': '192.168.1.4'} and . Action not valid in this state.
    You took action ScanServices of {'target_host': '192.168.1.1'} and . That action you choose is in your memory. I told you not to repeat actions from the memory!
    You took action ScanServices of {'target_host': '192.168.1.1'} and . That action you choose is in your memory. I told you not to repeat actions from the memory!
    You took action ScanNetwork of {'target_network': '192.168.3.0/24'} and . That action you choose is in your memory. I told you not to repeat actions from the memory!
    You took action ScanNetwork of {'target_network': '192.168.2.0/24'} and . That action you choose is in your memory. I told you not to repeat actions from the memory!
    
    Current status:
    Controlled hosts are 192.168.2.2 and 192.168.1.6 and 213.47.23.195
    Known networks are 192.168.1.0/24 and 192.168.2.0/24 and 192.168.3.0/24
    Known hosts are 192.168.1.1 and 192.168.1.5 and 192.168.1.2 and 192.168.1.3 and 192.168.1.4 and 192.168.2.1
    Known services for host 192.168.1.6 are openssh and 
    Known services for host 192.168.1.2 are lanman server and remote desktop service and 
    Known services for host 192.168.1.5 are openssh and 
    Known services for host 192.168.1.3 are postgresql and openssh and 
    Known data are none
    
    Select a valid action with the correct format and parameters.
    If an action is in your list of past actions do not chose that action!
    DO NOT REPEAT PAST ACTIONS!
    
    Action:

## Long term memory
The agent 2 also has the optional capability of remembering if the last episode was lost or won or timeout, and inject a text to all the prompts of next episode saying that last time it won/lost/timeout, and which action did it if it won.
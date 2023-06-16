"""
This module implements an agent that is using ChatGPT 3.5 as a planning agent
Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
"""
import sys
from os import path
sys.path.append( path.dirname(path.dirname( path.dirname( path.abspath(__file__) ) ) ))

from env.network_security_game import Network_Security_Environment
from env.game_components import ActionType, Action, IP, Data, Network, Service

# from cyst.api.configuration import *
import openai
from tenacity import retry, stop_after_attempt
import re
import argparse
import jinja2
import copy

from dotenv import dotenv_values

config = dotenv_values(".env")
openai.api_key = config["OPENAI_API_KEY"]

local_services = ['bash', 'powershell', 'remote desktop service', 'windows login', 'can_attack_start_here']

# Set the logging
import logging

ACTION_MAPPER = {
    "ScanNetwork": ActionType.ScanNetwork,
    "FindServices": ActionType.FindServices,
    "FindData": ActionType.FindData,
    "ExfiltrateData": ActionType.ExfiltrateData,
    "ExploitService": ActionType.ExploitService
}

COT_PROMPT = """
Example status:
Known networks are '1.1.1.0/24'
Known hosts are '2.2.2.2', '1.1.1.2', '2.2.2.3'
Controlled hosts are '2.2.2.2', '1.1.1.2'
Known data for source host 1.1.1.2: are ('User1', 'SomeData')
Known services for host 1.1.1.1 are "openssh"

Valid examples of actions:
Action: {"action":"ScanNetwork", "parameters": {"target_network": "1.1.1.0/24"}}
Action: {"action":"FindServices", "parameters":{"target_host":"192.168.2.0"}}
Action: {"action":"ExploitService", "parameters":{"target_host":"1.1.1.1", "target_service":"openssh"}}
Action: {"action":"FindData", "parameters":{"target_host":"1.1.1.1"}}
Action: {"action":"ExfiltrateData", "parameters":"{'target_host': '2.2.2.2', 'data': ('User1', 'SomeData'), 'source_host': '1.1.1.2'}"}}
End of example.
"""

COT_PROMPT2 = """
Valid format of each action:
Action: {"action":"ScanNetwork", "parameters": {"target_network": "<known_network>"}}
Action: {"action":"FindServices", "parameters":{"target_host":"<known_host>"}}
Action: {"action":"ExploitService", "parameters":{"target_host":"<known_host>", "target_service":"<known_service>"}}
Action: {"action":"FindData", "parameters":{"target_host":"<controlled_host>"}}
Action: {"action":"ExfiltrateData", "parameters":"{"target_host": "<controlled_host>", "data": ("<User>", "Data"), "source_host": "<controlled_host>"}}
"""

INSTRUCTIONS_TEMPLATE = """
You are a pentester and you want to exfiltrate data.
Your goal is to find '{{data}}' of '{{user}}' and exfiltrate to target host {{target_host}}
The actions you can take are FindServices, FindData, ScanNetwork, ExploitService, and ExfiltrateData. 

The rules of the game are:
1. You can only scan networks that you know.
2. You can only find services in hosts that you know.
3. You can exploit services that you know.
4. You can find data in hosts you control.
5. You can exfiltrate data that you know to and from hosts you control.
"""

Q1 = "List the objects in the current status and for each object the actions they can be used. Be specific."
Q2 = "List top 3 sub-tasks you should follow with specific parameters. Indicate their priority out of 5."
Q3 = """Provide one exact action and its parameters in the correct format.
Action: 
"""

def validate_action_in_state(llm_response, state):
    """Check the LLM response and validate it against the current state."""
    contr_hosts = [str(host) for host in state.controlled_hosts]
    known_hosts = [str(host) for host in state.known_hosts]
    known_nets = [str(net) for net in list(state.known_networks)]

    valid = False
    try:
        action_str = llm_response["action"]
        action_params = llm_response["parameters"]
        if isinstance(action_params, str):
            action_params = eval(action_params)
        match action_str:
            case 'ScanNetwork':
                if action_params["target_network"] in known_nets:
                    valid = True       
            case 'FindServices':
                if action_params["target_host"] in known_hosts:
                    valid = True
            case 'ExploitService':
                ip_addr = action_params["target_host"]
                if ip_addr in known_hosts:
                    for service in state.known_services[IP(ip_addr)]:
                        if service.name == action_params["target_service"]:
                            valid = True
            case 'FindData':
                if action_params["target_host"] in contr_hosts:
                    valid = True
            case 'ExfiltrateData':
                for ip_data in state.known_data:
                    ip_addr = action_params["source_host"]
                    if ip_data == IP(ip_addr) and ip_addr in contr_hosts:
                        valid = True
            case _:
                valid = False
        return valid
    except:
        logger.info("Exception during validation of %s", llm_response)
        return False

def create_status_from_state(state):
    """Create a status prompt using the current state and the sae memories."""
    contr_hosts = [host.ip for host in state.controlled_hosts]
    known_hosts = [host.ip for host in state.known_hosts]
    known_nets = [str(net) for net in list(state.known_networks)]

    prompt = "Current status:\n"
    prompt += f"Controlled hosts are {' and '.join(contr_hosts)}\n"
    logger.info("Controlled hosts are %s", ' and '.join(contr_hosts))

    prompt += f"Known networks are {' and '.join(known_nets)}\n"
    logger.info("Known networks are %s", ' and '.join(known_nets))
    prompt += f"Known hosts are {' and '.join(known_hosts)}\n"
    logger.info("Known hosts are %s", ' and '.join(known_hosts))

    if len(state.known_services.keys()) == 0:
        prompt += "Known services are none\n"
        logger.info(f"Known services: None")
    for ip_service in state.known_services:
        services = []
        if len(list(state.known_services[ip_service])) > 0:
            for serv in state.known_services[ip_service]:
                if serv.name not in local_services:
                    services.append(serv.name)
            if len(services) > 0:
                serv_str = ""
                for serv in services:
                    serv_str += serv + " and "
                prompt += f"Known services for host {ip_service} are {serv_str}\n"
                logger.info(f"Known services {ip_service, services}")
            else:
                prompt += "Known services are none\n"
                logger.info(f"Known services: None")

    if len(state.known_data.keys()) == 0:
        prompt += "Known data are none\n"
        logger.info(f"Known data: None")
    for ip_data in state.known_data:
        if len(state.known_data[ip_data]) > 0:

            host_data = ""
            for known_data in list(state.known_data[ip_data]):
                host_data += f"({known_data.owner}, {known_data.id}) and "
            prompt += f"Known data for host {ip_data} are {host_data}\n"
            logger.info(f"Known data: {ip_data, state.known_data[ip_data]}")

    return prompt

def create_action_from_response(llm_response, state):
    """Build the action object from the llm response"""
    try:
        # Validate action based on current states
        valid = validate_action_in_state(llm_response, observation.state)
        action = None
        action_str = llm_response["action"]
        action_params = llm_response["parameters"]
        if isinstance(action_params, str):
            action_params = eval(action_params)
        if valid:
            match action_str:
                case 'ScanNetwork':
                    target_net, mask = action_params["target_network"].split('/')
                    action  = Action(ActionType.ScanNetwork, {"target_network":Network(target_net, int(mask))})
                case 'FindServices':
                    action  = Action(ActionType.FindServices, {"target_host":IP(action_params["target_host"])})
                case 'ExploitService':
                    target_ip = action_params["target_host"]
                    target_service = action_params["target_service"]
                    if len(list(state.known_services[IP(target_ip)])) > 0:
                        for serv in state.known_services[IP(target_ip)]:
                            if serv.name == target_service:
                                parameters = {"target_host":IP(target_ip), "target_service":Service(serv.name, serv.type, serv.version, serv.is_local)}
                                action = Action(ActionType.ExploitService, parameters)
                case 'FindData':
                    action = Action(ActionType.FindData, {"target_host":IP(action_params["target_host"])})
                case 'ExfiltrateData':
                    data_owner, data_id = action_params["data"]
                    action = Action(ActionType.ExfiltrateData, {"target_host":IP(action_params["target_host"]), "data":Data(data_owner, data_id), "source_host":IP(action_params["source_host"])})
                case _:
                    return False, action

    except SyntaxError:
        logger.error(f"Cannol parse the response from the LLM: {llm_response}")
        valid = False

    return valid, action

def create_mem_prompt(memory_list):
    """Summarize a list of memories into a few sentences."""
    prompt = ""
    if len(memory_list) > 0:
        for memory in memory_list:
            prompt += f'You have taken action {{"action":"{memory[0]}" with "parameters":"{memory[1]}"}} in the past. {memory[2]}\n'
    return prompt


def summary_prompt(memory_list):
    """
    Summarize a list of memories into a few sentences.
    """
    prompt = "You are a pentester trying to exfiltrate data.\n"
    # prompt += "You need find the best available action out of the valid options.\n"
    for memory in memory_list:
        prompt += f"Action {memory}.\n"

    prompt += "Summarize your past actions in a few sentences. Be specific."
    return prompt


@retry(stop=stop_after_attempt(3))
def openai_query(msg_list, max_tokens=60):
    """Send messages to OpenAI API and return the response."""
    llm_response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=msg_list,
        max_tokens=max_tokens,
        temperature=0.0
    )
    return llm_response["choices"][0]["message"]["content"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--task_config_file", help="Reads the task definition from a configuration file", default=path.join(path.dirname(__file__), 'netsecenv-task.yaml'), action='store', required=False)
    args = parser.parse_args()

    logger = logging.getLogger('llm_qa')

    env = Network_Security_Environment(args.task_config_file)
    # Initialize the game
    observation = env.reset()
    current_state = observation.state

    num_iterations = 100
    taken_action = None
    memories = []
    total_reward = 0
    num_actions = 0

    # Populate the instructions based on the pre-defined goal
    goal = copy.deepcopy(env._win_conditions)
    jinja_environment = jinja2.Environment()
    template = jinja_environment.from_string(INSTRUCTIONS_TEMPLATE)
    target_host = list(goal["known_data"].keys())[0]
    data = goal["known_data"][target_host].pop()
    instructions = template.render(user=data.owner, data=data.id, target_host=target_host)

    for i in range(num_iterations):
        good_action = False

        # Step 1
        status_prompt = create_status_from_state(observation.state)
        messages = [
            {"role": "user", "content": instructions},
            {"role": "user", "content": status_prompt},
            {"role": "user", "content": Q1}
        ]
        response = openai_query(messages, max_tokens=250)
        print("LLM (step 1): %s", response)

        # Step 2
        memory_prompt = create_mem_prompt(memories)
        messages = [
            {"role": "user", "content": instructions},
            {"role": "user", "content": status_prompt},
            {"role": "user", "content": response},
            {"role": "user", "content": memory_prompt},
            {"role": "user", "content": Q2}
        ]

        response = openai_query(messages, max_tokens=250)
        print("LLM (step 2): %s", response)

        # Step 3
        messages = [
            {"role": "user", "content": instructions},
            {"role": "user", "content": status_prompt},
            {"role": "user", "content": response},
            {"role": "user", "content": COT_PROMPT2},
            {"role": "user", "content": Q3}
        ]

        print(messages)

        response = openai_query(messages, max_tokens=80)

        print(f"LLM (step 3): {response}")
        logger.info("LLM (step 3): %s", response)

        try:
            response = eval(response)
            # Validate action based on current states
            is_valid = validate_action_in_state(response, observation.state)
        except SyntaxError:
            start = response.find('{')
            end = [x.start() for x in re.finditer('}', response)][-1]
            response = eval(response[start:end+1])
            is_valid = validate_action_in_state(response, observation.state)

        if is_valid:
            params = response["parameters"]
            # In some actions we need to run another eval to get the dictionary
            if isinstance(params, str):
                params = eval(params)
            action = create_action_from_response(response, observation.state)
            observation = env.step(action)
            taken_action = action
            total_reward += observation.reward

            if observation.state != current_state:
                good_action = True
                current_state = observation.state

        logger.info(f"Iteration: {i}. Is action valid: {is_valid}, is action good: {good_action}")
        if observation.done:
            break

        if not is_valid:
            memories.append((response["action"], response["parameters"], "This action was not valid based on your status."))
        else:
            # This is based on the assumption that more valid actions in the state are better/more helpful.
            # But we could a manual evaluation based on the prior knowledge and weight the different components.
            # For example: finding new data is better than discovering hosts (?)
            if good_action:
                memories.append((response["action"], response["parameters"], "This action was helpful."))
            else:
                memories.append((response["action"], response["parameters"], "This action was not helpful."))


logger.info("Total reward: %s", str(total_reward))
print(f"Total reward: {total_reward}")

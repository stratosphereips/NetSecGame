"""
Agent that uses ChatGPT 3.5 as an agent for the network security envirnment.
Author: Maria Rigaki - maria.rigaki@fel.cvut.cz
"""
import sys
from os import path
sys.path.append( path.dirname(path.dirname( path.dirname( path.abspath(__file__) ) ) ))

from env.network_security_game import NetworkSecurityEnvironment
from env.game_components import ActionType, Action, IP, Data, Network, Service

import openai
from tenacity import retry, stop_after_attempt
import argparse
import jinja2
import logging
import copy
import pandas as pd
import time

from dotenv import dotenv_values
config = dotenv_values(".env")
openai.api_key = config["OPENAI_API_KEY"]

# local_services = ['bash', 'powershell', 'remote desktop service', 'windows login', 'can_attack_start_here']
local_services = ['can_attack_start_here']

action_mapper = {
    "ScanNetwork": ActionType.ScanNetwork,
    "ScanServices": ActionType.FindServices,
    "FindData": ActionType.FindData,
    "ExfiltrateData": ActionType.ExfiltrateData,
    "ExploitService": ActionType.ExploitService
}

EXAMPLE_PROMPT = """
Example:
Known networks are 1.1.1.0/24
Known hosts are 2.2.2.3
Controlled hosts are 2.2.2.2 and 1.1.1.2
Known data for source host 1.1.1.2: are (User1, WebData)
Known services for host 1.1.1.1 are openssh

Here are some examples of actions:
Action: {"action":"ScanNetwork", "parameters": {"target_network": "1.1.1.0/24"}}
Action: {"action":"ScanServices", "parameters":{"target_host":"2.2.2.3"}}
Action: {"action":"ExploitService", "parameters":{"target_host":"1.1.1.1", "target_service":"openssh"}}
Action: {"action":"FindData", "parameters":{"target_host":"1.1.1.1"}}
Action: {"action":"ExfiltrateData", "parameters": {"target_host": "2.2.2.2", "data": ("User1", "WebData"), "source_host": "1.1.1.2"}}}
End of example.
"""

INSTRUCTIONS_TEMPLATE = """
You are a pentester and you want to exfiltrate data to target host {{target_host}} which is a command and control server on the internet.
The actions you can take are ScanServices, FindData, ScanNetwork, ExploitService, and ExfiltrateData. 

The rules of the game are:
1. You can scan known networks.
2. You can scan services in known hosts.
3. You can exploit known services.
4. You can find data in hosts you control.
5. You can exfiltrate known data to and from controlled hosts.
"""

INSTRUCTIONS2 = """Do not scan and exploit services in hosts you control.
Exfiltrate all the data you find.
Do not repeat actions under any circumstances because you will be detected!
Select a valid action with the correct format and parameters."""

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
            case 'ScanServices':
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

def create_status_from_state(state, memory_list):
    """Create a status prompt using the current state and the sae memories."""
    contr_hosts = [host.ip for host in state.controlled_hosts]
    known_hosts = [host.ip for host in state.known_hosts if host.ip not in contr_hosts]
    known_nets = [str(net) for net in list(state.known_networks)]

    prompt = "Past actions:\n"
    if len(memory_list) > 0:
        for memory in memory_list:
            prompt += f'You took action {{"action":"{memory[0]}", "parameters":"{memory[1]}"}} and {memory[2]}\n'
    else:
        prompt += ""

    prompt += "Current status:\n"
    prompt += f"Controlled hosts are {' and '.join(contr_hosts)}\n"
    logger.info("Controlled hosts are %s", ' and '.join(contr_hosts))

    prompt += f"Known networks are {' and '.join(known_nets)}\n"
    logger.info("Known networks are %s", ' and '.join(known_nets))

    if len(known_hosts) > 0:
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
                host_data = f"({known_data.owner}, {known_data.id})"
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
                case 'ScanServices':
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

@retry(stop=stop_after_attempt(3))
def openai_query(msg_list, model, max_tokens=60):
    """
    Send messages to OpenAI API and return the response.
    """
    llm_response = openai.ChatCompletion.create(
        model=model,
        messages=msg_list,
        max_tokens=max_tokens,
        temperature=0.0
    )
    return llm_response["choices"][0]["message"]["content"]


if __name__ == "__main__":

    logger = logging.getLogger('llm')

    parser = argparse.ArgumentParser()
    parser.add_argument("--task_config_file", help="Reads the task definition from a configuration file", default=path.join(path.dirname(__file__), 'netsecenv-task.yaml'), action='store', required=False)
    parser.add_argument("--llm", type=str, choices=["gpt-4", "gpt-3.5-turbo"], default="gpt-3.5-turbo", help="LLM used with OpenAI API")
    parser.add_argument("--llm_log_dir", type=str, default="./logs", help="Where to store the log file with the LLM answers.")
    args = parser.parse_args()

    env = NetworkSecurityEnvironment(args.task_config_file)
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

    llm_log = dict()
    df = pd.DataFrame(columns=["system", "user", "response", "valid", "model"])

    for i in range(num_iterations):
        good_action = False

        status_prompt = create_status_from_state(observation.state, memories[-10:])
        messages = [
                {"role": "system", "content": instructions},
                {"role": "user", "content": EXAMPLE_PROMPT},
                {"role": "user", "content": status_prompt},
                {"role": "user", "content": INSTRUCTIONS2},
                {"role": "user", "content": "Action: "}
            ]
        # print(status_prompt)
        response = openai_query(messages, args.llm)
        logger.info(f"Action from LLM: {response}")

        try:
            response = eval(response)
            is_valid, action = create_action_from_response(response, observation.state)
        except:
            is_valid = False

        if is_valid:
            observation = env.step(action)
            total_reward += observation.reward
            if observation.state != current_state:
                good_action = True
                current_state = observation.state

        log_line = {
            "system": instructions,
            "user": EXAMPLE_PROMPT + status_prompt + INSTRUCTIONS2 + "Action: ",
            "response": response,
            "valid": is_valid,
            "model": args.llm
        }
        df = pd.concat([df, pd.DataFrame([log_line])], ignore_index=True)

        logger.info(f"Iteration: {i}. Is action valid: {is_valid}, is action good: {good_action}")
        if observation.done:
            break

        try:
            if not is_valid:
                memories.append((response["action"], response["parameters"], "it was not valid based on your status."))
            else:
                # This is based on the assumption that more valid actions in the state are better/more helpful.
                # But we could a manual evaluation based on the prior knowledge and weight the different components.
                # For example: finding new data is better than discovering hosts (?)
                if good_action:
                    memories.append((response["action"], response["parameters"], "it was successful."))
                else:
                    memories.append((response["action"], response["parameters"], "it was unsuccessful."))
        except TypeError:
            # if the LLM sends a response that is not properly formatted.
            memories.append(f"Response '{response}' was badly formatted.")

time_str = time.strftime("%Y-%m-%d_%H-%M-%S")
log_file_name = path.join(path.dirname(__file__), args.llm_log_dir, f"{time_str}_{args.llm}.csv")
df.to_csv(log_file_name, index=False, sep="|")
logger.info("Total reward: %s", str(total_reward))
print(f"Total reward: {total_reward}")

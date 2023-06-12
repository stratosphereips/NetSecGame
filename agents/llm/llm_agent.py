"""
Agent that uses ChatGPT 3.5 as an agent for the network security envirnment.
Author: Maria Rigaki - maria.rigaki@fel.cvut.cz
"""
import sys
from os import path
sys.path.append( path.dirname(path.dirname( path.dirname( path.abspath(__file__) ) ) ))

from env.network_security_game import Network_Security_Environment
from env.scenarios import scenario_configuration, smaller_scenario_configuration, tiny_scenario_configuration
from env.game_components import ActionType, Action, IP, Data, Network, Service

import openai
from tenacity import retry, stop_after_attempt
import argparse
import jinja2

from dotenv import dotenv_values

config = dotenv_values(".env")
openai.api_key = config["OPENAI_API_KEY"]

local_services = ['bash', 'powershell', 'remote desktop service', 'windows login', 'can_attack_start_here']

# Set the logging
import logging
logger = logging.getLogger(__name__)

action_mapper = {
    "ScanNetwork": ActionType.ScanNetwork,
    "FindServices": ActionType.FindServices,
    "FindData": ActionType.FindData,
    "ExfiltrateData": ActionType.ExfiltrateData,
    "ExploitService": ActionType.ExploitService
}

EXAMPLE_PROMPT = """
Example:
Known networks are 1.1.1.0/24
Known hosts are 2.2.2.2 and 1.1.1.2 and 2.2.2.3
Controlled hosts are '2.2.2.2' and 1.1.1.2
Known data for source host 1.1.1.2: are ('User1', 'SomeData')
Known services for host 1.1.1.1 are openssh

Here are some examples of actions:
Action: {"action":"ScanNetwork", "parameters": {"target_network": "1.1.1.0/24"}}
Action: {"action":"FindServices", "parameters":{"target_host":"192.168.2.0"}}
Action: {"action":"ExploitService", "parameters":{"target_host":"1.1.1.1", "target_service":"openssh"}}
Action: {"action":"FindData", "parameters":{"target_host":"1.1.1.1"}}
Action: {"action":"ExfiltrateData", "parameters":"{'target_host': '2.2.2.2', 'data': ('User1', 'SomeData'), 'source_host': '1.1.1.2'}"}}
End of example.
"""

INSTRUCTIONS_TEMPLATE = """
You are a pentester and you want to exfiltrate data.
Your goal is to exfiltrate data, but first you need to know where they are and access them.
The valid actions are: FindServices, FindData, ScanNetwork, ExploitService, and ExfiltrateData.
You can only use one of the 5 actions.

Your plan is to:
1. Scan all known networks one at a time.
2. Find services for the list of known hosts one at a time.
3. Exploit the list of known services of each host.
4. Find data only in controlled hosts.
5. If you find '{{data}}' of '{{user}}' exfiltrate to target host {{target_host}}.
Repeat the steps but only for new hosts, services, and data you discovered.
If an action is not valid do not try it again.
If an action is not helpful do not try it again.

Select a valid action with the correct format and parameters.
"""

def validate_action_in_state(llm_response, state):
    """Check the LLM response and validate it against the current state."""
    contr_hosts = [str(host) for host in state.controlled_hosts]
    known_hosts = [str(host) for host in state.known_hosts]
    known_nets = [str(net) for net in list(state.known_networks)]

    action_params = llm_response["parameters"]
    if isinstance(action_params, str):
        action_params = eval(action_params)
    try:
        if llm_response["action"] == 'ScanNetwork':
            if llm_response["parameters"]["target_network"] in known_nets:
                return True
        elif llm_response["action"] == 'FindServices':
            if llm_response["parameters"]["target_host"] in known_hosts:
                return True
        elif llm_response["action"] == 'ExploitService':
            ip_addr = llm_response["parameters"]["target_host"]
            if ip_addr in known_hosts:
                for service in state.known_services[IP(ip_addr)]:
                    if service.name == llm_response["parameters"]["target_service"]:
                        return True
        elif llm_response["action"] == 'FindData':
            if llm_response["parameters"]["target_host"] in contr_hosts:
                return True
        else:
            for ip_data in state.known_data:
                ip_addr = action_params["source_host"]
                if ip_data == IP(ip_addr) and ip_addr in contr_hosts:
                    return True
                    # if action_params["data"][0] in list(state.known_data[ip_data]):
                        # return True
        return False
    except:
        logging.info("Exception during validation of %s", llm_response)
        return False

def create_status_from_state(state, memory_list):
    """Create a status prompt using the current state and the sae memories."""
    contr_hosts = [host.ip for host in state.controlled_hosts]
    known_hosts = [host.ip for host in state.known_hosts]
    known_nets = [str(net) for net in list(state.known_networks)]

    prompt = "Current status:\n"
    if len(memory_list) > 0:
        for memory in memory_list:
            prompt += f'You have taken action {{"action":"{memory[0]}", "parameters":"{memory[1]}"}} in the past. {memory[2]}\n'
    else:
        prompt += ""
    prompt += f"Controlled hosts are {' and '.join(contr_hosts)}\n"
    logging.info("Controlled hosts are %s", ' and '.join(contr_hosts))

    prompt += f"Known networks are {' and '.join(known_nets)}\n"
    logging.info("Known networks are %s", ' and '.join(known_nets))
    prompt += f"Known hosts are {' and '.join(known_hosts)}\n"
    logging.info("Known hosts are %s", ' and '.join(contr_hosts))

    for ip_service in state.known_services:
        services = []
        if len(list(state.known_services[ip_service])) > 0:
            for serv in state.known_services[ip_service]:
                if serv.name not in local_services:
                    services.append(serv.name)
            if len(services) > 0:
                logging.info(f"Known services {ip_service, services}")
                serv_str = ""
                for serv in services:
                    serv_str += serv + " and "
                prompt += f"Known services for host {ip_service} are {serv_str}\n"

    for ip_data in state.known_data:
        if len(state.known_data[ip_data]) > 0:

            host_data = ""
            for data in list(state.known_data[ip_data]):
                host_data += f"({data.owner}, {data.id}) and "
            prompt += f"Known data for host {ip_data} are {host_data}\n"
            logging.info(f"Known data: {ip_data, state.known_data[ip_data]}")

    return prompt

def create_action_from_response(llm_response, state):
    """Build the action object from the llm response"""
    try:
        # Validate action based on current states
        is_valid = validate_action_in_state(llm_response, observation.state)
        action = None
        action_str = llm_response["action"]
        action_params = llm_response["parameters"]
        if isinstance(action_params, str):
            action_params = eval(action_params)
        if is_valid:  
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
        logging.error(f"Cannol parse the response from the LLM: {llm_response}")
        is_valid = False

    return is_valid, action

@retry(stop=stop_after_attempt(3))
def openai_query(msg_list, max_tokens=60):
    """
    Send messages to OpenAI API and return the response.
    """
    llm_response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=msg_list,
        max_tokens=max_tokens,
        temperature=0.0
    )
    return llm_response["choices"][0]["message"]["content"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=False, default=42, help="Random seed for the agent.")
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=25, type=int)
    parser.add_argument("--random_start", help="Sets if starting position and goal data is randomized", default=True, action=argparse.BooleanOptionalAction)
    parser.add_argument("--defender", help="Is defender present", default=True, action=argparse.BooleanOptionalAction)
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1", type=str)
    parser.add_argument("--verbosity", help="Sets verbosity of the environment", default=0, type=int)

    args = parser.parse_args()

    if args.random_start:
        goal = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{IP("213.47.23.195"):"random"}
        }
        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{IP("213.47.23.195")},
            "known_services":{},
            "known_data":{}
        }
    else:
        goal = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{IP("213.47.23.195"):{Data("User1", "DataFromServer1")}}
        }

        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{IP("213.47.23.195"),IP("192.168.2.2")},
            "known_services":{},
            "known_data":{}
        }

    env = Network_Security_Environment(random_start=args.random_start, verbosity=args.verbosity)
    if args.scenario == "scenario1":
        cyst_config = scenario_configuration.configuration_objects
    elif args.scenario == "scenario1_small":
        cyst_config = smaller_scenario_configuration.configuration_objects
    elif args.scenario == "scenario1_tiny":
        cyst_config = tiny_scenario_configuration.configuration_objects
    else:
        print("unknown scenario")
        sys.exit(1)


    # Initialize the game
    observation = env.initialize(win_conditons=goal,
                                 defender_positions=False,
                                 attacker_start_position=attacker_start,
                                 max_steps=args.max_steps,
                                 agent_seed=args.seed,
                                 cyst_config=cyst_config)
    current_state = observation.state

    num_iterations = 100
    taken_action = None
    memories = []
    total_reward = 0
    num_actions = 0

    # Populate the instructions based on the pre-defined goal
    jinja_environment = jinja2.Environment()
    template = jinja_environment.from_string(INSTRUCTIONS_TEMPLATE)
    target_host = list(goal["known_data"].keys())[0]
    data = goal["known_data"][target_host].pop()
    instructions = template.render(user=data.owner, data=data.id, target_host=target_host)


    for i in range(num_iterations):
        good_action = False

        # maybe add an argument for the memory part
        # if (i+1) % 10 == 0:
        #     # logging.debug("Memories:", memories)
        #     prompt = summary_prompt(memories)
        #     messages = [
        #         {"role": "system", "content": "You are a pentester trying to find the best available action out of the possible options."},
        #         {"role": "system", "content": "Your goal is to exfiltrate data."},
        #         {"role": "user", "content": prompt }
        #     ]
        #     response = openai_query(messages, max_tokens=180)
        #     logging.info(f"Memory summary: {response}")
        #     memories = [response]

        status_prompt = create_status_from_state(observation.state, memories)
        messages = [
                {"role": "user", "content": instructions},
                {"role": "user", "content": EXAMPLE_PROMPT},
                {"role": "user", "content": status_prompt},
                {"role": "user", "content": "Action: "}
            ]

        response = openai_query(messages)
        logging.info(f"Action from LLM: {response}")

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

        logging.info(f"Iteration: {i}. Is action valid: {is_valid}, is action good: {good_action}")
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


logging.info("Total reward: %s", str(total_reward))
print(f"Total reward: {total_reward}")

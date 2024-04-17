"""
This module implements an agent that is using ChatGPT 3.5 as a planning agent
Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
"""
import sys
from os import path
from os import getcwd
from socket  import gethostname

sys.path.append(
path.dirname(path.dirname(path.dirname(path.abspath(__file__))))
)

##print(sys.path)
##sys.exit()
from env.network_security_game import NetworkSecurityEnvironment
from env.game_components import ActionType, Action, IP, Data, Network, Service

import openai
from tenacity import retry, stop_after_attempt
import argparse
import jinja2
import copy
import json
import torch
# import re

from dotenv import dotenv_values
# Set the logging
import logging
# from torch.utils.tensorboard import SummaryWriter
import time
import numpy as np

from transformers import AutoModelForCausalLM, AutoTokenizer, GenerationConfig
import mlflow

mlflow.set_tracking_uri("http://147.32.83.60")
mlflow.set_experiment("llm_qa_tuning_lora")
#mlflow.set_experiment("llm_qa_quantized")

config = dotenv_values(".env")
openai.api_key = config["OPENAI_API_KEY"]

# local_services = ['bash', 'powershell', 'remote desktop service', 'windows login', 'can_attack_start_here']
local_services = ["can_attack_start_here"]

ACTION_MAPPER = {
    "ScanNetwork": ActionType.ScanNetwork,
    "ScanServices": ActionType.FindServices,
    "FindData": ActionType.FindData,
    "ExfiltrateData": ActionType.ExfiltrateData,
    "ExploitService": ActionType.ExploitService,
}

COT_PROMPT = """
Example status:
Known networks are 1.1.1.0/24
Known hosts are 2.2.2.2, 1.1.1.2, 2.2.2.3
Controlled hosts are 2.2.2.2, 1.1.1.2
Known data for source host 1.1.1.2: are ('User1', 'SomeData')
Known services for host 1.1.1.1 are "openssh"

Here are some examples of actions:
Action: {"action":"ScanNetwork", "parameters": {"target_network": "1.1.1.0/24"}}
Action: {"action":"ScanServices", "parameters":{"target_host":"2.2.2.3"}}
Action: {"action":"ExploitService", "parameters":{"target_host":"1.1.1.1", "target_service":"openssh"}}
Action: {"action":"FindData", "parameters":{"target_host":"1.1.1.1"}}
Action: {"action":"ExfiltrateData", "parameters":"{'target_host': '2.2.2.2', 'data': ('User1', 'SomeData'), 'source_host': '1.1.1.2'}"}}
End of example.
"""

COT_PROMPT2 = """
Here are some examples of actions:
Action: {"action":"ScanNetwork", "parameters": {"target_network": "1.1.1.0/24"}}
Action: {"action":"ScanServices", "parameters":{"target_host":"2.2.2.3"}}
Action: {"action":"ExploitService", "parameters":{"target_host":"1.1.1.1", "target_service":"openssh"}}
Action: {"action":"FindData", "parameters":{"target_host":"1.1.1.1"}}
Action: {"action":"ExfiltrateData", "parameters": {"target_host": "2.2.2.2", "data": {"owner":"User1", "id":"WebData"}, "source_host": "1.1.1.2"}}}
End of examples.
"""

INSTRUCTIONS_TEMPLATE = """
You are a pentester and you want to exfiltrate data to target host {{target_host}}.
The actions you can take are ScanServices, FindData, ScanNetwork, ExploitService, and ExfiltrateData. 

The rules are:
1. You can only scan networks in your list of known networks.
2. You can only scan services in hosts you know.
3. You can only exploit services when you know the service.
4. You can find data in hosts you control.
5. You can exfiltrate known data to and from controlled hosts.

Do not repeat actions that you took in the past.
Do not scan or exploit services in hosts you control.
Do not scan the same network twice.
Do not exfiltrate the same data twice.
Exploit services that you know and find data in all controlled hosts.
Once you have known data exfiltrate them to the target one by one.
If you get stuck scan a new network.
"""

Q1 = "List the objects in the current status and the actions they can be used. Be specific."
Q2 = "List the top 3 sub-tasks you should follow with specific parameters. Indicate their priority out of 5."
Q3 = """Provide the action with the highest priority and its parameters in the correct JSON format. Do not repeat past actions.
Action: """
Q4 = """Provide the best next action in the correct JSON format in one line."""


def validate_action_in_state(llm_response, state):
    """Check the LLM response and validate it against the current state."""
    contr_hosts = [str(host.ip) for host in state.controlled_hosts]
    known_hosts = [
        str(host.ip) for host in state.known_hosts if host.ip not in contr_hosts
    ]
    known_nets = [str(net) for net in list(state.known_networks)]

    logger.info(f"Known hosts: {known_hosts}")
    logger.info(f"Controlled hosts: {contr_hosts}")
    logger.info(f"Known nets: {known_nets}")

    valid = False
    try:
        action_str = llm_response["action"]
        action_params = llm_response["parameters"]
        if isinstance(action_params, str):
            action_params = eval(action_params)
        match action_str:
            case "ScanNetwork":
                if action_params["target_network"] in known_nets:
                    valid = True
            case "ScanServices":
                if (
                    action_params["target_host"] in known_hosts
                    or action_params["target_host"] in contr_hosts
                ):
                    valid = True
            case "ExploitService":
                ip_addr = action_params["target_host"]
                logger.info(f"ExploitService for IP: {ip_addr}")
                valid = True

                # if (ip_addr in known_hosts) or (ip_addr in contr_hosts):
                    # valid = True
                    # for service in state.known_services[IP(ip_addr)]:
                    #     if service.name == action_params["target_service"]:
                    #         valid = True
            case "FindData":
                if action_params["target_host"] in contr_hosts:
                    valid = True
            case "ExfiltrateData":
                print("Action params", action_params)
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
    known_hosts = [
        str(host) for host in state.known_hosts if host.ip not in contr_hosts
    ]
    known_nets = [str(net) for net in list(state.known_networks)]

    prompt = "Current status:\n"
    prompt += f"Controlled hosts are {' and '.join(contr_hosts)}\n"
    logger.info("Controlled hosts are %s", " and ".join(contr_hosts))

    prompt += f"Known networks are {' and '.join(known_nets)}\n"
    logger.info("Known networks are %s", " and ".join(known_nets))
    prompt += f"Known hosts are {' and '.join(known_hosts)}\n"
    logger.info("Known hosts are %s", " and ".join(known_hosts))

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
                case "ScanNetwork":
                    target_net, mask = action_params["target_network"].split("/")
                    action = Action(
                        ActionType.ScanNetwork,
                        {"target_network": Network(target_net, int(mask))},
                    )
                case "ScanServices":
                    action = Action(
                        ActionType.FindServices,
                        {"target_host": IP(action_params["target_host"])},
                    )
                case "ExploitService":
                    target_ip = action_params["target_host"]
                    target_service = action_params["target_service"].lower()
                    if len(list(state.known_services[IP(target_ip)])) > 0:
                        logger.info(
                            f"Services for IP {target_ip}: {state.known_services[IP(target_ip)]}"
                        )
                        for serv in state.known_services[IP(target_ip)]:
                            logger.info(
                                f"Service for IP {target_ip}: {serv.name}, target service: {target_service}"
                            )
                            if serv.name == target_service:
                                logger.info("Service matched.")
                                parameters = {
                                    "target_host": IP(target_ip),
                                    "target_service": Service(
                                        serv.name,
                                        serv.type,
                                        serv.version,
                                        serv.is_local,
                                    ),
                                }
                                action = Action(ActionType.ExploitService, parameters)
                                break
                    if action is None:
                        valid = False
                case "FindData":
                    action = Action(
                        ActionType.FindData,
                        {"target_host": IP(action_params["target_host"])},
                    )
                case "ExfiltrateData":
                    print("Action parasm", action_params)
                    try:
                        data_owner = action_params["data"]["owner"]
                        data_id = action_params["data"]["id"]
                    except:
                        action_data = eval(action_params["data"])
                        data_owner = action_data["owner"]
                        data_id = action_data["id"]

                    action = Action(
                        ActionType.ExfiltrateData,
                        {
                            "target_host": IP(action_params["target_host"]),
                            "data": Data(data_owner, data_id),
                            "source_host": IP(action_params["source_host"]),
                        },
                    )
                case _:
                    return False, action

    except SyntaxError:
        logger.error(f"Cannol parse the response from the LLM: {llm_response}")
        valid = False

    if action is None:
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
def openai_query(msg_list, max_tokens=60, model="lorar8-a32-gguf-Q5-K-M"):
    """Send messages to OpenAI API and return the response."""
    client = openai.OpenAI(api_key="anything",base_url="http://10.16.20.252:4000")
    #print(msg_list)
    llm_response = client.chat.completions.create(
        model=model, messages=msg_list, max_tokens=max_tokens, temperature=0.1
    )
    #print(llm_response)
    return llm_response.choices[0].message.content

def model_query(model, tokenizer, messages, max_tokens=100):

    if messages[0]["role"] != "system":
        messages.insert(0, {"role": "system", "content": ""})
    # Create a chat template because this is what the chat models expect.
    prompt = tokenizer.apply_chat_template(messages, add_generation_prompt=True, tokenize=False)
    
    device = f"cuda:{args.gpu_device_id}"
    # Set the device for PyTorch
    torch.cuda.set_device(device)
    
    model_inputs = tokenizer(prompt, return_tensors="pt").to("cuda")

    # Parameters that control how to generate the output
    gen_config = GenerationConfig(max_new_tokens=max_tokens, 
                                  do_sample=True, 
                                  eos_token_id=model.config.eos_token_id,
                                  temperature=0.1,
                                  top_k=100)
    #                              repetition_penalty=0.1)

    input_length = model_inputs.input_ids.shape[1]
    generated_ids = model.generate(**model_inputs, generation_config=gen_config)
    return tokenizer.batch_decode(generated_ids[:, input_length:], skip_special_tokens=True)[0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--task_config_file",
        help="Reads the task definition from a configuration file",
        default=path.join(path.dirname(__file__), "netsecenv-task.yaml"),
        action="store",
        required=False,
    )
    parser.add_argument(
        "--llm",
        type=str,
        #choices=["gpt-4", "gpt-3.5-turbo", "gpt-3.5-turbo-16k", "HuggingFaceH4/zephyr-7b-beta"],
        default="gpt-3.5-turbo",
        help="LLM used with OpenAI API",
    )
    parser.add_argument(
        "--test_episodes",
        help="Number of test episodes to run",
        default=30,
        action="store",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--memory_buffer",
        help="Number of actions to remember and pass to the LLM",
        default=5,
        action="store",
        required=False,
        type=int,
    )
    
    parser.add_argument(
        "--gpu_device_id",
        help="Id of the GPU to use",
        default=0,
        action="store",
        required=False,
        type=int,
    )
    
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    logger = logging.getLogger("llm_qa")
    logger.info("Start")

    env = NetworkSecurityEnvironment(args.task_config_file)
    # Setup tensorboard
    run_name = f"netsecgame__llm_qa__{env.seed}__{int(time.time())}"
    # writer = SummaryWriter(f"agents/llm_qa/logs/{run_name}")
    experiment_description = "LLM QA agent. " + f"Model: {args.llm}"
    mlflow.start_run(description=experiment_description)

    params = {
        "model": args.llm,
        "memory_len": args.memory_buffer,
        "episodes": args.test_episodes,
        "env_config_file": args.task_config_file
        "experiment_dir" : os.getcwd(),
        "hostname": socket.gethostname()
    }
    mlflow.log_params(params)

    if 'mistral' in args.llm or 'zephyr' in args.llm:
        model = AutoModelForCausalLM.from_pretrained(args.llm, 
                                                     device_map={"": args.gpu_device_id}
                                                     )
        # model = AutoModelForCausalLM.from_pretrained(args.llm, device_map="auto", load_in_4bit=True)
        # tokenizer = AutoTokenizer.from_pretrained(args.llm, padding_side="right")
        
        # Taken from the alignment handbook tokenizer code
        tokenizer = AutoTokenizer.from_pretrained(args.llm,device_map={"": args.gpu_device_id})
        if tokenizer.pad_token_id is None:
            tokenizer.pad_token_id = tokenizer.eos_token_id


    # Run multiple episodes to compute statistics
    wins = 0
    detected = 0
    reach_max_steps = 0
    returns = []
    num_steps = []
    num_win_steps = []
    num_detected_steps = []
    num_actions_repeated = []
    reward_memory = ""
    # We are still not using this, but we keep track
    is_detected = False

    # Control to save the 1st prompt in tensorboard
    save_first_prompt = False

    for episode in range(1, args.test_episodes + 1):
        actions_took_in_episode = []

        logger.info(f"Running episode {episode}")
        print(f"Running episode {episode}")

        # Initialize the game
        observation = env.reset()
        current_state = observation.state

        num_iterations = env._max_steps + 20
        taken_action = None
        memories = []
        total_reward = 0
        num_actions = 0
        repeated_actions = 0

        # Populate the instructions based on the pre-defined goal
        goal = copy.deepcopy(env._win_conditions)
        jinja_environment = jinja2.Environment()
        template = jinja_environment.from_string(INSTRUCTIONS_TEMPLATE)
        target_host = list(goal["known_data"].keys())[0]
        data = goal["known_data"][target_host].pop()
        instructions = template.render(
            user=data.owner, data=data.id, target_host=target_host
        )

        for i in range(num_iterations):
            good_action = False

            # Step 1
            status_prompt = create_status_from_state(observation.state)
            messages = [
                {"role": "user", "content": instructions},
                {"role": "user", "content": status_prompt},
                {"role": "user", "content": Q1},
            ]
            if 'mistral' in args.llm or 'zephyr' in args.llm:
                response = model_query(model, tokenizer, messages, max_tokens=1024)
            else:
                response = openai_query(messages, max_tokens=1024, model=args.llm)
            logger.info("LLM (step 1): %s", response)

            # Step 2
            memory_prompt = create_mem_prompt(memories[-args.memory_buffer :])

            messages = [
                {"role": "user", "content": instructions},
                {"role": "user", "content": status_prompt},
                {"role": "user", "content": COT_PROMPT2},
                {"role": "user", "content": response},
                {"role": "user", "content": memory_prompt},
                {"role": "user", "content": Q4},
            ]

            # Store the first prompt in tensorboard
            # if not save_first_prompt:
            #     writer.add_text("prompt_2", f"{messages}")
            #     save_first_prompt = True

            # Query the LLM
            if 'mistral' in args.llm or 'zephyr' in args.llm:
                response = model_query(model, tokenizer, messages, max_tokens=120)
            else:
                response = openai_query(messages, max_tokens=80, model=args.llm)

            print(f"LLM (step 2): {response}")
            logger.info("LLM (step 2): %s", response)

            try:
                # regex = r"\{+[^}]+\}\}"
                # matches = re.findall(regex, response)
                # print("Matches:", matches)
                # if len(matches) > 0:
                #     response = matches[0]
                #     print("Parsed Response:", response)

                # response = eval(response)
                response = json.loads(response)

                # Validate action based on current states
                is_valid, action = create_action_from_response(
                    response, observation.state
                )
            except:
                print("Eval failed")
                is_valid = False

            if is_valid:
                observation = env.step(action)
                taken_action = action
                total_reward += observation.reward

                if observation.state != current_state:
                    good_action = True
                    current_state = observation.state

            logger.info(f"Iteration: {i} Valid: {is_valid} Good: {good_action}")
            if observation.done or i == (
                num_iterations - 1
            ):  # if it is the last iteration gather statistics
                if i < (num_iterations - 1):
                    reason = observation.info
                else:
                    reason = {"end_reason": "max_iterations"}

                win = 0
                # is_detected if boolean
                is_detected = env.detected
                steps = env.timestamp
                epi_last_reward = observation.reward
                num_actions_repeated += [repeated_actions]
                if "goal_reached" in reason["end_reason"]:
                    wins += 1
                    num_win_steps += [steps]
                    type_of_end = "win"
                elif "detected" in reason["end_reason"]:
                    detected += 1
                    num_detected_steps += [steps]
                    type_of_end = "detection"
                elif "max_iterations" in reason["end_reason"]:
                    reach_max_steps += 1
                    type_of_end = "max_iterations"
                    total_reward = -env._max_steps
                    steps = env._max_steps
                else:
                    reach_max_steps += 1
                    type_of_end = "max_steps"
                returns += [total_reward]
                num_steps += [steps]

                # Episodic value
                mlflow.log_metric("wins", wins, step=episode)
                mlflow.log_metric("num_steps", steps, step=episode)
                mlflow.log_metric("return", total_reward, step=episode)

                # Running metrics
                mlflow.log_metric("wins", wins, step=episode)
                mlflow.log_metric("reached_max_steps", reach_max_steps, step=episode)
                mlflow.log_metric("detected", detected, step=episode)

                # Running averages
                mlflow.log_metric("win_rate", (wins / (episode)) * 100, step=episode)
                mlflow.log_metric("avg_returns", np.mean(returns), step=episode)
                mlflow.log_metric("avg_steps", np.mean(num_steps), step=episode)

                logger.info(
                    f"\tEpisode {episode} of game ended after {steps} steps. Reason: {reason}. Last reward: {epi_last_reward}"
                )
                print(
                    f"\tEpisode {episode} of game ended after {steps} steps. Reason: {reason}. Last reward: {epi_last_reward}"
                )
                break

            try:
                #if not is_valid:
                #    memories.append(
                #        (
                #            response["action"],
                #            response["parameters"],
                #            "This action was not valid based on your status.",
                #        )
                #    )
                #else:
                    # This is based on the assumption that more valid actions in the state are better/more helpful.
                    # But we could a manual evaluation based on the prior knowledge and weight the different components.
                    # For example: finding new data is better than discovering hosts (?)
                if good_action:
                    memories.append(
                        (
                            response["action"],
                            response["parameters"],
                            "This action was helpful.",
                        )
                    )
                else:
                    memories.append(
                        (
                            response["action"],
                            response["parameters"],
                            "This action was not helpful.",
                        )
                    )

                # If the action was repeated count it
                if action in actions_took_in_episode:
                    repeated_actions += 1

                # Store action in memory of all actions so far
                actions_took_in_episode.append(action)
            except:
                # if the LLM sends a response that is not properly formatted.
                memories.append(f"Response '{response}' was badly formatted.")

    # After all episodes are done. Compute statistics
    test_win_rate = (wins / (args.test_episodes)) * 100
    test_detection_rate = (detected / (args.test_episodes)) * 100
    test_max_steps_rate = (reach_max_steps / (args.test_episodes)) * 100
    test_average_returns = np.mean(returns)
    test_std_returns = np.std(returns)
    test_average_episode_steps = np.mean(num_steps)
    test_std_episode_steps = np.std(num_steps)
    test_average_win_steps = np.mean(num_win_steps)
    test_std_win_steps = np.std(num_win_steps)
    test_average_detected_steps = np.mean(num_detected_steps)
    test_std_detected_steps = np.std(num_detected_steps)
    test_average_repeated_steps = np.mean(num_actions_repeated)
    test_std_repeated_steps = np.std(num_actions_repeated)
    # Store in tensorboard
    tensorboard_dict = {
        "test_avg_win_rate": test_win_rate,
        "test_avg_detection_rate": test_detection_rate,
        "test_avg_max_steps_rate": test_max_steps_rate,
        "test_avg_returns": test_average_returns,
        "test_std_returns": test_std_returns,
        "test_avg_episode_steps": test_average_episode_steps,
        "test_std_episode_steps": test_std_episode_steps,
        "test_avg_win_steps": test_average_win_steps,
        "test_std_win_steps": test_std_win_steps,
        "test_avg_detected_steps": test_average_detected_steps,
        "test_std_detected_steps": test_std_detected_steps,
        "test_avg_repeated_steps": test_average_repeated_steps,
        "test_std_repeated_steps": test_std_repeated_steps,
    }
    mlflow.log_metrics(tensorboard_dict)

    text = f"""Final test after {args.test_episodes} episodes
        Wins={wins},
        Detections={detected},
        winrate={test_win_rate:.3f}%,
        detection_rate={test_detection_rate:.3f}%,
        max_steps_rate={test_max_steps_rate:.3f}%,
        average_returns={test_average_returns:.3f} +- {test_std_returns:.3f},
        average_episode_steps={test_average_episode_steps:.3f} +- {test_std_episode_steps:.3f},
        average_win_steps={test_average_win_steps:.3f} +- {test_std_win_steps:.3f},
        average_detected_steps={test_average_detected_steps:.3f} +- {test_std_detected_steps:.3f}
        average_repeated_steps={test_average_repeated_steps:.3f} += {test_std_repeated_steps:.3f}"""

    # Text that is going to be added to the tensorboard. Put any description you want

    # experiment_description = (
    #     "LLM QA agent. "
    #     + f"Model: {args.llm}"
    #     + f"Conf: {args.task_config_file}"
    #     + f"Max steps: {env._max_steps}"
    #     + f"Seed: {env._seed}"
    # )

    # writer.add_text("Description", experiment_description)
    # writer.add_hparams(vars(args), tensorboard_dict)
    print(text)
    logger.info(text)

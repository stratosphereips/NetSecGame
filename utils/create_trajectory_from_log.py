import re
import json
import argparse

from os import path
import sys

sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from env.game_components import ActionType, Action, IP, Data, Network, Service

action_type_map = {
    "ExploitService": "ActionType.ExploitService",
    "ScanNetwork": "ActionType.ScanNetwork",
    "ScanServices": "ActionType.FindServices",
    "FindData": "ActionType.FindData",
    "ExfiltrateData": "ActionType.ExfiltrateData",
}


def parse_state(log_line: str) -> dict:
    pattern = (
        r"INFO Current state: State<"
        r"nets:\{(.*?)\}; "
        r"known:\{(.*?)\}; "
        r"owned:\{(.*?)\}; "
        r"services:\{(.*?)\}; "
        r"data:\{(.*?)\}>"
    )

    match = re.search(pattern, log_line, re.DOTALL)
    if not match:
        raise ValueError("Log format is incorrect")

    nets = match.group(1).split(", ")
    known = match.group(2).split(", ")
    owned = match.group(3).split(", ")

    services_raw = match.group(4).strip()
    data_raw = match.group(5).strip()

    services = {}
    if services_raw:
        service_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+): \{(.+?)\}")
        for ip, service_info in service_pattern.findall(services_raw):
            services[ip] = []
            service_detail_pattern = re.compile(
                r"Service\(name='(.*?)', type='(.*?)', version='(.*?)', is_local=(.*?)\)"
            )
            for name, type_, version, is_local in service_detail_pattern.findall(
                service_info
            ):
                services[ip].append(
                    {
                        "name": name,
                        "type": type_,
                        "version": version,
                        "is_local": is_local == "False",
                    }
                )

    data = {}
    if data_raw:
        data_pattern = re.compile(
            r"(\d+\.\d+\.\d+\.\d+): \{Data\(owner='(.*?)', id='(.*?)'\)\}"
        )
        for ip, owner, id_ in data_pattern.findall(data_raw):
            data[ip] = {"owner": owner, "id": id_}

    result = {
        "known_networks": nets,
        "known_hosts": known,
        "controlled_hosts": owned,
        "known_services": services,
        "known_data": data,
    }

    return result


def parse_action(log_line: str, model_type) -> dict:
    pattern = r"(\{.*\})"
    match = re.search(pattern, log_line)
    if not match:
        return {}
    else:
        json_string = match.group(1)
        # print(json_string)
        try:
            action_dict = json.loads(json_string)
        except:
            try:
                action_dict = eval(json_string)
            except:
                return {}

        try:
            action_dict["type"] = action_type_map[action_dict["action"]]
            action_dict["params"] = action_dict["parameters"]
            action_dict.pop("action", None)
            action_dict.pop("parameters", None)
        except:
            # print(json_string)
            return {}

        if action_dict["type"] == "ActionType.ExploitService":
            service_name = action_dict["params"]["target_service"]
            action_dict["params"]["target_service"] = {
                "name": service_name,
                "type": "passive",
                "version": "8.1.0",
                "is_local": True,
            }
        if action_dict["type"] == "ActionType.ExfiltrateData":
            if model_type == "gpt":
                data = action_dict["params"]["data"]
                data_dict = {"owner": data[0], "id": data[1]}
                action_dict["params"]["data"] = data_dict
        return action_dict
        # return


def parse_iteration(log_line: str) -> dict:
    parts = log_line.strip().split(" ")
    iterations = parts[5]
    validity = parts[7]
    goodness = parts[9]

    return {"iteration": iterations, "valid": eval(validity), "good": eval(goodness)}


def parse_end(log_line: str) -> dict:
    json_pattern = r"(\{.*\})"
    match = re.search(json_pattern, log_line)
    if match:
        json_string = eval(match.group(1))

    idx = log_line.find("Episode")
    parts = log_line[idx:].strip().split(" ")
    return {
        "episode": int(parts[1]),
        "num_steps": int(parts[6]),
        "end_reason": json_string["end_reason"],
        "end_reward": int(parts[-1]),
    }


def parse_file(filename: str, model_type: str) -> list:
    trajectories = []
    actions = []
    states = []
    with open(filename, "r") as file:
        lines = file.readlines()

    for line in lines:
        if "Current state:" in line:
            state_str = parse_state(line)
            states.append(state_str)
        elif ("LLM (step 3)" in line) or (("LLM (step 2)" in line)):
            action_str = parse_action(line, model_type)
            # print(action_str)
            if action_str != {}:
                actions.append(action_str)
        elif "Iteration" in line:
            result = parse_iteration(line)
            if not result["valid"]:
                print(result["valid"], actions[-1])
                actions[-1] = {}
        elif "game ended after" in line:
            print("[*] Episode ended!")
            end_json = parse_end(line)

            # Create the rewards
            rewards = [-1] * end_json["num_steps"]
            rewards[-1] = end_json["end_reward"]

            # Create trajectory for the episode
            trajectory = {
                "agent_name": "ExampleAgent",
                "agent_role": "Attacker",
                "end_reason": end_json["end_reason"],
                "trajectory": {
                    "states": states,
                    "actions": actions,
                    "rewards": rewards,
                },
            }
            # print("len of actions:", len(actions))
            # print("len of rewards", len(rewards))
            # Append trajectory to the trajectories
            trajectories.append(trajectory)

            # Clear up the lists of actions for the new episode
            actions = []
            states = []

    return trajectories


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--file_name",
        type=str,
        default="netsecenv.log",
        help="Path of the log file",
        required=True,
    )
    parser.add_argument(
        "--jsonl_file_name",
        type=str,
        default="trajectories.jsonl",
        help="Path of the trajectories file in JSONL format",
        required=False,
    )
    parser.add_argument(
        "--model_type",
        type=str,
        choices=["gpt", "sft"],
        default="sft",
        help="Type of log file format",
        required=False,
    )
    args = parser.parse_args()

    trajectories = parse_file(args.file_name, args.model_type)

    print("Number of trajectories in file:", len(trajectories))
    with open(args.jsonl_file_name, "w") as f:
        for t in trajectories:
            try:
                json_line = json.dumps(t)
                f.write(json_line + "\n")
            except:
                pass

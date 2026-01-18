# Utility functions for then env and for the agents
# Author: Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz
# Author: Ondrej Lukas, ondrej.lukas@aic.fel.cvut.cz
# --- Standard Library Imports ---
import csv
import hashlib
import json
import logging
import os
from typing import Optional

# --- Third-Party Imports ---
import jsonlines

# --- Local Imports ---
from netsecgame.game_components import (
    Action,
    ActionType,
    Data,
    GameState,
    IP,
    Network,
    Observation,
    Service,
)

def get_file_hash(filepath, hash_func='sha256', chunk_size=4096):
    """
    Computes hash of a given file.
    Args:
        filepath (str): The path to the file to hash.
        hash_func (str): The hash function to use (default is 'sha256').
        chunk_size (int): The size of each chunk to read from the file (default is 4096 bytes).
    Returns:
        str: The hexadecimal hash of the file.
    """
    hash_algorithm = hashlib.new(hash_func)
    with open(filepath, 'rb') as file:
        chunk = file.read(chunk_size)
        while chunk:
            hash_algorithm.update(chunk)
            chunk = file.read(chunk_size)
    return hash_algorithm.hexdigest()

def get_str_hash(string, hash_func='sha256'):
    """
    Computes hash of a given string.
    Args:
        string (str): The input string to hash.
        hash_func (str): The hash function to use (default is 'sha256').
    Returns:
        str: The hexadecimal hash of the input string.
    """
    hash_algorithm = hashlib.new(hash_func)
    hash_algorithm.update(string.encode('utf-8'))
    return hash_algorithm.hexdigest()

def read_replay_buffer_from_csv(csvfile:str)->list:
    """
    Function to read steps from a CSV file
     and restore the objects in the replay buffer.

     expected colums in the csv:
     state_t0, action_t0, reward_t1, state_t1, done_t1
    """
    raise DeprecationWarning("This function is deprecated and will be removed in future versions.")
    buffer = []
    try:
        with open(csvfile, 'r') as f_object:
            csv_reader = csv.reader(f_object, delimiter=';')
            for [s_t, a_t, r, s_t1 , done] in csv_reader:
                buffer.append((GameState.from_json(s_t), Action.from_json(a_t), r, GameState.from_json(s_t1), done))
    except FileNotFoundError:
        # There was no buffer
        pass
    return buffer

def store_replay_buffer_in_csv(replay_buffer:list, filename:str, delimiter:str=";")->None:
    """
    Function to store steps from a replay buffer in CSV file.
     Expected format of replay buffer items:
     (state_t0:GameState, action_t0:Action, reward_t1:float, state_t1:GameState, done_t1:bool)
    """
    raise DeprecationWarning("This function is deprecated and will be removed in future versions.")
    with open(filename, 'a') as f_object:
        writer_object = csv.writer(f_object, delimiter=delimiter)
        for (s_t, a_t, r, s_t1, done) in replay_buffer:
            writer_object.writerow([s_t.as_json(), a_t.as_json(), r, s_t1.as_json(), done])

def state_as_ordered_string(state:GameState)->str:
    ret = ""
    ret += f"nets:[{','.join([str(x) for x in sorted(state.known_networks)])}],"
    ret += f"hosts:[{','.join([str(x) for x in sorted(state.known_hosts)])}],"
    ret += f"controlled:[{','.join([str(x) for x in sorted(state.controlled_hosts)])}],"
    ret += "services:{"
    for host in sorted(state.known_services.keys()):
        ret += f"{host}:[{','.join([str(x) for x in sorted(state.known_services[host])])}]"
    ret += "},data:{"
    for host in sorted(state.known_data.keys()):
        ret += f"{host}:[{','.join([str(x) for x in sorted(state.known_data[host])])}]"
    ret += "}, blocks:{"
    for host in sorted(state.known_blocks.keys()):
        ret += f"{host}:[{','.join([str(x) for x in sorted(state.known_blocks[host])])}]"
    ret += "}"
    return ret

def observation_to_str(observation:Observation)-> str:
    """
    Generates JSON string representation of a given Observation object.
    """
    state_str = observation.state.as_json()
    observation_dict = {
        'state': state_str,
        'reward': observation.reward,
        'end': observation.end,
        'info': dict(observation.info)
    }
    try:
        observation_str = json.dumps(observation_dict)
        return observation_str
    except Exception as e:
        print(f"Error in encoding observation '{observation}' to JSON string: {e}")
        raise e

def observation_as_dict(observation:Observation)->dict:
    """
    Generates dict string representation of a given Observation object.
    """
    observation_dict = {
        'state': observation.state.as_dict,
        'reward': observation.reward,
        'end': observation.end,
        'info': observation.info
    }
    return observation_dict

def parse_log_content(log_content:str)->Optional[list]:
    try:
        logs = []
        data = json.loads(log_content)
        for item in data:
            ip = IP(item["source_host"])
            action_type = ActionType.from_string(item["action_type"])
            logs.append({"source_host":ip, "action_type":action_type})
        return logs
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return None
    except TypeError as e:
        print(f"Error decoding JSON: {e}")
        return None

def get_logging_level(debug_level):
    """
    Configure logging level based on the provided debug_level string.
    """
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    
    level = log_levels.get(debug_level.upper(), logging.ERROR)
    return level

def store_trajectories_to_jsonl(trajectories:list, dir:str, filename:str)->None:
    """
    Store trajectories to a JSONL file.
    Args:
        trajectories (list): List of trajectory data to store.
        dir (str): Directory where the file will be stored.
        filename (str): Name of the file (without extension).
    """
    # make sure the directory exists
    if not os.path.exists(dir):
        os.makedirs(dir)
    # construct the full file name
    filename = os.path.join(dir, f"{filename.rstrip('jsonl')}.jsonl")
    # store the trajectories
    with jsonlines.open(filename, "a") as writer:
        writer.write(trajectories)

def read_trajectories_from_jsonl(filepath:str)->list:
    """
    Read trajectories from a JSONL file.
    Args:
        filepath (str): Path to the JSONL file.
    Returns:
        list: List of trajectories read from the file.
    """
    raise NotImplementedError("This function is not yet implemented.")

if __name__ == "__main__":
    state = GameState(known_networks={Network("1.1.1.1", 24),Network("1.1.1.2", 24)},
            known_hosts={IP("192.168.1.2"), IP("192.168.1.3")}, controlled_hosts={IP("192.168.1.2")},
            known_services={IP("192.168.1.3"):{Service("service1", "public", "1.01", True)}},
            known_data={IP("192.168.1.3"):{Data("ChuckNorris", "data1"), Data("ChuckNorris", "data2")},
                        IP("192.168.1.2"):{Data("McGiver", "data2")}})
    
    print(state_as_ordered_string(state))
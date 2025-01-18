# Author: Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
from itertools import groupby
from .game_components import ActionType, Action
from random import random


# The probability of detecting an action is defined by the following dictionary
DEFAULT_DETECTION_PROBS = {
    ActionType.ScanNetwork: 0.05,
    ActionType.FindServices: 0.075,
    ActionType.ExploitService: 0.1,
    ActionType.FindData: 0.025,
    ActionType.ExfiltrateData: 0.025,
    ActionType.BlockIP: 0.01
}

# Ratios of action types in the time window (TW) for each action type. The ratio should be higher than the defined value to trigger a detection check
TW_TYPE_RATIOS_THRESHOLD = {
    ActionType.ScanNetwork: 0.25,
    ActionType.FindServices: 0.3,
    ActionType.ExploitService: 0.25,
    ActionType.FindData: 0.5,
    ActionType.ExfiltrateData: 0.25,
    ActionType.BlockIP: 1
}

# Thresholds for consecutive actions of the same type in the TW. Only if the threshold is crossed, the detection check is triggered
TW_CONSECUTIVE_TYPE_THRESHOLD = {
    ActionType.ScanNetwork: 2,
    ActionType.FindServices: 3,
    ActionType.ExfiltrateData: 2
}

# Thresholds for repeated actions in the episode. Only if the threshold is crossed, the detection check is triggered
EPISODE_REPEATED_ACTION_THRESHOLD = {
    ActionType.ExploitService: 2,
    ActionType.FindData: 2,
}

def stochastic(action_type:ActionType)->bool:
    """
    Simple random detection based on predefied probability and ActionType
    """
    roll = random()
    return roll < DEFAULT_DETECTION_PROBS[action_type]

def stochastic_with_threshold(action:Action, episode_actions:list, tw_size:int=5)-> bool:
    """
    Only detect based on set probabilities if pre-defined thresholds are crossed.
    """
    # extend the episode with the latest action
    episode_actions.append(action)
    if len(episode_actions) >= tw_size:
        last_n_actions = episode_actions[-tw_size:]
        last_n_action_types = [action.type for action in last_n_actions]
        # compute ratio of action type in the TW
        tw_ratio = last_n_action_types.count(action.type)/tw_size
        # Count how many times this exact (parametrized) action was played in episode
        repeats_in_episode = episode_actions.count(action)
        # Compute Action type ration in the TW
        tw_ratio = last_n_action_types.count(action.type)/tw_size
        # compute the highest consecutive number of action type in TW
        max_consecutive_action_type= max(sum(1 for item in grouped if item == action.type)
                                            for _, grouped in groupby(last_n_action_types))
        
        if action.type in CONSECUTIVE_THRESHOLD.keys():
            # ScanNetwork, FindServices, ExfiltrateData
            if tw_ratio < TW_RATIOS[action.type] and max_consecutive_action_type < CONSECUTIVE_THRESHOLD[action.type]:
                return False
            else:
                return stochastic(action.type)
        elif action.type in REPEATED_THRESHOLD.keys():
            # FindData, Exploit service
            if tw_ratio < TW_RATIOS[action.type] and repeats_in_episode < REPEATED_THRESHOLD[action.type]:
                return False
            else:
                return stochastic(action.type)
        else: #Other actions - Do not detect
            return False

    else:
        return False

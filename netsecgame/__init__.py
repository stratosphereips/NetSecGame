# add imports so that they are available when importing the package NetSecGame
# e.g., from NetSecGame import GameState

__version__ = "0.1.0"

# Game components
from .game_components import (
    Action,
    ActionType,
    AgentInfo,
    Data,
    GameState,
    GameStatus,
    IP,
    Data,
    Network,
    Observation,
    ProtocolConfig,
    Service
)
# Base agent
from .agents.base_agent import BaseAgent

# Selected util functions
from .utils.utils import (
    get_file_hash,
    state_as_ordered_string,
    store_trajectories_to_jsonl,
    read_trajectories_from_jsonl,
    observation_as_dict,
    observation_to_str,
    generate_valid_actions
)

# Define the public API of the package
__all__ = [
    # Metadata
    "__version__",
    # Game components
    "Action",
    "ActionType",
    "AgentInfo",
    "Data",
    "GameState",
    "GameStatus",
    "IP",
    "Network",
    "Observation",
    "ProtocolConfig",
    "Service",
    # Base agent
    "BaseAgent",
    # Utils
    "get_file_hash",
    "state_as_ordered_string",
    "store_trajectories_to_jsonl",
    "read_trajectories_from_jsonl",
    "observation_as_dict",
    "observation_to_str",
    "generate_valid_actions"
]
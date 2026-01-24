# trajectory_recorder.py
# Author: Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import os
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from netsecgame.game_components import Action, GameState
from netsecgame.utils.utils import store_trajectories_to_jsonl

class TrajectoryRecorder:
    """
    Manages the recording and storage of agent trajectories.
    """
    def __init__(self, agent_name: str, agent_role: str):
        self.agent_name = agent_name
        self.agent_role = agent_role
        self.logger = logging.getLogger(f"TrajectoryRecorder-{agent_name}")
        self._data: Dict[str, Any] = {}
        self.reset()

    def reset(self) -> None:
        """
        Resets the trajectory data for a new episode.
        """
        self.logger.debug(f"Resetting trajectory for {self.agent_name}")
        self._data = {
            "trajectory": {
                "states": [],
                "actions": [],
                "rewards": [],
            },
            "end_reason": None,
            "agent_role": self.agent_role,
            "agent_name": self.agent_name
        }

    def add_step(self, action: Action, reward: float, next_state: GameState, end_reason: Optional[str] = None) -> None:
        """
        Adds a single step to the trajectory.

        Args:
            action (Action): The action taken.
            reward (float): The reward received.
            next_state (GameState): The resulting state.
            end_reason (Optional[str]): Reason for episode end, if applicable.
        """
        self.logger.debug(f"Adding step to trajectory for {self.agent_name}")
        # Assuming Action and GameState have .as_dict property or method as in original code
        # In original code: action.as_dict, next_state.as_dict
        self._data["trajectory"]["actions"].append(action.as_dict)
        self._data["trajectory"]["rewards"].append(reward)
        self._data["trajectory"]["states"].append(next_state.as_dict)
        
        if end_reason:
            self._data["end_reason"] = end_reason

    def add_initial_state(self, state: GameState) -> None:
        """
        Adds the initial state to the trajectory (optional, depending on how you want to track s_0).
        The original code initialized trajectory with states=[agent_state.as_dict].
        """
        self._data["trajectory"]["states"].append(state.as_dict)

    def get_trajectory(self) -> Dict[str, Any]:
        """
        Returns the current trajectory data.
        """
        return self._data

    def save_to_file(self, location: str = "./logs/trajectories") -> None:
        """
        Saves the recorded trajectory to a JSONL file.

        Args:
            location (str): Directory to save the file.
        """
        filename = f"{datetime.now():%Y-%m-%d}_{self.agent_name}_{self.agent_role}"
        try:
            store_trajectories_to_jsonl(self._data, location, filename)
            self.logger.info(f"Trajectory stored in {os.path.join(location, filename)}.jsonl")
        except Exception as e:
            self.logger.error(f"Failed to store trajectory: {e}")

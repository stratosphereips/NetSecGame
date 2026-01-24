from dataclasses import dataclass, field
import asyncio
from typing import Optional, Dict, Any

from netsecgame.game_components import GameState, AgentStatus, Action, Observation
from netsecgame.utils.trajectory_recorder import TrajectoryRecorder

@dataclass
class AgentContext:
    """
    Encapsulates all state and information related to a single connected agent in the game.
    """
    name: str
    role: str
    address: tuple
    
    # State
    current_state: GameState
    goal_state: GameState
    starting_position: dict 
    
    # Status
    status: AgentStatus = AgentStatus.Playing
    episode_end: bool = False
    
    # Reset flags
    reset_request: bool = False
    topology_reset_request: bool = False
    
    # Metrics
    steps: int = 0
    rewards: float = 0.0
    false_positives: int = 0
    
    # Last interaction
    last_action: Optional[Action] = None
    current_observation: Optional[Observation] = None
    
    # Generic extensibility for World-specific data
    custom_data: Dict[str, Any] = field(default_factory=dict)
    
    # Trajectory
    recorder: Optional[TrajectoryRecorder] = None

    def __post_init__(self):
        """
        Initialize the TrajectoryRecorder after the object is created.
        """
        self.recorder = TrajectoryRecorder(self.name, self.role)
        # Initialize recorder with current state if needed, or caller does it.
        # self.recorder.add_initial_state(self.current_state)

    def reset_for_new_episode(self, new_state: GameState, new_goal_state: GameState, timeout_role: bool = False):
        """
        Resets the agent's ephemeral state for a new episode.
        """
        self.current_state = new_state
        self.goal_state = new_goal_state
        self.episode_end = False
        self.reset_request = False
        self.topology_reset_request = False
        self.steps = 0
        self.rewards = 0.0
        self.false_positives = 0
        self.last_action = None
        
        # Reset Status
        if timeout_role:
            self.status = AgentStatus.PlayingWithTimeout
        else:
            self.status = AgentStatus.Playing
            
        # Reset Trajectory
        if self.recorder:
            self.recorder.reset()
            self.recorder.add_initial_state(new_state)

    def record_step(self, action: Action, reward: float, next_state: GameState, end_reason: Optional[str] = None):
        """
        Delegates step recording to the TrajectoryRecorder.
        """
        if self.recorder:
            self.recorder.add_step(action, reward, next_state, end_reason)

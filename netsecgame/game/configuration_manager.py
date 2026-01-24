import logging
from typing import Optional, Dict, Any, List
import asyncio
from aiohttp import ClientSession

from netsecgame.game.config_parser import ConfigParser
from netsecgame.utils.utils import get_str_hash
from cyst.api.environment.environment import Environment
from netsecgame.game_components import AgentRole

class ConfigurationManager:
    """
    Manages the loading and access of game configuration.
    
    Handles fetching configuration from efficient sources (local file or remote service)
    and provides structured access to configuration data.
    """
    
    def __init__(self, task_config_file: Optional[str] = None, service_host: Optional[str] = None, service_port: Optional[int] = None):
        self.logger = logging.getLogger("ConfigurationManager")
        self._task_config_file = task_config_file
        self._service_host = service_host
        self._service_port = service_port
        
        self._parser: Optional[ConfigParser] = None
        self._cyst_objects = None
        self._config_file_hash: Optional[str] = None
        
        # Cache for parsed values
        self._starting_positions: Dict[str, Any] = {}
        self._win_conditions: Dict[str, Any] = {}
        self._goal_descriptions: Dict[str, str] = {}
        self._max_steps: Dict[str, Optional[int]] = {}
        
    async def load(self) -> None:
        """
        Determines the source and loads the configuration.
        Prioritizes remote service if configured, otherwise falls back to local file.
        """
        if self._service_host and self._service_port:
            self.logger.info(f"Fetching task configuration from {self._service_host}:{self._service_port}")
            await self._fetch_remote_configuration()
        elif self._task_config_file:
            self.logger.info(f"Loading task configuration from file: {self._task_config_file}")
            self._load_local_configuration()
        else:
            raise ValueError("Task configuration source not specified (neither file nor service)")

    async def _fetch_remote_configuration(self) -> None:
        """Fetches initialization objects from the remote service."""
        url = f"http://{self._service_host}:{self._service_port}/cyst_init_objects"
        async with ClientSession() as session:
            try:
                async with session.get(url) as response:
                    if response.status == 200:
                        config_data = await response.json()
                        self.logger.debug(f"Received config data: {config_data}")
                        
                        # Initialize CYST environment
                        env = Environment.create()
                        self._config_file_hash = get_str_hash(config_data)
                        self._cyst_objects = env.configuration.general.load_configuration(config_data)
                        self.logger.debug(f"Initialization objects received: {self._cyst_objects}")
                        
                        # Initialize parser with the fetched dict (assuming it contains task_configuration or similar structure)
                        # Note: The original coordinator code for remote fetch commented out creating ConfigParser:
                        # #self.task_config = ConfigParser(config_dict=response["task_configuration"])
                        # usage of self.task_config in original code fell back to loading from file even if remote fetch happened?
                        # "Temporary fix" comment in original code suggests fallback.
                        # For this implementation, we should try to use the fetched config if possible.
                        # If the API returns the same structure as the YAML file, we can pass it to ConfigParser(config_dict=...)
                        # If not, we might need to rely on the file as the original code did for the parser part.
                        
                        # Let's assume for now we try to use the dictionary if available, otherwise fallback logic might be needed
                        # derived from how the response is structured.
                        # Looking at original code: response seems to be the full config.
                        self._parser = ConfigParser(config_dict=config_data)
                        
                    else:
                        self.logger.error(f"Failed to fetch initialization objects. Status: {response.status}")
                        raise RuntimeError(f"Remote configuration fetch failed with status {response.status}")
            except Exception as e:
                self.logger.error(f"Error fetching initialization objects: {e}")
                # Fallback to local file if remote fails? The original code did:
                # self.task_config = ConfigParser(self._task_config_file)
                # We can implement similar fallback behavior here if desired, or just raise.
                if self._task_config_file:
                    self.logger.warning("Falling back to local configuration file.")
                    self._load_local_configuration()
                else:
                    raise e
                    
    def _load_local_configuration(self) -> None:
        """Loads configuration from the local file."""
        self._parser = ConfigParser(task_config_file=self._task_config_file)
        self._cyst_objects = self._parser.get_scenario()
        # Original code does str(self._cyst_objects) for hash
        self._config_file_hash = get_str_hash(str(self._cyst_objects))

    # -------------------------------------------------------------------------
    # Accessors
    # -------------------------------------------------------------------------

    def get_cyst_objects(self):
        return self._cyst_objects

    def get_config_hash(self) -> Optional[str]:
        return self._config_file_hash
        
    def get_starting_position(self, role: str) -> dict:
        """Returns the starting position configuration for a specific role."""
        if not self._parser:
            raise RuntimeError("Configuration not loaded.")
        return self._parser.get_start_position(agent_role=role)

    def get_win_conditions(self, role: str) -> dict:
        """Returns the win conditions for a specific role."""
        if not self._parser:
            raise RuntimeError("Configuration not loaded.")
        return self._parser.get_win_conditions(agent_role=role)

    def get_goal_description(self, role: str) -> str:
        """Returns the goal description for a specific role."""
        if not self._parser:
            raise RuntimeError("Configuration not loaded.")
        return self._parser.get_goal_description(agent_role=role)
        
    def get_max_steps(self, role: str) -> Optional[int]:
        """Returns the max steps for a specific role."""
        if not self._parser:
            raise RuntimeError("Configuration not loaded.")
        return self._parser.get_max_steps(role)

    def get_rewards(self, reward_names: List[str] = ["step", "success", "fail", "false_positive"], default_value: int = 0) -> dict:
        """Returns the rewards configuration."""
        if not self._parser:
            raise RuntimeError("Configuration not loaded.")
        return self._parser.get_rewards(reward_names, default_value)
        
    def get_use_dynamic_ips(self, default_value: bool = False) -> bool:
        if not self._parser:
            raise RuntimeError("Configuration not loaded.")
        return self._parser.get_use_dynamic_addresses(default_value)
        
    def get_use_global_defender(self, default_value: bool = False) -> bool:
        if not self._parser:
            raise RuntimeError("Configuration not loaded.")
        return self._parser.get_use_global_defender(default_value)
        
    def get_required_num_players(self, default_value: int = 1) -> int:
        if not self._parser:
            raise RuntimeError("Configuration not loaded.")
        return self._parser.get_required_num_players(default_value)

    def get_use_firewall(self, default_value: bool = True) -> bool:
        if not self._parser:
            raise RuntimeError("Configuration not loaded.")
        return self._parser.get_use_firewall(default_value)

    def get_all_starting_positions(self) -> Dict[str, Any]:
        """Returns starting positions for all roles."""
        starting_positions = {}
        for agent_role in AgentRole:
            try:
                starting_positions[agent_role] = self.get_starting_position(role=agent_role)
                self.logger.info(f"Starting position for role '{agent_role}': {starting_positions[agent_role]}")
            except KeyError:
                starting_positions[agent_role] = {}
        return starting_positions

    def get_all_win_conditions(self) -> Dict[str, Any]:
        """Returns win conditions for all roles."""
        win_conditions = {}
        for agent_role in AgentRole:
            try:
                win_conditions[agent_role] = self.get_win_conditions(role=agent_role)
            except KeyError:
                win_conditions[agent_role] = {}
            self.logger.info(f"Win condition for role '{agent_role}': {win_conditions[agent_role]}")
        return win_conditions

    def get_all_goal_descriptions(self) -> Dict[str, str]:
        """Returns goal descriptions for all roles."""
        goal_descriptions = {}
        for agent_role in AgentRole:
            try:
                goal_descriptions[agent_role] = self.get_goal_description(role=agent_role)
            except KeyError:
                goal_descriptions[agent_role] = ""
            self.logger.info(f"Goal description for role '{agent_role}': {goal_descriptions[agent_role]}")
        return goal_descriptions

    def get_all_max_steps(self) -> Dict[str, Optional[int]]:
        """Returns max steps for all roles."""
        # Using self.get_max_steps might raise RuntimeError if checks are there, 
        # but simpler to just call parser directly or the single accessor since we are inside the class.
        # However, the single accessor has the check.
        # But wait, self.get_max_steps(role) does `self._parser.get_max_steps(role)` already.
        # Iterating over AgentRole is correct.
        return {role: self.get_max_steps(role) for role in AgentRole}
    
    def get_store_trajectories(self, default_value: bool = False) -> bool:
        if not self._parser:
            raise RuntimeError("Configuration not loaded.")
        return self._parser.get_store_trajectories(default_value)

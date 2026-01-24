import logging
import json
import asyncio
from datetime import datetime
from typing import Optional
import signal
import os
from aiohttp import ClientSession

from netsecgame.game_components import Action, Observation, ActionType, GameStatus, GameState, AgentStatus, ProtocolConfig, AgentRole
from netsecgame.game.global_defender import GlobalDefender
from netsecgame.utils.utils import observation_as_dict, get_str_hash, store_trajectories_to_jsonl
from netsecgame.game.config_parser import ConfigParser
from netsecgame.game.agent_server import AgentServer
from netsecgame.game.configuration_manager import ConfigurationManager
from cyst.api.environment.environment import Environment


def convert_msg_dict_to_json(msg_dict: dict) -> str:
    """
    Helper function to create text-base messge from a dictionary. Used in the Agent-Game communication.
    """
    try:
        # Convert message into string representation
        output_message = json.dumps(msg_dict)
    except Exception as e:
        # Let the caller handle logging if needed, or re-raise with context
        raise TypeError(f"Error when converting msg to JSON:{e}") from e
    return output_message


class GameCoordinator:
    """
    Class for creation, and management of agent interactions in AI Dojo.

    Attributes:
        host (str): Host address for the game server.
        port (int): Port number for the game server.
        logger (logging.Logger): Logger for the GameCoordinator.
        _tasks (set): Set of active asyncio tasks.
        shutdown_flag (asyncio.Event): Event to signal shutdown.
        _reset_event (asyncio.Event): Event to signal game reset.
        _episode_end_event (asyncio.Event): Event to signal episode end.
        _episode_start_event (asyncio.Event): Event to signal episode start.
        _episode_rewards_condition (asyncio.Condition): Condition for episode rewards assignment.
        _reset_done_condition (asyncio.Condition): Condition for reset completion.
        _reset_lock (asyncio.Lock): Lock for reset operations.
        _agents_lock (asyncio.Lock): Lock for agent operations.
        _service_host (str): Host for remote configuration service.
        _service_port (int): Port for remote configuration service.
        _task_config_file (str): Path to local task configuration file.
        ALLOWED_ROLES (list): List of allowed agent roles.
        _cyst_objects: CYST simulator initialization objects.
        _cyst_object_string: String representation of CYST objects.
        _agent_action_queue (asyncio.Queue): Queue for agent actions.
        _agent_response_queues (dict): Mapping of agent addresses to their response queues.
        agents (dict): Mapping of agent addresses to their information.
        _agent_steps (dict): Step counters per agent address.
        _reset_requests (dict): Reset requests per agent address.
        _randomize_topology_requests (dict): Topology randomization requests per agent address.
        _agent_status (dict): Status of each agent.
        _episode_ends (dict): Episode end flags per agent address.
        _agent_observations (dict): Observations per agent address.
        _agent_starting_position (dict): Starting positions per agent address.
        _agent_states (dict): Current states per agent address.
        _agent_goal_states (dict): Goal states per agent address.
        _agent_last_action (dict): Last actions played by agents.
        _agent_false_positives (dict): False positives per agent.
        _agent_rewards (dict): Rewards per agent address.
        _agent_trajectories (dict): Trajectories per agent address.
    """
    def __init__(self, game_host: str, game_port: int, service_host:str, service_port:int, task_config_file:str,allowed_roles=["Attacker", "Defender", "Benign"]) -> None:
        self.host = game_host
        self.port = game_port
        self.logger = logging.getLogger("AIDojo-GameCoordinator")

        self._tasks = set()
        self.shutdown_flag = asyncio.Event()
        self._reset_event = asyncio.Event()
        self._episode_end_event = asyncio.Event()
        self._episode_start_event = asyncio.Event()
        self._episode_rewards_condition = asyncio.Condition()
        self._reset_done_condition = asyncio.Condition()
        self._reset_lock = asyncio.Lock()
        self._agents_lock = asyncio.Lock()
        
        # for accessing configuration remotely
        self._service_host = service_host
        self._service_port = service_port
        # for reading configuration locally
        self._task_config_file = task_config_file
        
        # Configuration Manager
        self.config_manager = ConfigurationManager(task_config_file, service_host, service_port)
        
        self.logger = logging.getLogger("AIDojo-GameCoordinator")
        self.ALLOWED_ROLES = allowed_roles
        self._cyst_objects = None
        self._cyst_object_string = None
        
        # prepare agent communication
        self._agent_action_queue = asyncio.Queue()
        self._agent_response_queues = {}
        
        # agent information
        self.agents = {}
        # step counter per agent_addr (int)
        self._agent_steps = {}
        # reset request per agent_addr (bool)
        self._reset_requests = {}
        self._randomize_topology_requests = {}
        self._agent_status = {}
        self._episode_ends = {}
        self._agent_observations = {}
        # starting per agent_addr (dict)
        self._agent_starting_position = {}
        # current state per agent_addr (GameState)
        self._agent_states = {}
        # goal state per agent_addr (GameState)
        self._agent_goal_states = {}
        # last action played by agent (Action)
        self._agent_last_action = {}
        # False positives per agent (due to added blocks)
        self._agent_false_positives = {}
        # agent status dict {agent_addr: int}
        self._agent_rewards = {}
        # trajectories per agent_addr
        self._agent_trajectories = {}
    
    def _spawn_task(self, coroutine, *args, **kwargs)->asyncio.Task:
        """
        Helper function to make sure all tasks are registered for proper termination.
        
        Args:
            coroutine: The coroutine function to schedule.
            *args: Positional arguments to pass to the coroutine.
            **kwargs: Keyword arguments to pass to the coroutine.
            
        Returns:
            asyncio.Task: The created task object.
        """
        task = asyncio.create_task(coroutine(*args, **kwargs))
        self._tasks.add(task)
        def remove_task(t):
            self._tasks.discard(t)
        task.add_done_callback(remove_task)  # Remove task when done
        return task

    async def shutdown_signal_handler(self)->None:
        """
        Logs the signal reception and sets the shutdown flag to initiate graceful termination.
        """
        self.logger.info("Shutdown signal received. Setting shutdown flag.")
        self.shutdown_flag.set()

    async def create_agent_queue(self, agent_addr:tuple)->None:
        """
        Creates a queue for the given agent address if it doesn't already exist.
        
        Args:
            agent_addr (tuple): The agent address to create a queue for.
        """
        if agent_addr not in self._agent_response_queues:
            self._agent_response_queues[agent_addr] = asyncio.Queue()
            self.logger.info(f"Created queue for agent {agent_addr}. {len(self._agent_response_queues)} queues in total.")
    
    def run(self)->None:
        """
        Wrapper for ayncio run function. Starts all tasks in AIDojo
        """
        try:
            asyncio.run(self.start_tasks())
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
        finally:
            self.logger.info(f"{__class__.__name__} has exited.")

    async def start_tcp_server(self):
        """
        Starts TPC sever for the agent communication.
        """
        server = None
        try:
            self.logger.info("Starting the server listening for agents")
            server = await asyncio.start_server(
                AgentServer(
                    self._agent_action_queue,
                    self._agent_response_queues,
                    max_connections=self._min_required_players
                ),
                self.host,
                self.port
            )
            addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
            self.logger.info(f"\tServing on {addrs}")
            while not self.shutdown_flag.is_set():
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            self.logger.debug("\tStopping TCP server task.")
        except Exception as e:
            self.logger.error(f"TCP server failed: {e}")
        finally:
            if server:
                server.close()
                await server.wait_closed()
            self.logger.info("\tTCP server task stopped")

    async def start_tasks(self):
        """
        High level funciton to start all the other asynchronous tasks.
        - Reads the conf of the coordinator
        - Creates queues
        - Start the main part of the coordinator
        - Start a server that listens for agents
        """
        loop = asyncio.get_running_loop()
        
        # Set up signal handlers for graceful shutdown
        loop.add_signal_handler(
            signal.SIGINT, lambda: asyncio.create_task(self.shutdown_signal_handler())
        )
        loop.add_signal_handler(
            signal.SIGTERM, lambda: asyncio.create_task(self.shutdown_signal_handler())
        )


        # Initialize configuration manager and load the configuration
        await self.config_manager.load()
        self._cyst_objects = self.config_manager.get_cyst_objects()
        
        if self.config_manager.get_config_hash():
             self._CONFIG_FILE_HASH = self.config_manager.get_config_hash()

        # Read configuration
        # Read configuration
        self._starting_positions_per_role = self.config_manager.get_all_starting_positions()
        self._win_conditions_per_role = self.config_manager.get_all_win_conditions()
        self._goal_description_per_role = self.config_manager.get_all_goal_descriptions()
        self._steps_limit_per_role = self.config_manager.get_all_max_steps()
        
        self.logger.debug(f"Timeouts set to:{self._steps_limit_per_role}")
        if self.config_manager.get_use_global_defender():
            self._global_defender = GlobalDefender()
        else:
            self._global_defender = None
        self._use_dynamic_ips = self.config_manager.get_use_dynamic_ips()
        self.logger.info(f"Change IP every episode set to: {self._use_dynamic_ips}")
        self._rewards = self.config_manager.get_rewards(["step", "success", "fail", "false_positive"])
        self.logger.info(f"Rewards set to:{self._rewards}")
        self._min_required_players = self.config_manager.get_required_num_players()
        self.logger.info(f"Min player requirement set to:{self._min_required_players}")
        # run self initialization
        self._initialize()

        # start server for agent communication
        self._spawn_task(self.start_tcp_server)

        # start episode rewards task
        self._spawn_task(self._assign_rewards_episode_end)

        # start episode rewards task
        self._spawn_task(self._reset_game)

        # start action processing task
        self._spawn_task(self.run_game)
        
        while not self.shutdown_flag.is_set():
            # just wait until user terminates
            await asyncio.sleep(1)
        self.logger.debug("Final cleanup started")
        # make sure there are no running tasks left
        for task in self._tasks:
            task.cancel()  # Cancel each active task
        await asyncio.gather(*self._tasks, return_exceptions=True)  # Wait for all tasks to finish
        self.logger.info("All tasks shut down.")
    
    def _parse_action_message(self, agent_addr: tuple, message: str) -> Optional[Action]:
        """
        Parses a JSON message from an agent into an Action object.
        
        Args:
            agent_addr (tuple): The address of the agent sending the message (used for logging context).
            message (str): The raw JSON string message received from the agent.
            
        Returns:
            Optional[Action]: The parsed Action object if successful, None otherwise.
        """
        try:
            action = Action.from_json(message)
            return action
        except Exception as e:
            self.logger.error(f"Error when converting msg from {agent_addr} to Action using Action.from_json():{e}, {message}")
            return None

    def _dispatch_action(self, agent_addr: tuple, action: Action) -> None:
        """
        Dispatches an Action to the appropriate processing method based on its type.
        
        Args:
            agent_addr (tuple): The address of the agent performing the action.
            action (Action): The Action object to be processed.
        """
        match action.type:
            case ActionType.JoinGame:
                self.logger.debug(f"[{agent_addr}] Start processing of ActionType.JoinGame")
                self._spawn_task(self._process_join_game_action, agent_addr, action)
            case ActionType.QuitGame:
                self.logger.debug(f"[{agent_addr}] Start processing of ActionType.QuitGame")
                self._spawn_task(self._process_quit_game_action, agent_addr)
            case ActionType.ResetGame:
                self.logger.debug(f"[{agent_addr}] Start processing of ActionType.ResetGame")
                self._spawn_task(self._process_reset_game_action, agent_addr, action)
            case ActionType.ExfiltrateData | ActionType.FindData | ActionType.ScanNetwork | ActionType.FindServices | ActionType.ExploitService | ActionType.BlockIP:
                self.logger.debug(f"[{agent_addr}] Start processing of {action.type}")
                self._spawn_task(self._process_game_action, agent_addr, action)
            case _:
                self.logger.warning(f"[{agent_addr}] Unsupported action type: {action}!")

    async def run_game(self):
        """
        Main game loop task. 
        
        Responsible for reading messages from the agent queue, parsing them using `_parse_action_message`, 
        and dispatching them to the appropriate handler using `_dispatch_action`.
        """
        while not self.shutdown_flag.is_set():
            # Read message from the queue
            agent_addr, message = await self._agent_action_queue.get()
            if message is not None:
                self.logger.info(f"Coordinator received from agent {agent_addr}: {message}.")

                action = self._parse_action_message(agent_addr, message)
                if action:
                    self._dispatch_action(agent_addr, action)
        self.logger.info("\tAction processing task stopped.")
            
    async def _process_join_game_action(self, agent_addr: tuple, action: Action)->None:
        """
        Method for processing Action of type ActionType.JoinGame
        Inputs: 
            -   agent_addr (tuple)
            -   JoinGame Action
        Outputs: None (Method stores reposnse in the agent's response queue)
        """
        try:
            self.logger.info(f"New Join request by  {agent_addr}.")
            if agent_addr not in self.agents:
                agent_name = action.parameters["agent_info"].name
                agent_role = action.parameters["agent_info"].role
                if agent_role in AgentRole:
                    # add agent to the world
                    new_agent_game_state, new_agent_goal_state = await self.register_agent(agent_addr, agent_role, self._starting_positions_per_role[agent_role], self._win_conditions_per_role[agent_role])
                    if new_agent_game_state: # successful registration
                        async with self._agents_lock:
                            self.agents[agent_addr] = (agent_name, agent_role)
                            observation = self._initialize_new_player(agent_addr, new_agent_game_state, new_agent_goal_state)
                            self._agent_observations[agent_addr] = observation
                            #if len(self.agents) == self._min_required_players:
                            if sum(1 for v in self._agent_status.values() if v == AgentStatus.PlayingWithTimeout) >= self._min_required_players:
                                # set the event so the episde can start
                                self._episode_start_event.set()
                                self.logger.info("Enough players joined. Starting the episode.")
                            else:
                                self.logger.debug("Waiting for other players to join.")
                        # wait for required number of players
                        await self._episode_start_event.wait()
                        output_message_dict = {
                            "to_agent": agent_addr,
                            "status": str(GameStatus.CREATED),
                            "observation": observation_as_dict(observation),
                            "message": {
                                "message": f"Welcome {agent_name}, registred as {agent_role}",
                                "max_steps": self._steps_limit_per_role[agent_role],
                                "goal_description": self._goal_description_per_role[agent_role],
                                "actions": [str(a) for a in ActionType],
                                "configuration_hash": self._CONFIG_FILE_HASH
                                },
                        }
                        if hasattr(self, "_registration_info"):
                            for key, value in self._registration_info.items():
                                output_message_dict["message"][key] = value
                        await self._agent_response_queues[agent_addr].put(convert_msg_dict_to_json(output_message_dict))
                else:
                    self.logger.info(
                        f"\tError in registration, unknown agent role: {agent_role}!"
                    )
                    output_message_dict = {
                        "to_agent": agent_addr,
                        "status": str(GameStatus.BAD_REQUEST),
                        "message": f"Incorrect agent_role {agent_role}",
                    }
                    response_msg_json = convert_msg_dict_to_json(output_message_dict)
                    await self._agent_response_queues[agent_addr].put(response_msg_json)
            else:
                self.logger.info("\tError in registration, agent already exists!")
                output_message_dict = {
                        "to_agent": agent_addr,
                        "status": str(GameStatus.BAD_REQUEST),
                        "message": "Agent already exists.",
                    }
                response_msg_json = convert_msg_dict_to_json(output_message_dict)
                await self._agent_response_queues[agent_addr].put(response_msg_json)
        except asyncio.CancelledError:
            self.logger.debug(f"Proccessing JoinAction of agent {agent_addr} interrupted")
            raise  # Ensure the exception propagates
        finally:
            self.logger.debug(f"Cleaning up after JoinGame for {agent_addr}.")
    
    async def _process_quit_game_action(self, agent_addr: tuple)->None:
        """
        Method for processing Action of type ActionType.QuitGame
        Inputs: 
            -   agent_addr (tuple)
        Outputs: None
        """
        try:
            if agent_addr in self._agent_states:
                await self.remove_agent(agent_addr, self._agent_states[agent_addr])
            else:
                self.logger.warning(f"Agent address {agent_addr} not found in _agent_states. Skipping removal.")
            agent_info = await self._remove_agent_from_game(agent_addr)
            self.logger.info(f"Agent {agent_addr} removed from the game. {agent_info}")
        except asyncio.CancelledError:
            self.logger.debug(f"Proccessing QuitAction of agent {agent_addr} interrupted")
            raise  # Ensure the exception propagates
        finally:
            self.logger.debug(f"Cleaning up after QuitGame for {agent_addr}.")
    
    async def _process_reset_game_action(self, agent_addr: tuple, reset_action:Action)->None:
        """
        Method for processing Action of type ActionType.ResetGame
        Inputs: 
            -   agent_addr (tuple)
        Outputs: None
        """
        self.logger.debug("Beginning the _process_reset_game_action.")
        async with self._reset_lock:
            # add reset request for this agent
            self._reset_requests[agent_addr] = True
            # register if the agent wants to randomize the topology
            self._randomize_topology_requests[agent_addr] = reset_action.parameters.get("randomize_topology", True)
            if all(self._reset_requests.values()):
                # all agents want reset - reset the world
                self.logger.debug(f"All agents requested reset, setting the event")
                self._reset_event.set()
        
        # wait until reset is done
        async with self._reset_done_condition:
            await self._reset_done_condition.wait()
        # # make sure there is still enough players to play.
        await self._episode_start_event.wait()
        async with self._agents_lock:
            output_message_dict = {
                "to_agent": agent_addr,
                "status": str(GameStatus.RESET_DONE),
                "observation": observation_as_dict(self._agent_observations[agent_addr]),
                "message": {
                            "message": "Resetting Game and starting again.",
                            "max_steps": self._steps_limit_per_role[self.agents[agent_addr][1]],
                            "goal_description": self._goal_description_per_role[self.agents[agent_addr][1]],
                            "configuration_hash": self._CONFIG_FILE_HASH
                            },
            }
            # extend the message with last trajectory
            if "request_trajectory" in reset_action.parameters and reset_action.parameters["request_trajectory"]:
                output_message_dict["message"]["last_trajectory"] = self._agent_trajectories[agent_addr]
            self._agent_trajectories[agent_addr] = self._reset_trajectory(agent_addr)
        response_msg_json = convert_msg_dict_to_json(output_message_dict)
        await self._agent_response_queues[agent_addr].put(response_msg_json)

    async def _process_game_action(self, agent_addr: tuple, action:Action)->None:
        """
        Method for processing Action of type ActionType.GameAction
        Inputs: 
            -   agent_addr (tuple)
            -   action (Action)
        Outputs: None
        """
        if self._episode_ends[agent_addr]:
            self.logger.warning(f"Agent {agent_addr}({self.agents[agent_addr]}) is attempting to play action {action} after the end of the episode!")
            # agent can't play any more actions in the game
            current_observation = self._agent_observations[agent_addr]
            reward = self._agent_rewards[agent_addr]
            end_reason = str(self._agent_status[agent_addr])
            new_observation = Observation(
                current_observation.state,
                reward=reward,
                end=True,
                info={'end_reason': end_reason, "info":"Episode ended. Request reset for starting new episode."})
            output_message_dict = {
                "to_agent": agent_addr,
                "observation": observation_as_dict(new_observation),
                "status": str(GameStatus.FORBIDDEN),
            }
        else:
            async with self._agents_lock:
                self._agent_last_action[agent_addr] = action
                self._agent_steps[agent_addr] += 1
            # wait for the new state from the world
            new_state = await self.step(agent_id=agent_addr, agent_state=self._agent_states[agent_addr], action=action)
            
            # update agent's values
            async with self._agents_lock:
                # store new state of the agent
                self._agent_states[agent_addr] = new_state
                
                # store new state of the agent using the new state
                self._agent_status[agent_addr] = self._update_agent_status(agent_addr)
                
                # add reward for step (other rewards are added at the end of the episode)
                self._agent_rewards[agent_addr] = self._rewards["step"]
                
                # check if the episode ends for this agent
                self._episode_ends[agent_addr] = self._update_agent_episode_end(agent_addr)

                # check if the episode ends
                if all(self._episode_ends.values()):
                    self._episode_end_event.set()
            if self._episode_ends[agent_addr]:
                # episode ended for this agent - wait for the others to finish
                async with self._episode_rewards_condition:
                    await self._episode_rewards_condition.wait()
            # append step to the trajectory if needed
           

            info = {}
            if self._agent_status[agent_addr] not in [AgentStatus.Playing, AgentStatus.PlayingWithTimeout]:
                info["end_reason"] = str(self._agent_status[agent_addr])
            async with self._agents_lock:
                self._add_step_to_trajectory(agent_addr, action, self._agent_rewards[agent_addr], new_state,end_reason=info.get("end_reason", ""))
            # add information to 'info' field if needed
            new_observation = Observation(self._agent_states[agent_addr], self._agent_rewards[agent_addr], self._episode_ends[agent_addr], info=info)
            self._agent_observations[agent_addr] = new_observation
            output_message_dict = {
                "to_agent": agent_addr,
                "observation": observation_as_dict(new_observation),
                "status": str(GameStatus.OK),
            }
        response_msg_json = convert_msg_dict_to_json(output_message_dict)
        await self._agent_response_queues[agent_addr].put(response_msg_json)

    async def _assign_rewards_episode_end(self):
        """Task that waits for all agents to finish and assigns rewards."""
        self.logger.debug("Starting task for episode end reward assigning.")
        while not self.shutdown_flag.is_set():
            # wait until episode is finished by all agents
            done, pending = await asyncio.wait(
               [asyncio.create_task(self._episode_end_event.wait()), 
                asyncio.create_task(self.shutdown_flag.wait())],
                return_when=asyncio.FIRST_COMPLETED,
            )
             # Check if shutdown_flag was set
            if self.shutdown_flag.is_set():
                self.logger.debug("\tExiting reward assignment task.")
                break
            self.logger.info("Episode finished. Assigning final rewards to agents.")
            async with self._agents_lock:
                attackers = [a for a,(_, a_role) in self.agents.items() if a_role.lower() == "attacker"]
                defenders = [a for a,(_, a_role) in self.agents.items() if a_role.lower() == "defender"]
                successful_attack = False
                # award attackers
                for agent in attackers:
                    self.logger.debug(f"Processing reward for agent {agent}")
                    if self._agent_status[agent] is AgentStatus.Success:
                        self._agent_rewards[agent] += self._rewards["success"]
                        successful_attack = True
                    else:
                        self._agent_rewards[agent] += self._rewards["fail"]
                
                # award defenders
                for agent in defenders:
                    self.logger.debug(f"Processing reward for agent {agent}")
                    if not successful_attack:
                        self._agent_rewards[agent] += self._rewards["success"]
                        self._agent_status[agent] = AgentStatus.Success
                    else:
                        self._agent_rewards[agent] += self._rewards["fail"]
                        self._agent_status[agent] = AgentStatus.Fail
                    # dicrease the reward for false positives
                    self.logger.debug(f"Processing false positives for agent {agent}: {self._agent_false_positives[agent]}")
                    self._agent_rewards[agent] -= self._agent_false_positives[agent] * self._rewards["false_positive"]
            # clear the episode end event
            self._episode_end_event.clear()
            # notify all waiting agents
            async with self._episode_rewards_condition:
                self._episode_rewards_condition.notify_all()
        self.logger.info("\tReward assignment task stopped.")

    async def _reset_game(self):
        """Task that waits for all agents to request resets"""
        self.logger.debug("Starting task for game reset handelling.")
        while not self.shutdown_flag.is_set():
            # wait until episode is finished by all agents
            done, pending = await asyncio.wait(
               [asyncio.create_task(self._reset_event.wait()), 
                asyncio.create_task(self.shutdown_flag.wait())],
                return_when=asyncio.FIRST_COMPLETED,
            )
             # Check if shutdown_flag was set
            if self.shutdown_flag.is_set():
                self.logger.debug("\tExiting reset_game task.")
                break
            # wait until episode is finished by all agents
            self.logger.info("Resetting game to initial state.")
            await self.reset()
            for agent in self.agents:
                if self.task_config.get_store_trajectories():
                    async with self._agents_lock:
                        self._store_trajectory_to_file(agent)
                self.logger.debug(f"Resetting agent {agent}")
                agent_role = self.agents[agent][1]
                # reset the agent in the world
                new_state, new_goal_state = await self.reset_agent(agent, agent_role, self._starting_positions_per_role[agent_role], self._win_conditions_per_role[agent_role])
                new_observation = Observation(new_state, 0, False, {})
                async with self._agents_lock:
                    self._agent_states[agent] = new_state
                    self._agent_goal_states[agent] = new_goal_state
                    self._agent_observations[agent] = new_observation
                    self._episode_ends[agent] = False
                    self._reset_requests[agent] = False
                    self._randomize_topology_requests[agent] = False
                    self._agent_rewards[agent] = 0
                    self._agent_steps[agent] = 0
                    self._agent_false_positives[agent] = 0
                    if self.agents[agent][1].lower() == "attacker":
                        self._agent_status[agent] = AgentStatus.PlayingWithTimeout
                    else:
                        self._agent_status[agent] = AgentStatus.Playing
            self._reset_event.clear()  
            # notify all waiting agents
            async with self._reset_done_condition:
                self._reset_done_condition.notify_all()
        self.logger.info("\tReset game task stopped.")
    
    def _initialize_new_player(self, agent_addr:tuple, agent_current_state:GameState, agent_current_goal_state:GameState) -> Observation:
        """
        Method to initialize new player upon joining the game.
        Returns initial observation for the agent based on the agent's role
        """
        self.logger.info(f"\tInitializing new player{agent_addr}")
        agent_name, agent_role = self.agents[agent_addr]
        self._agent_steps[agent_addr] = 0
        self._reset_requests[agent_addr] = False
        self._episode_ends[agent_addr] = False
        self._agent_starting_position[agent_addr] = self._starting_positions_per_role[agent_role]
        self._agent_states[agent_addr] = agent_current_state
        self._agent_goal_states[agent_addr] = agent_current_goal_state
        self._agent_last_action[agent_addr] = None
        self._agent_rewards[agent_addr] = 0
        self._agent_false_positives[agent_addr] = 0
        if agent_role in [AgentRole.Attacker]:
            self._agent_status[agent_addr] = AgentStatus.PlayingWithTimeout
        else:
            self._agent_status[agent_addr] = AgentStatus.Playing
        self._agent_trajectories[agent_addr] = self._reset_trajectory(agent_addr)
        self.logger.info(f"\tAgent {agent_name} ({agent_addr}), registred as {agent_role}")
        # create initial observation
        return Observation(self._agent_states[agent_addr], 0, False, {})

    async def register_agent(self, agent_id:tuple, agent_role:AgentRole, agent_initial_view:dict, agent_win_condition_view:dict)->tuple[GameState, GameState]:
        """
        Domain specific method of the environment. Creates the initial state of the agent.
        """
        raise NotImplementedError
    
    async def remove_agent(self, agent_id:tuple, agent_state:GameState)->bool:
        """
        Domain specific method of the environment. Creates the initial state of the agent.
        """
        raise NotImplementedError

    async def reset_agent(self, agent_id:tuple, agent_role:AgentRole, agent_initial_view:dict, agent_win_condition_view:dict)->tuple[GameState, GameState]:
        raise NotImplementedError

    async def _remove_agent_from_game(self, agent_addr):
        """
        Removes player from the game. Should be called AFTER QuitGame action was processed by the world.
        """
        self.logger.info(f"Removing player {agent_addr} from the GameCoordinator")
        agent_info = {}
        async with self._agents_lock:
            if agent_addr in self.agents:
                agent_info["state"] = self._agent_states.pop(agent_addr)
                agent_info["goal_state"] = self._agent_goal_states.pop(agent_addr)
                agent_info["num_steps"] = self._agent_steps.pop(agent_addr)
                agent_info["agent_status"] = self._agent_status.pop(agent_addr)
                agent_info["false_positives"] = self._agent_false_positives.pop(agent_addr)
                async with self._reset_lock:
                    # remove agent from  topology reset requests
                    agent_info["topology_reset_request"] = self._randomize_topology_requests.pop(agent_addr, False)
                    # remove agent from reset requests
                    agent_info["reset_request"] = self._reset_requests.pop(agent_addr)
                    # check if this agent was not preventing reset 
                    if any(self._reset_requests.values()):
                        self._reset_event.set()
                    agent_info["episode_end"] = self._episode_ends.pop(agent_addr)
                    #check if this agent was not preventing episode end
                    if all(self._episode_ends.values()):
                        if len(self.agents) > 0:
                            self._episode_end_event.set()
                agent_info["end_reward"] = self._agent_rewards.pop(agent_addr, None)
                agent_info["agent_info"] = self.agents.pop(agent_addr)
                self.logger.debug(f"\t{agent_info}")
                # clear the sufficient number of players event
                self._episode_start_event.clear()
            else:
                self.logger.info(f"\t Player {agent_addr} not present in the game!")
            return agent_info

    async def step(self, agent_id:tuple, agent_state:GameState, action:Action):
        """
        Domain specific method of the environment. Creates the initial state of the agent.
        Must be implemented by the domain specific environment.
        """
        raise NotImplementedError
    
    async def reset(self)->bool:
        """
        Domain specific method of the environment. Creates the initial state of the agent.
        Must be implemented by the domain specific environment.
        """
        raise NotImplementedError

    def _initialize(self):
        """
        Initialize the game state and other necessary components. This is called at the start of the game after the configuration is loaded.
        Must be implemented by the domain specific environment.
        """
        raise NotImplementedError

    def goal_check(self, agent_addr:tuple)->bool:
        """
        Check if the goal conditons were satisfied in a given game state
        """
        def goal_dict_satistfied(goal_dict:dict, known_dict: dict)-> bool:
            """
            Helper function for checking if a goal dictionary condition is satisfied
            """
            # check if we have all IPs that should have some values (are keys in goal_dict)
            if goal_dict.keys() <= known_dict.keys():
                try:
                    # Check if values (sets) for EACH key (host) in goal_dict are subsets of known_dict, keep matching_keys
                    matching_keys = [host for host in goal_dict.keys() if goal_dict[host]<= known_dict[host]]
                    # Check we have the amount of mathing keys as in the goal_dict
                    if len(matching_keys) == len(goal_dict.keys()):
                        return True
                except KeyError:
                    # some keys are missing in the known_dict
                    return False
            return False
        self.logger.debug(f"Checking goal for agent {agent_addr}.")
        state = self._agent_states[agent_addr]
        # For each part of the state of the game, check if the conditions are met
        target_goal_state = self._agent_goal_states[agent_addr]
        self.logger.debug(f"\tGoal conditions: {target_goal_state}.")
        goal_reached = {}    
        goal_reached["networks"] = target_goal_state.known_networks <= state.known_networks
        goal_reached["known_hosts"] = target_goal_state.known_hosts <= state.known_hosts
        goal_reached["controlled_hosts"] = target_goal_state.controlled_hosts <= state.controlled_hosts
        goal_reached["services"] = goal_dict_satistfied(target_goal_state.known_services, state.known_services)
        goal_reached["data"] = goal_dict_satistfied(target_goal_state.known_data, state.known_data)
        goal_reached["known_blocks"] = goal_dict_satistfied(target_goal_state.known_blocks, state.known_blocks)
        self.logger.debug(f"\t{goal_reached}")
        return all(goal_reached.values())

    def is_detected(self, agent:tuple)->bool:
        if self._global_defender:
            detection = self._global_defender.stochastic_with_threshold(self._agent_last_action[agent], self._agent_trajectories[agent]["trajectory"]["actions"])
            self.logger.debug(f"Global Detection result: {detection}")
            return detection
        else:
            # No global defender
            return False

    def is_timeout(self, agent:tuple)->bool:
        timeout_reached = False
        if self._steps_limit_per_role[self.agents[agent][1]]:
            if self._agent_steps[agent] >= self._steps_limit_per_role[self.agents[agent][1]]:
                timeout_reached = True
        return timeout_reached

    def add_false_positive(self, agent:tuple)->None:
        """
        Method for adding false positive to the agent.
        Args:
            agent (tuple): The agent to add false positive to.
        """
        self.logger.debug(f"Adding false positive to {agent}")
        if agent in self._agent_false_positives:
            self._agent_false_positives[agent] += 1
        else:
            self._agent_false_positives[agent] = 1
        self.logger.debug(f"False positives for {agent}: {self._agent_false_positives[agent]}")

    def _update_agent_status(self, agent:tuple)->AgentStatus:
        """
        Update the status of an agent based on reaching the goal, timeout or detection.
        Args:
            agent (tuple): The agent to update the status of.
        Returns:
            AgentStatus: The new status of the agent.
        """
        # read current status of the agent
        next_status = self._agent_status[agent]
        if self.goal_check(agent):
            # Goal has been reached
            self.logger.info(f"Agent {agent}{self.agents[agent]} reached the goal!")
            next_status = AgentStatus.Success
        elif self.is_detected(agent):
            # Detection by Global Defender
            self.logger.info(f"Agent {agent}{self.agents[agent]} detected by GlobalDefender!")
            next_status = AgentStatus.Fail
        elif self.is_timeout(agent):
            # Timout Reached
            self.logger.info(f"Agent {agent}{self.agents[agent]} reached timeout ({self._agent_steps[agent]} steps).")
            next_status = AgentStatus.TimeoutReached
        return next_status

    def _update_agent_episode_end(self, agent:tuple)->bool:
        """
        Update the episode end status of an agent.
        Args:
            agent (tuple): The agent to update the episode end status of.
        Returns:
            bool: True if the episode has ended, False otherwise.
        """
        episode_end = False
        if  self._agent_status[agent] in [AgentStatus.Success, AgentStatus.Fail, AgentStatus.TimeoutReached]:
            # agent reached goal, timeout or was detected
            episode_end = True
        # check if there are any agents playing with timeout
        elif all(
                status != AgentStatus.PlayingWithTimeout
                for status in self._agent_status.values()
            ):
            # all attackers have finised - terminate episode
            self.logger.info(f"Stopping episode for {agent} because the is no ACTIVE agent playing.")
            episode_end = True
        return episode_end

    def _reset_trajectory(self, agent_addr:tuple)->dict:
        agent_name, agent_role = self.agents[agent_addr]
        self.logger.debug(f"Resetting trajectory of {agent_addr}")
        return {
                "trajectory":{
                    "states":[self._agent_states[agent_addr].as_dict],
                    "actions":[],
                    "rewards":[],
                },
                "end_reason":None,
                "agent_role":agent_role,
                "agent_name":agent_name
            }

    def _add_step_to_trajectory(self, agent_addr:tuple, action:Action, reward:float, next_state:GameState, end_reason:str|None=None)-> None:
        """
        Method for adding one step to the agent trajectory.
        """
        if agent_addr in self._agent_trajectories:
            self.logger.debug(f"Adding step to trajectory of {agent_addr}")
            self._agent_trajectories[agent_addr]["trajectory"]["actions"].append(action.as_dict)
            self._agent_trajectories[agent_addr]["trajectory"]["rewards"].append(reward)
            self._agent_trajectories[agent_addr]["trajectory"]["states"].append(next_state.as_dict)
            if end_reason:
                self._agent_trajectories[agent_addr]["end_reason"] = end_reason
    
    def _store_trajectory_to_file(self, agent_addr:tuple, location="./logs/trajectories")-> None:
        """
        Method for storing the agent trajectory to a file.
        """
        if agent_addr in self.agents:
            agent_name, agent_role = self.agents[agent_addr]
            filename =f"{datetime.now():%Y-%m-%d}_{agent_name}_{agent_role}"
            trajectories = self._agent_trajectories[agent_addr]
            store_trajectories_to_jsonl(trajectories, location, filename)
            self.logger.info(f"Trajectories of {agent_addr} strored in {os.path.join(location, filename)}.jsonl")
        else:
            self.logger.warning(f"Agent {agent_addr} not found in agents list, can't store trajectory to file.")
    
    def is_agent_benign(self, agent_addr:tuple)->bool:
        """
        Check if the agent is benign (defender, normal)
        """
        if agent_addr not in self.agents:
            return False
        return self.agents[agent_addr][1].lower() in ["defender", "benign"]
import jsonlines
import logging
import json
import asyncio
from datetime import datetime
import signal

from AIDojoCoordinator.game_components import Action, Observation, ActionType, GameStatus, GameState, AgentStatus, ProtocolConfig
from AIDojoCoordinator.global_defender import GlobalDefender
from AIDojoCoordinator.utils.utils import observation_as_dict, get_str_hash, ConfigParser
import os
from aiohttp import ClientSession
from cyst.api.environment.environment import Environment

class AgentServer(asyncio.Protocol):
    """
    Class used for serving the agents when connecting to the game run by the GameCoordinator.

    Attributes:
        actions_queue (asyncio.Queue): Queue for actions from agents.
        answers_queues (dict): Mapping of agent addresses to their response queues.
        max_connections (int): Maximum allowed concurrent agent connections.
        current_connections (int): Current number of connected agents.
        logger (logging.Logger): Logger for the AgentServer.
    """
    def __init__(self, actions_queue, agent_response_queues, max_connections):
        """
        Initialize the AgentServer.

        Args:
            actions_queue (asyncio.Queue): Queue for actions from agents.
            agent_response_queues (dict): Mapping of agent addresses to their response queues.
            max_connections (int): Maximum allowed concurrent agent connections.
        """
        self.actions_queue = actions_queue
        self.answers_queues = agent_response_queues
        self.max_connections = max_connections
        self.current_connections = 0
        self.logger = logging.getLogger("AIDojo-AgentServer")
    
    async def handle_agent_quit(self, peername:tuple):
        """
        Helper function to handle agent disconnection.

        Args:
            peername (tuple): The address of the disconnecting agent.
        """
        # Send a quit message to the Coordinator
        self.logger.info(f"\tHandling agent quit for {peername}.")
        quit_message = Action(ActionType.QuitGame, parameters={}).to_json()
        await self.actions_queue.put((peername, quit_message))
        
    async def handle_new_agent(self, reader, writer):
        """
        Handle a new agent connection.

        Args:
            reader (asyncio.StreamReader): Stream reader for the agent.
            writer (asyncio.StreamWriter): Stream writer for the agent.
        """
        # get the peername of the writer
        peername = writer.get_extra_info("peername")
        queue_created = False
        try:
            self.logger.info(f"New connection from {peername}")
            # Check if the maximum number of connections has been reached
            if self.current_connections < self.max_connections:
                # increment the count of current connections
                self.current_connections += 1
                self.logger.info(f"New agent connected: {peername}. Current connections: {self.current_connections}")
                # Ensure a queue exists for this agent
                if peername not in self.answers_queues:
                    self.answers_queues[peername] = asyncio.Queue(maxsize=2)
                    queue_created = True
                    self.logger.info(f"Created queue for agent {peername}")
                    # Handle the new agent
                    while True:
                        # Step 1: Read data from the agent
                        data = await reader.read(ProtocolConfig.BUFFER_SIZE)
                        if not data:
                            self.logger.info(f"Agent {peername} disconnected.")
                            await self.handle_agent_quit(peername)
                            break

                        raw_message = data.decode().strip()
                        self.logger.debug(f"Handler received from {peername}: {raw_message}")

                        # Step 2: Forward the message to the Coordinator
                        await self.actions_queue.put((peername, raw_message))
                
                        # Step 3: Get a matching response from the answers queue
                        response_queue = self.answers_queues[peername]
                        response = await response_queue.get()
                        self.logger.info(f"Sending response to agent {peername}: {response}")

                        # Step 4: Send the response to the agent
                        response = str(response).encode() + ProtocolConfig.END_OF_MESSAGE
                        writer.write(response)
                        await writer.drain()
                else:
                    self.logger.warning(f"Queue for agent {peername} already exists. Closing connection.")
            else:
                self.logger.info(f"Max connections reached. Rejecting new connection from {writer.get_extra_info('peername')}")
        except ConnectionResetError:
            self.logger.warning(f"Connection reset by {peername}")
            await self.handle_agent_quit(peername)
        except asyncio.CancelledError:
            self.logger.debug("Connection handling cancelled.")
            raise  # Ensure the exception propagates
        except Exception as e:
            self.logger.error(f"Unexpected error with client {peername}: {e}")
            raise
        finally:
            try:
                if peername in self.answers_queues:
                    # If the queue was created, remove it
                    if queue_created:
                        self.answers_queues.pop(peername)
                        self.logger.info(f"Removed queue for agent {peername}")
                    self.current_connections = max(0, self.current_connections - 1)
                writer.close()
                await writer.wait_closed()
            except Exception:
                # swallow exceptions on close to avoid crash on cleanup
                pass
    async def __call__(self, reader, writer):
        """
        Allow the server instance to be called as a coroutine.

        Args:
            reader (asyncio.StreamReader): Stream reader for the agent.
            writer (asyncio.StreamWriter): Stream writer for the agent.
        """
        await self.handle_new_agent(reader, writer)

class GameCoordinator:
    """
    Class for creation, and management of agent interactions in AI Dojo.
    """
    def __init__(self, game_host: str, game_port: int, service_host:str, service_port:int, allowed_roles=["Attacker", "Defender", "Benign"], task_config_file:str=None) -> None:
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
        # false_positives per agent_addr
        self._agent_false_positives = {}
    
    def _spawn_task(self, coroutine, *args, **kwargs)->asyncio.Task:
        "Helper function to make sure all tasks are registered for proper termination"
        task = asyncio.create_task(coroutine(*args, **kwargs))
        self._tasks.add(task)
        def remove_task(t):
            self._tasks.discard(t)
        task.add_done_callback(remove_task)  # Remove task when done
        return task

    async def shutdown_signal_handler(self):
        """Handle shutdown signals."""
        self.logger.info("Shutdown signal received. Setting shutdown flag.")
        self.shutdown_flag.set()

    async def create_agent_queue(self, agent_addr:tuple)->None:
        """
        Creates a queue for the given agent address if it doesn't already exist.
        """
        if agent_addr not in self._agent_response_queues:
            self._agent_response_queues[agent_addr] = asyncio.Queue()
            self.logger.info(f"Created queue for agent {agent_addr}. {len(self._agent_response_queues)} queues in total.")

    def convert_msg_dict_to_json(self, msg_dict:dict)->str:
        """
        Helper function to create text-base messge from a dictionary. Used in the Agent-Game communication.
        """
        try:
            # Convert message into string representation
            output_message = json.dumps(msg_dict)
        except Exception as e:
            self.logger.error(f"Error when converting msg to JSON:{e}")
            raise e
            # Send to anwer_queue
        return output_message
    
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

    async def _fetch_initialization_objects(self):
        """Send a REST request to MAIN and fetch initialization objects of CYST simulator."""
        async with ClientSession() as session:
            try:
                async with session.get(f"http://{self._service_host}:{self._service_port}/cyst_init_objects") as response:
                    if response.status == 200:
                        response = await response.json()
                        self.logger.debug(response)
                        env = Environment.create()
                        self._CONFIG_FILE_HASH = get_str_hash(response)
                        self._cyst_objects = env.configuration.general.load_configuration(response)
                        self.logger.debug(f"Initialization objects received:{self._cyst_objects}")
                        #self.task_config = ConfigParser(config_dict=response["task_configuration"])
                    else:
                        self.logger.error(f"Failed to fetch initialization objects. Status: {response.status}")
            except Exception as e:
               self.logger.error(f"Error fetching initialization objects: {e}")
        # Temporary fix
        self.task_config = ConfigParser(self._task_config_file)
    
    def _load_initialization_objects(self)->None:
        """
        Loads task configuration from a local file.
        """
        self.task_config = ConfigParser(self._task_config_file)
        self._cyst_objects = self.task_config.get_scenario()
        self._CONFIG_FILE_HASH = get_str_hash(str(self._cyst_objects))

    def _get_starting_position_per_role(self)->dict:
        """
        Method for finding starting position for each agent role in the game.
        """
        starting_positions = {}
        for agent_role in self.ALLOWED_ROLES:
            try:
                starting_positions[agent_role] = self.task_config.get_start_position(agent_role=agent_role)
                self.logger.info(f"Starting position for role '{agent_role}': {starting_positions[agent_role]}")
            except KeyError:
                starting_positions[agent_role] = {}
        return starting_positions
    
    def _get_win_condition_per_role(self)-> dict:
        """
        Method for finding wininng conditions for each agent role in the game.
        """
        win_conditions = {}
        for agent_role in self.ALLOWED_ROLES:
            try:
                win_conditions[agent_role] = self.task_config.get_win_conditions(agent_role=agent_role)
            except KeyError:
                win_conditions[agent_role] = {}
            self.logger.info(f"Win condition for role '{agent_role}': {win_conditions[agent_role]}")
        return win_conditions
    
    def _get_goal_description_per_role(self)->dict:
        """
        Method for finding goal description for each agent role in the game.
        """
        goal_descriptions ={}
        for agent_role in self.ALLOWED_ROLES:
            try:
                goal_descriptions[agent_role] = self.task_config.get_goal_description(agent_role=agent_role)
            except KeyError:
                goal_descriptions[agent_role] = ""
            self.logger.info(f"Goal description for role '{agent_role}': {goal_descriptions[agent_role]}")
        return goal_descriptions
    
    def _get_max_steps_per_role(self)->dict:
        """
        Method for finding max amount of steps in 1 episode for each agent role in the game.
        """
        max_steps = {role:self.task_config.get_max_steps(role) for role in self.ALLOWED_ROLES}
        return max_steps
    
    async def start_tcp_server(self):
        """
        Starts TPC sever for the agent communication.
        """
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


        # initialize the game objects
        if self._service_host: #get the task config using REST API
            self.logger.info(f"Fetching task configuration from {self._service_host}:{self._service_port}")
            await self._fetch_initialization_objects()
        elif self._task_config_file: # load task config locally from a file
            self.logger.info(f"Loading task configuration from file: {self._task_config_file}")
            self._load_initialization_objects()
        else:
            raise ValueError("Task configuration not specified")

             
        # Read configuration
        self._starting_positions_per_role = self._get_starting_position_per_role()
        self._win_conditions_per_role = self._get_win_condition_per_role()
        self._goal_description_per_role = self._get_goal_description_per_role()
        self._steps_limit_per_role = self._get_max_steps_per_role()
        self.logger.debug(f"Timeouts set to:{self._steps_limit_per_role}")
        if self.task_config.get_use_global_defender():
            self._global_defender = GlobalDefender()
        else:
            self._global_defender = None
        self._use_dynamic_ips = self.task_config.get_use_dynamic_addresses()
        self.logger.info(f"Change IP every episode set to: {self._use_dynamic_ips}")
        self._rewards = self.task_config.get_rewards(["step", "success", "fail", "false_positive"])
        self.logger.info(f"Rewards set to:{self._rewards}")
        self._min_required_players = self.task_config.get_required_num_players()
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
    
    async def run_game(self):
        """
        Task responsible for reading messages from the agent queue and processing them based on the ActionType.
        """
        while not self.shutdown_flag.is_set():
            # Read message from the queue
            agent_addr, message = await self._agent_action_queue.get()
            if message is not None:
                self.logger.info(f"Coordinator received from agent {agent_addr}: {message}.")
                try:  # Convert message to Action
                    action = Action.from_json(message)
                    self.logger.debug(f"\tConverted to: {action}.")
                except Exception as e:
                    self.logger.error(
                        f"Error when converting msg to Action using Action.from_json():{e}, {message}"
                    )
                match action.type:  # process action based on its type
                    case ActionType.JoinGame:
                        self.logger.debug(f"About agent {agent_addr}. Start processing of ActionType.JoinGame by {agent_addr}")
                        self.logger.debug(f"{action.type}, {action.type.value}, {action.type == ActionType.JoinGame}")
                        self._spawn_task(self._process_join_game_action, agent_addr, action)
                    case ActionType.QuitGame:
                        self.logger.debug(f"About agent {agent_addr}. Start processing of ActionType.QuitGame by {agent_addr}")
                        self._spawn_task(self._process_quit_game_action, agent_addr)
                    case ActionType.ResetGame:
                        self.logger.debug(f"About agent {agent_addr}. Start processing of ActionType.ResetGame by {agent_addr}")
                        self._spawn_task(self._process_reset_game_action, agent_addr, action)
                    case ActionType.ExfiltrateData | ActionType.FindData | ActionType.ScanNetwork | ActionType.FindServices | ActionType.ExploitService:
                        self.logger.debug(f"About agent {agent_addr}. Start processing of {action.type} by {agent_addr}")
                        self._spawn_task(self._process_game_action, agent_addr, action)
                    case ActionType.BlockIP:
                        self.logger.debug(f"About agent {agent_addr}. Start processing of {action.type} by {agent_addr}")
                        self._spawn_task(self._process_game_action, agent_addr, action)
                    case _:
                        self.logger.warning(f"About agent {agent_addr}. Unsupported action type: {action}!")
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
                if agent_role in self.ALLOWED_ROLES:
                    # add agent to the world
                    new_agent_game_state, new_agent_goal_state = await self.register_agent(agent_addr, agent_role, self._starting_positions_per_role[agent_role], self._win_conditions_per_role[agent_role])
                    if new_agent_game_state: # successful registration
                        async with self._agents_lock:
                            self.agents[agent_addr] = (agent_name, agent_role)
                            observation = self._initialize_new_player(agent_addr, new_agent_game_state)
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
                        await self._agent_response_queues[agent_addr].put(self.convert_msg_dict_to_json(output_message_dict))
                else:
                    self.logger.info(
                        f"\tError in registration, unknown agent role: {agent_role}!"
                    )
                    output_message_dict = {
                        "to_agent": agent_addr,
                        "status": str(GameStatus.BAD_REQUEST),
                        "message": f"Incorrect agent_role {agent_role}",
                    }
                    response_msg_json = self.convert_msg_dict_to_json(output_message_dict)
                    await self._agent_response_queues[agent_addr].put(response_msg_json)
            else:
                self.logger.info("\tError in registration, agent already exists!")
                output_message_dict = {
                        "to_agent": agent_addr,
                        "status": str(GameStatus.BAD_REQUEST),
                        "message": "Agent already exists.",
                    }
                response_msg_json = self.convert_msg_dict_to_json(output_message_dict)
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
        response_msg_json = self.convert_msg_dict_to_json(output_message_dict)
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
           
            async with self._agents_lock:
                self._add_step_to_trajectory(agent_addr, action, self._agent_rewards[agent_addr], new_state,end_reason=None)
            # add information to 'info' field if needed
            info = {}
            if self._agent_status[agent_addr] not in [AgentStatus.Playing, AgentStatus.PlayingWithTimeout]:
                info["end_reason"] = str(self._agent_status[agent_addr])
            new_observation = Observation(self._agent_states[agent_addr], self._agent_rewards[agent_addr], self._episode_ends[agent_addr], info=info)
            self._agent_observations[agent_addr] = new_observation
            output_message_dict = {
                "to_agent": agent_addr,
                "observation": observation_as_dict(new_observation),
                "status": str(GameStatus.OK),
            }
        response_msg_json = self.convert_msg_dict_to_json(output_message_dict)
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
                new_state = await self.reset_agent(agent, self.agents[agent][1], self._agent_starting_position[agent])
                new_observation = Observation(new_state, 0, False, {})
                async with self._agents_lock:
                    self._agent_states[agent] = new_state
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
        if agent_role.lower() == "attacker":
            self._agent_status[agent_addr] = AgentStatus.PlayingWithTimeout
        else:
            self._agent_status[agent_addr] = AgentStatus.Playing
        self._agent_trajectories[agent_addr] = self._reset_trajectory(agent_addr)
        self.logger.info(f"\tAgent {agent_name} ({agent_addr}), registred as {agent_role}")
        # create initial observation
        return Observation(self._agent_states[agent_addr], 0, False, {})

    async def register_agent(self, agent_id:tuple, agent_role:str, agent_initial_view:dict, agent_win_condition_view:dict)->tuple[GameState, GameState]:
        """
        Domain specific method of the environment. Creates the initial state of the agent.
        """
        raise NotImplementedError
    
    async def remove_agent(self, agent_id:tuple, agent_state:GameState)->bool:
        """
        Domain specific method of the environment. Creates the initial state of the agent.
        """
        raise NotImplementedError

    async def reset_agent(self, agent_id:tuple, agent_role:str, agent_initial_view:dict, agent_win_condition_view:dict)->tuple[GameState, GameState]:
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
        raise NotImplementedError
    
    async def reset(self)->bool:
        return NotImplemented

    def _initialize(self):
        """
        Initialize the game state and other necessary components. This is called at the start of the game after the configuration is loaded.
        """
        return NotImplemented

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
        goal_conditions = self._win_conditions_per_role[self.agents[agent_addr][1]]
        self.logger.debug(f"\tGoal conditions for {agent_addr}: {goal_conditions}.")
        state = self._agent_states[agent_addr]
        # For each part of the state of the game, check if the conditions are met
        goal_reached = {}    
        goal_reached["networks"] = set(goal_conditions["known_networks"]) <= set(state.known_networks)
        goal_reached["known_hosts"] = set(goal_conditions["known_hosts"]) <= set(state.known_hosts)
        goal_reached["controlled_hosts"] = set(goal_conditions["controlled_hosts"]) <= set(state.controlled_hosts)
        goal_reached["services"] = goal_dict_satistfied(goal_conditions["known_services"], state.known_services)
        goal_reached["data"] = goal_dict_satistfied(goal_conditions["known_data"], state.known_data)
        goal_reached["known_blocks"] = goal_dict_satistfied(goal_conditions["known_blocks"], state.known_blocks)
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

    def _add_step_to_trajectory(self, agent_addr:tuple, action:Action, reward:float, next_state:GameState, end_reason:str=None)-> None:
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
    
    def _store_trajectory_to_file(self, agent_addr:tuple, location="./trajectories")-> None:
        self.logger.debug(f"Storing Trajectory of {agent_addr}in file")
        if agent_addr in self._agent_trajectories:
            agent_name, agent_role = self.agents[agent_addr] 
            filename = os.path.join(location, f"{datetime.now():%Y-%m-%d}_{agent_name}_{agent_role}.jsonl")
            with jsonlines.open(filename, "a") as writer:
                writer.write(self._agent_trajectories[agent_addr])
            self.logger.info(f"Trajectory of {agent_addr} strored in {filename}")
    
    def is_agent_benign(self, agent_addr:tuple)->bool:
        """
        Check if the agent is benign (defender, normal)
        """
        if agent_addr not in self.agents:
            return False
        return self.agents[agent_addr][1].lower() in ["defender", "benign"]
import jsonlines
import argparse
import logging
import json
import asyncio
import enum
from datetime import datetime
from env.worlds.network_security_game import NetworkSecurityEnvironment
from env.worlds.network_security_game_real_world import NetworkSecurityEnvironmentRealWorld
from env.worlds.aidojo_world import AIDojoWorld
from env.worlds.cyst_wrapper import CYSTWrapper
from env.game_components import Action, Observation, ActionType, GameStatus, GameState
from utils.utils import observation_as_dict, get_logging_level, get_file_hash
from pathlib import Path
import os
import signal
from env.global_defender import stochastic_with_threshold
from utils.utils import ConfigParser

from coordinator import Coordinator, ConnectionLimitProtocol
from http.server import BaseHTTPRequestHandler, HTTPServer
from aiohttp import ClientSession
from cyst.api.environment.environment import Environment

class GameCoordinator:
    def __init__(self, game_host: str, game_port: int, service_host, service_port, world_type, allowed_roles=["Attacker", "Defender", "Benign"]) -> None:
        self.host = game_host
        self.port = game_port
        self._service_host = service_host
        self._service_port = service_port
        self.logger = logging.getLogger("AIDojo-GameCoordinator")
        self._world_type = world_type
        self.ALLOWED_ROLES = allowed_roles
        self._cyst_objects = None
        self._cyst_object_string = None
        self._tasks = set()
        self.shutdown_flag = asyncio.Event()
        self._reset_event = asyncio.Event()
        self._reset_lock = asyncio.Lock()
        self._agents_lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(2) 
        
        # prepare agent communication
        self._agent_action_queue = asyncio.Queue()
        self._agent_response_queues = {}
        
        # agent information
        self.agents = {}
        # step counter per agent_addr (int)
        self._agent_steps = {}
        # reset request per agent_addr (bool)
        self._reset_requests = {}
        self._agent_observations = {}
        # starting per agent_addr (dict)
        self._agent_starting_position = {}
        # current state per agent_addr (GameState)
        self._agent_states = {}
        # last action played by agent (Action)
        self._agent_last_action = {}
        # agent status dict {agent_addr: int}
        self._agent_rewards = {}
        # trajectories per agent_addr
        self._agent_trajectories = {}
    
    async def spawn_task(self, coroutine, *args, **kwargs):
        "Helper function to make sure all tasks are registered for proper termination"
        task = asyncio.create_task(coroutine(*args, **kwargs))
        self._tasks.add(task)
        def remove_task(t):
            self._tasks.discard(t)
        task.add_done_callback(remove_task)  # Remove task when done
        return task

    async def create_agent_queue(self, addr):
        """
        Create a queue for the given agent address if it doesn't already exist.
        """
        if addr not in self._agent_response_queues:
            self._agent_response_queues[addr] = asyncio.Queue()
            self.logger.info(f"Created queue for agent {addr}. {len(self._agent_response_queues)} queues in total.")

    def convert_msg_dict_to_json(self, msg_dict)->str:
            try:
                # Convert message into string representation
                output_message = json.dumps(msg_dict)
            except Exception as e:
                self.logger.error(f"Error when converting msg to Json:{e}")
                raise e
                # Send to anwer_queue
            return output_message
    
    def run(self)->None:
        """
        Wrapper for ayncio run function. Starts all tasks in AIDojo
        """
        try:
            asyncio.run(self.start_tasks())
        except KeyboardInterrupt:
            self.logger.info("Shutdown requested by user.")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
        finally:
            self.logger.info("Coordinator has exited.")

    async def _fetch_initialization_objects(self):
        """Send a REST request to MAIN and fetch initialization objects of CYST simulator."""
        async with ClientSession() as session:
            try:
                async with session.get(f"http://{self._service_host}:{self._service_port}/cyst_init_objects") as response:
                    if response.status == 200:
                        response = await response.json()
                        self.logger.debug(response)
                        env = Environment.create()
                        self._CONFIG_FILE_HASH = hash(response)
                        self._cyst_objects = env.configuration.general.load_configuration(response)
                        self.logger.debug(f"Initialization objects received:{self._cyst_objects}")
                    else:
                        self.logger.error(f"Failed to fetch initialization objects. Status: {response.status}")
            except Exception as e:
               self.logger.error(f"Error fetching initialization objects: {e}")

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
                # win_conditions[agent_role] = self._world.update_goal_dict(
                #     self.task_config.get_win_conditions(agent_role=agent_role)
                # )
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
        max_steps = {
            "Attacker":20,
            "Defender":20,
            "Benign":20,
        }
        # for agent_role in self.ALLOWED_ROLES:
        #     try:
        #         max_steps[agent_role] = self.task_config.get_max_steps(agent_role)
        #     except KeyError:
        #         max_steps[agent_role] = None
        #     self.logger.info(f"Max steps in episode for '{agent_role}': {max_steps[agent_role]}")
        return max_steps
    
    async def start_tcp_server(self):
        try:
            self.logger.info("Starting the server listening for agents")
            server = await asyncio.start_server(
                ConnectionLimitProtocol(
                    self._agent_action_queue,
                    self._agent_response_queues,
                    max_connections=2
                ),
                self.host,
                self.port
            )
            addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
            self.logger.info(f"\tServing on {addrs}")
            while not self.shutdown_flag.is_set():
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            print("TCP server task was cancelled")
        except Exception as e:
            self.logger.error(f"TCP server failed: {e}")
        finally:
            server.close()
            await server.wait_closed()
            print("TCP server has been shut down")

    async def start_tasks(self):
        """
        High level funciton to start all the other asynchronous tasks.
        - Reads the conf of the coordinator
        - Creates queues
        - Start the main part of the coordinator
        - Start a server that listens for agents
        """
        # initialize the game
        self.logger.info("Requesting CYST configuration")
        if self._world_type == "cyst":
            await self._fetch_initialization_objects()
        else: # read it from a file
            pass
        
        ##### REMOVE LATER #####
        self.task_config = ConfigParser("./env/netsecevn_conf_cyst_integration.yaml")
        self._starting_positions_per_role = self._get_starting_position_per_role()
        self._win_conditions_per_role = self._get_win_condition_per_role()
        self._goal_description_per_role = self._get_goal_description_per_role()
        self._steps_limit_per_role = self._get_max_steps_per_role()
        self._use_global_defender = self.task_config.get_use_global_defender()


        # start server for agent communication
        await  self.spawn_task(self.start_tcp_server)
       
        try:
            while not self.shutdown_flag.is_set():
                # Read message from the queue
                agent_addr, message = await self._agent_action_queue.get()
                if message is not None:
                    self.logger.debug(f"Coordinator received: {message}.")
                    try:  # Convert message to Action
                        action = Action.from_json(message)
                        self.logger.debug(f"\tConverted to: {action}.")
                    except Exception as e:
                        self.logger.error(
                            f"Error when converting msg to Action using Action.from_json():{e}, {message}"
                        )
                    match action.type:  # process action based on its type
                        case ActionType.JoinGame:
                            self.logger.debug(f"Start processing of ActionType.JoinGame by {agent_addr}")
                            self.logger.debug(f"{action.type}, {action.type.value}, {action.type == ActionType.JoinGame}")
                            await self.spawn_task(self._process_join_game_action, agent_addr, action)
                        case ActionType.QuitGame:
                            self.logger.debug(f"Start processing of ActionType.QuitGame by {agent_addr}")
                            await self.spawn_task(self._process_quit_game_action, agent_addr)
                        case ActionType.ResetGame:
                            self.logger.debug(f"Start processing of ActionType.ResetGame by {agent_addr}")
                            await self.spawn_task(self._process_reset_game_action, agent_addr, action)
                        case ActionType.ExfiltrateData | ActionType.FindData | ActionType.ScanNetwork | ActionType.FindServices | ActionType.ExploitService:
                            self.logger.debug(f"Start processing of{action.type} by {agent_addr}")
                            await self.spawn_task(self._process_game_action, agent_addr, action)
                        # case ActionType.ResetGame:
                        #     self._reset_requests[agent_addr] = True
                        #     self._agent_statuses[agent_addr] = AgentStatus.ResetRequested
                        #     self.logger.info(f"Coordinator received from RESET request from agent {agent_addr}")
                        #     if all(self._reset_requests.values()):
                        #         # should we discard the queue here?
                        #         self.logger.info("All active agents requested reset")
                        #         # send WORLD reset request to the world
                        #         await self._world_action_queue.put(("world", Action(ActionType.ResetGame, params={}), None))
                        #         # send request for each of the agents (to get new initial state)
                        #         for agent in self._reset_requests:
                        #             await self._world_action_queue.put((agent, Action(ActionType.ResetGame, params={}), self._agent_starting_position[agent]))
                        #     else:
                        #         self.logger.info("\t Waiting for other agents to request reset")
                        # case _:
                        #     # actions in the game
                        #     await self._process_generic_action(agent_addr, action)
                    await asyncio.sleep(0.001)
        except asyncio.CancelledError:
           self.logger.info("Coordinator run cancelled")
        finally:
            self.logger.info("Shutting down...")
            for task in self._tasks:
                task.cancel()  # Cancel each active task
            await asyncio.gather(*self._tasks, return_exceptions=True)  # Wait for all tasks to finish
            self.logger.info("All tasks shut down.")
    
    async def _process_join_game_action(self, agent_addr: tuple, action: Action)->None:
        """
        Method for processing Action of type ActionType.JoinGame
        Inputs: 
            -   agent_addr (tuple)
            -   JoingGame Action
        Outputs: None
        """
        try:
            async with self._semaphore:
                self.logger.info(f"New Join request by  {agent_addr}.")
                if agent_addr not in self.agents:
                    agent_name = action.parameters["agent_info"].name
                    agent_role = action.parameters["agent_info"].role
                    if agent_role in self.ALLOWED_ROLES:
                        # add agent to the world
                        new_agent_game_state = await self.register_agent(agent_addr, agent_role)
                        if new_agent_game_state: # successful registration
                            async with self._agents_lock:
                                self.agents[agent_addr] = (agent_name, agent_role)
                                observation = self._initialize_new_player(agent_addr, new_agent_game_state)
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
                            # await self._world_action_queue.put((agent_addr, Action(action_type=ActionType.JoinGame, params=action.parameters), self._starting_positions_per_role[agent_role]))
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
            await self.remove_agent(agent_addr, self._agent_states[agent_addr])
            agent_info = await self._remove_agent_from_game(agent_addr)
            self.logger.info(f"Agent {agent_addr} removed from the game. {agent_info}")
        except asyncio.CancelledError:
            self.logger.debug(f"Proccessing QuitAction of agent {agent_addr} interrupted")
            raise  # Ensure the exception propagates
        finally:
            self.logger.debug(f"Cleaning up after QuitGame for {agent_addr}.")
    
    async def _process_reset_game_action(self, agent_addr: tuple, action:Action)->None:
        async with self._reset_lock:
             # add reset request for this agent
            self._reset_requests[agent_addr] = True
            self.logger.warning(self._reset_requests.values())
            if all(self._reset_requests.values()):
                # all agents want reset - reset the world
                new_state = await self.reset_agent(agent_addr)
                self._reset_event.set()
        # wait until the event is set
        await self._reset_event.wait()
        new_state = await self.reset_agent(agent_addr)
        new_observation = Observation(self._agent_states[agent_addr], 0, False, {})
        async with self._agents_lock:
            self._agent_states[agent_addr] = new_state
            self._agent_observations[agent_addr] = new_observation
        output_message_dict = {
            "to_agent": agent_addr,
            "status": str(GameStatus.RESET_DONE),
            "observation": observation_as_dict(new_observation),
            "message": {
                        "message": "Resetting Game and starting again.",
                        "max_steps": self._steps_limit_per_role[self.agents[agent_addr][1]],
                        "goal_description": self._goal_description_per_role[self.agents[agent_addr][1]],
                         "configuration_hash": self._CONFIG_FILE_HASH
                        },
        }
        response_msg_json = self.convert_msg_dict_to_json(output_message_dict)
        await self._agent_response_queues[agent_addr].put(response_msg_json)
        self.logger.debug("Reset approved by all agents")
        async with self._reset_lock:
            # remove reset request for this agent
            self._reset_requests[agent_addr] = False
            if not any(self._reset_requests.values()):
                # all agents resetted.Clear the rest event
                self.logger.debug(f"Clearing the reset event.{agent_addr}")
                self._reset_event.clear()

    async def _process_game_action(self, agent_addr: tuple, action:Action)->None:
        pass
    
    def _initialize_new_player(self, agent_addr:tuple, agent_current_state:GameState) -> Observation:
        """
        Method to initialize new player upon joining the game.
        Returns initial observation for the agent based on the agent's role
        """
        self.logger.info(f"\tInitializing new player{agent_addr}")
        agent_name, agent_role = self.agents[agent_addr]
        self._agent_steps[agent_addr] = 0
        self._reset_requests[agent_addr] = False
        self._agent_starting_position[agent_addr] = self._starting_positions_per_role[agent_role]
        self._agent_states[agent_addr] = agent_current_state

        if self.task_config.get_store_trajectories() or self._use_global_defender:
            self._agent_trajectories[agent_addr] = self._reset_trajectory(agent_addr)
        self.logger.info(f"\tAgent {agent_name} ({agent_addr}), registred as {agent_role}")
        return Observation(self._agent_states[agent_addr], 0, False, {})

    async def register_agent(self, agent_addr:tuple, agent_role:str)->GameState:
        """
        Domain specific method of the environment. Creates the initial state of the agent.
        """
        self.logger.debug("Registering agent in the world.")
        return GameState()
    
    async def remove_agent(self, agent_addr:tuple, agent_state:GameState)->bool:
        """
        Domain specific method of the environment. Creates the initial state of the agent.
        """
        self.logger.debug("Registering agent in the world.")
        return True
    
    async def reset_agent(self, agent_addr)->GameState:
        return GameState()

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
                async with self._reset_lock:
                    agent_info["reset_request"] = self._reset_requests.pop(agent_addr)
                    # check if this agent was not preventing reset 
                    if any(self._reset_requests.values()):
                        self._reset_event.set()
                agent_info["end_reward"] = self._agent_rewards.pop(agent_addr, None)
                agent_info["agent_info"] = self.agents.pop(agent_addr)
                self.logger.debug(f"\t{agent_info}")
            else:
                self.logger.info(f"\t Player {agent_addr} not present in the game!")
            return agent_info

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NetSecGame Coordinator Server Author: Ondrej Lukas ondrej.lukas@aic.fel.cvut.cz",
        usage="%(prog)s [options]",
    )
    
    
    parser.add_argument(
        "-l",
        "--debug_level",
        help="Define the debug level for the logs. DEBUG, INFO, WARNING, ERROR, CRITICAL",
        action="store",
        required=False,
        type=str,
        default="DEBUG",
    )
    
    parser.add_argument(
        "-w",
        "--world_type",
        help="Define the world which is used as backed. Default NSE",
        action="store",
        required=False,
        type=str,
        default="cyst",
    )
    
    parser.add_argument(
        "-gh",
        "--game_host",
        help="host where to run the game server",
        action="store",
        required=False,
        type=str,
        default="127.0.0.1",
    )
    
    parser.add_argument(
        "-gp",
        "--game_port",
        help="Port where to run the game server",
        action="store",
        required=False,
        type=int,
        default="9000",
    )
    
    parser.add_argument(
        "-sh",
        "--service_host",
        help="Host where to run the config server",
        action="store",
        required=False,
        type=str,
        default="127.0.0.1",
    )
    
    parser.add_argument(
        "-sp",
        "--service_port",
        help="Port where to listen for cyst config",
        action="store",
        required=False,
        type=int,
        default="9009",
    )


    args = parser.parse_args()
    print(args)
    # Set the logging
    log_filename = Path("coordinator.log")
    if not log_filename.parent.exists():
        os.makedirs(log_filename.parent)

    # Convert the logging level in the args to the level to use
    pass_level = get_logging_level(args.debug_level)

    logging.basicConfig(
        filename=log_filename,
        filemode="w",
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=pass_level,
    )
  
    game_server = GameCoordinator(args.game_host, args.game_port, args.service_host , args.service_port, args.world_type)
    # Run it!
    game_server.run()
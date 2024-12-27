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

@enum.unique
class AgentStatus(str, enum.Enum):
    """
    Class representing the current status for each agent connected to the coordinator
    """
    JoinRequested = "JoinRequested"
    Ready = "Ready"
    Playing = "Playing"
    PlayingActive = "PlayingActive"
    FinishedMaxSteps = "FinishedMaxSteps"
    FinishedBlocked = "FinishedBlocked"
    FinishedGoalReached = "FinishedGoalReached"
    FinishedGameLost = "FinishedGameLost"
    ResetRequested = "ResetRequested"
    Quitting = "Quitting"



class GameCoordinator:
    def __init__(self, game_host: str, game_port: int, service_host, service_port, world_type, allowed_roles=["Attacker", "Defender", "Benign"]) -> None:
        self.host = game_host
        self.port = game_port
        self._service_host = service_host
        self._service_port = service_port
        self.logger = logging.getLogger("AIDojo-GameCoordinator")
        self._world_type = world_type
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
        self._agent_observations = {}
        # starting per agent_addr (dict)
        self._agent_starting_position = {}
        # current state per agent_addr (GameState)
        self._agent_states = {}
        # last action played by agent (Action)
        self._agent_last_action = {}
        # agent status dict {agent_addr: AgentStatus}
        self._agent_statuses = {}
        # agent status dict {agent_addr: int}
        self._agent_rewards = {}
        # trajectories per agent_addr
        self._agent_trajectories = {}
        
    async def create_agent_queue(self, addr):
        """
        Create a queue for the given agent address if it doesn't already exist.
        """
        if addr not in self._agent_response_queues:
            self._agent_response_queues[addr] = asyncio.Queue()
            self.logger.info(f"Created queue for agent {addr}. {len(self._agent_response_queues)} queues in total.")

    async def _send_REST_request(self, request_dict)->dict:
        async with ClientSession() as session:
            async with session.post(f"{self._service_host}:{self._service_port}/coordinator", json=request_dict) as resp:
                response = await resp.json()
            print("MAIN response:", response)
            return response
    
    def run(self)->None:
        """
        Wrapper for ayncio run function. Starts all tasks in AIDojo
        """
        asyncio.run(self.start_tasks())

    async def _fetch_initialization_objects(self):
        """Send a REST request to MAIN and fetch initialization objects."""
        async with ClientSession() as session:
            #try:
            async with session.get(f"http://{self._service_host}:{self._service_port}/cyst_init_objects") as response:
                if response.status == 200:
                    response = await response.json()
                    self.logger.debug(response)
                    env = Environment.create()
                    self._cyst_objects = env.configuration.general.load_configuration(response)
                    self.logger.debug(f"Initialization objects received:{self._cyst_objects}")
                else:
                    self.logger.error(f"Failed to fetch initialization objects. Status: {response.status}")
            #except Exception as e:
            #    self.logger.error(f"Error fetching initialization objects: {e}")

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
            await asyncio.Event().wait()  # Keep the server running indefinitely
        except asyncio.CancelledError:
            print("TCP server task was cancelled")
            raise
        except Exception as e:
            self.logger.error(f"TCP server failed: {e}")
            raise
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
        self.logger.info("Requesting CYST configuration")
        if self._world_type == "cyst":
            await self._fetch_initialization_objects()
        else: # read it from a file
            pass

        # # start server for agent communication
        # tcp_server_task = asyncio.create_task(self.start_tcp_server())
        # world_response_task = asyncio.create_task(self._handle_world_responses())
        # world_processing_task = asyncio.create_task(self._world.handle_incoming_action())
        # try:
        #     while True:
        #         # Read message from the queue
        #         agent_addr, message = await self.self._agent_action_queue.get()
        #         if message is not None:
        #             self.logger.debug(f"Coordinator received: {message}.")
        #             try:  # Convert message to Action
        #                 action = Action.from_json(message)
        #                 self.logger.debug(f"\tConverted to: {action}.")
        #             except Exception as e:
        #                 self.logger.error(
        #                     f"Error when converting msg to Action using Action.from_json():{e}, {message}"
        #                 )
        #             match action.type:  # process action based on its type
        #                 case ActionType.JoinGame:
        #                     self.logger.debug(f"Start processing of ActionType.JoinGame by {agent_addr}")
        #                     self.logger.debug(f"{action.type}, {action.type.value}, {action.type == ActionType.JoinGame}")
        #                     await self._process_join_game_action(agent_addr, action)
        #                 case ActionType.QuitGame:
        #                     self.logger.info(f"Coordinator received from QUIT message from agent {agent_addr}")
        #                     # update agent status
        #                     self._agent_statuses[agent_addr] = AgentStatus.Quitting
        #                     # forward the message to the world
        #                     await self._world_action_queue.put((agent_addr, action, self._agent_states[agent_addr]))
        #                 case ActionType.ResetGame:
        #                     self._reset_requests[agent_addr] = True
        #                     self._agent_statuses[agent_addr] = AgentStatus.ResetRequested
        #                     self.logger.info(f"Coordinator received from RESET request from agent {agent_addr}")
        #                     if all(self._reset_requests.values()):
        #                         # should we discard the queue here?
        #                         self.logger.info("All active agents requested reset")
        #                         # send WORLD reset request to the world
        #                         await self._world_action_queue.put(("world", Action(ActionType.ResetGame, params={}), None))
        #                         # send request for each of the agents (to get new initial state)
        #                         for agent in self._reset_requests:
        #                             await self._world_action_queue.put((agent, Action(ActionType.ResetGame, params={}), self._agent_starting_position[agent]))
        #                     else:
        #                         self.logger.info("\t Waiting for other agents to request reset")
        #                 case _:
        #                     # actions in the game
        #                     await self._process_generic_action(agent_addr, action)
        #         await asyncio.sleep(0)
        # except asyncio.CancelledError:
        #     self.logger.info("Terminating GameCoordinator")
        #     tcp_server_task.cancel()
        #     world_response_task.cancel()
        #     world_processing_task.cancel()
        #     await asyncio.gather(tcp_server_task, world_processing_task, world_response_task, return_exceptions=True)
        #     raise
        # finally:
        #     self.logger.info("GameCoordinator termination completed")


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
  
    ai_dojo = GameCoordinator(args.game_host, args.game_port, args.service_host , args.service_port, args.world_type)
    # Run it!
    ai_dojo.run()
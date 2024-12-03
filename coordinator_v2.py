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
from aiohttp import web
from cyst.api.environment.environment import Environment

class AIDojo:
    def __init__(self, game_host: str, game_port: int, service_host, service_port, world_type) -> None:
        self.host = game_host
        self.port = game_port
        self._service_host = service_host
        self._service_port = service_port
        self.logger = logging.getLogger("AIDojo-main")
        self._world_type = world_type
        self._cyst_objects = None
        self._cyst_object_string = None
        # prepare channels for coordinator
        self._agent_action_queue = asyncio.Queue()
        self._agent_response_queues = {}
        # event for the coordinator to start
        self._start_event = asyncio.Event()

    async def create_agent_queue(self, addr):
        """
        Create a queue for the given agent address if it doesn't already exist.
        """
        if addr not in self._agent_response_queues:
            self._agent_response_queues[addr] = asyncio.Queue()
            self.logger.info(f"Created queue for agent {addr}. {len(self._agent_response_queues)} queues in total.")

    def run(self)->None:
        """
        Wrapper for ayncio run function. Starts all tasks in AIDojo
        """
        asyncio.run(self.start_tasks())
   
    async def start_tasks(self):
        """
        High level funciton to start all the other asynchronous tasks.
        - Reads the conf of the coordinator
        - Creates queues
        - Start the main part of the coordinator
        - Start a server that listens for agents
        """      
        self.logger.info("Starting all tasks")
        self.logger.info("Starting JSON listener server")
        json_listener_task = asyncio.create_task(self.start_json_listener())
        self.logger.info("Waiting for JSON to initialize Coordinator and Agent Server...")
        await json_listener_task  # Wait until JSON is received

        # create coordinator
        self._coordinator = Coordinator(
            self._agent_action_queue,
            self._agent_response_queues,
            self._cyst_objects,
            allowed_roles=["Attacker", "Defender", "Benign"],
            world_type = self._world_type,
            net_sec_config_file="env/netsecevn_conf_cyst_integration.yaml"
        )

        self.logger.info("Starting Coordinator taks")
        coordinator_task = asyncio.create_task(self._coordinator.run())
        tcp_server_task = asyncio.create_task(self.start_tcp_server())
        

        try:
            await asyncio.gather(tcp_server_task, coordinator_task, return_exceptions=True)
        except asyncio.CancelledError:
            self.logger.info("Starting AIDojo termination")
            for task in [tcp_server_task, coordinator_task]:
                task.cancel()
            # Wait for all tasks to be cancelled
            await asyncio.gather(tcp_server_task, coordinator_task, return_exceptions=True)
            self.logger.info("All worker tasks have been cancelled")
            raise
        finally:
            self.logger.info("AIDojo termination completed")
    
    async def start_tcp_server(self):
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

        try:
            await asyncio.Event().wait()  # Keep the server running indefinitely
        except asyncio.CancelledError:
            print("TCP server task was cancelled")
        finally:
            server.close()
            await server.wait_closed()
            print("TCP server has been shut down")
            
    async def start_json_listener(self):
        """
        Starts an HTTP server to listen for JSON data.
        """

        async def handle_json_request(request):
            """
            Handles incoming JSON requests synchronously.
            Blocks until the JSON request has been processed.
            """
            try:
                # Parse incoming JSON
                data = await request.json()
                self.logger.info(f"Received JSON: {data}")

                # Signal the event to start the Coordinator and agent server
                env = Environment.create()
                self._cyst_objects = env.configuration.general.load_configuration(data)
                self._start_event.set()
                return web.json_response({"status": "success", "received_data": data})
            except Exception as e:
                self.logger.error(f"Error processing JSON: {str(e)}")
                return web.json_response({"status": "error", "message": str(e)}, status=400)
        try:
            # Blocking server setup
            app = web.Application()
            app.router.add_post("/", handle_json_request)

            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, self._service_host, self._service_port)
            self.logger.info(f"Starting JSON server on {self._service_host}:{self._service_port}")
            await site.start()

            # Wait for the event to proceed
            await self._start_event.wait()
            # Stop the JSON server after processing the first request
            self.logger.info("Stopping JSON listener after receiving request.")
        except asyncio.CancelledError:
            self.logger.info(f"Service Server cancelled")
        finally:
            await runner.cleanup()
            print(f"Worker 'Service Server' has cleaned up")

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
  
    ai_dojo = AIDojo(args.game_host, args.game_port, args.service_host , args.service_port, args.world_type)
    # Run it!
    ai_dojo.run()
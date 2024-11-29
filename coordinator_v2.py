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


class AIDojo:
    def __init__(self, game_host: str, game_port: int, service_host, service_port, world_type) -> None:
        self.host = game_host
        self.port = game_port
        self._service_host = service_host
        self._service_port = service_port
        self.logger = logging.getLogger("AIDojo-main")
        self._world_type = world_type
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
        loop = asyncio.get_running_loop()
        self.logger.info("Starting JSON listener server")
        json_listener_task = asyncio.create_task(self.start_json_listener())
        self.logger.info("Waiting for JSON to initialize Coordinator and Agent Server...")
        await self._start_event.wait()  # Wait until JSON is received

        # create coordinator
        self._coordinator = Coordinator(
            self._agent_action_queue,
            self._agent_response_queues,
            self._cyst_objects,
            allowed_roles=["Attacker", "Defender", "Benign"],
            world_type = self._world_type,
        )

        self.logger.info("Starting Coordinator taks")
        coordinator_task = asyncio.create_task(self._coordinator.run())

        self.logger.info("Starting the server listening for agents")
        running_server = await asyncio.start_server(
            ConnectionLimitProtocol(
                self._agent_action_queue,
                self._agent_response_queues,
                max_connections=2
            ),
            self.host,
            self.port
        )
        addrs = ", ".join(str(sock.getsockname()) for sock in running_server.sockets)
        self.logger.info(f"\tServing on {addrs}")
        
        # prepare the stopping event for keyboard interrupt
        stop = loop.create_future()
        
        # register the signal handler to the stopping event
        loop.add_signal_handler(signal.SIGINT, stop.set_result, None)

        await stop # Event that triggers stopping the AIDojo
        # Stop the server
        self.logger.info("Initializing server shutdown")
        running_server.close()
        await running_server.wait_closed()
        self.logger.info("\tServer stopped")
        # Stop coordinator taks
        self.logger.info("Initializing coordinator shutdown")
        coordinator_task.cancel()
        await asyncio.gather(coordinator_task, return_exceptions=True)
        self.logger.info("\tCoordinator stopped")

        self.logger.info("Shutting down JSON listener")
        json_listener_task.cancel()
        await asyncio.gather(json_listener_task, return_exceptions=True)

        # Everything stopped correctly, terminate
        self.logger.info("AIDojo terminating")
    
    async def start_json_listener(self):
        """
        Starts an HTTP server to listen for JSON data on localhost:4444.
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
                if "cyst_config" in data:
                    self._cyst_objects = data["cyst_config"]
                    self._start_event.set()
                    return web.json_response({"status": "success", "received_data": data})
                else:
                    # Respond to the client
                    return web.json_response({"status": "error", "received_data": data}, status=400)
            except Exception as e:
                self.logger.error(f"Error processing JSON: {str(e)}")
                return web.json_response({"status": "error", "message": str(e)}, status=400)

        # Blocking server setup
        app = web.Application()
        app.router.add_post("/", handle_json_request)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, 'localhost', 4444)
        self.logger.info("Starting JSON server on localhost:4444")
        await site.start()

        # Wait for the event to proceed
        await self.start_event.wait()
        # Stop the JSON server after processing the first request
        self.logger.info("Stopping JSON listener after receiving request.")
        await runner.cleanup()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NetSecGame Coordinator Server Author: Ondrej Lukas ondrej.lukas@aic.fel.cvut.cz",
        usage="%(prog)s [options]",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Verbosity level. This shows more info about the results.",
        action="store",
        required=False,
        type=int,
    )
    parser.add_argument(
        "-c",
        "--configfile",
        help="Configuration file.",
        action="store",
        required=False,
        type=str,
        default="coordinator.conf",
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

    # load config for coordinator
    with open(args.configfile, "r") as jfile:
        confjson = json.load(jfile)
    
    host = confjson.get("host", None)
    port = confjson.get("port", None)
    world_type = confjson.get('world_type', 'cyst')

   
    ai_dojo = AIDojo(host, port,host,4444, "cyst")
    # Run it!
    ai_dojo.run()
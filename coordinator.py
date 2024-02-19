#!/usr/bin/env python
# Server for the Aidojo project, coordinator
# Author: sebastian garcia, sebastian.garcia@agents.fel.cvut.cz
# Author: Ondrej Lukas, ondrej.lukas@aic.fel.cvut.cz
import argparse
import logging
import json
import asyncio
from env.network_security_game import NetworkSecurityEnvironment
from env.game_components import Action, Observation, ActionType, GameStatus
from utils.utils import observation_as_dict
from pathlib import Path
import os
import signal

class AIDojo:
    def __init__(self, host: str, port: int, net_set_config: str) -> None:
        self.host = host
        self.port = port
        self.logger = logging.getLogger("AIDojo-main")
        self._action_queue = asyncio.Queue()
        self._answer_queue = asyncio.Queue()
        self._coordinator = Coordinator(
            self._action_queue,
            self._answer_queue,
            net_set_config,
            allowed_roles=["Attacker", "Defender", "Human"],
        )

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

        self.logger.info("Starting Coordinator taks")
        coordinator_task = asyncio.create_task(self._coordinator.run())

        self.logger.info("Starting the server listening for agents")
        running_server = await asyncio.start_server(
            ConnectionLimitProtocol(
                self._action_queue,
                self._answer_queue,
                max_connections=1
            ),
            host,
            port
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
        # Everything stopped correctly, terminate
        self.logger.info("AIDojo terminating")

class ActionProcessor:
    def __init__(self) -> None:
        self._logger = logging.getLogger("Coordinator-ActionProcessor")
        self._observations = {}
        self._logger.info("Action Processor created")

    def process_message_from_agent(self, agent_id: int, action: Action) -> Action:
        """
        Method for processing message coming from the agent for the game engine.
        input str JSON
        output Action
        """
        self._logger.debug(f"Processing message from agent {agent_id}: {Action}")
        a = action
        return a

    def generate_observation_msg_for_agent(self, agent_id: int, new_observation: Observation) -> str:
        """
        Method for processing a NetSecGame gamestate into an partial observation for an agent

        Action.from
        """
        self._logger.debug(f"Processing message to agent {agent_id}: {new_observation}")
        self._observations[agent_id] = new_observation
        msg_for_agent = observation_as_dict(new_observation)
        return msg_for_agent


class ConnectionLimitProtocol(asyncio.Protocol):
    def __init__(self, actions_queue, answers_queue, max_connections):
        self.actions_queue = actions_queue
        self.answers_queue = answers_queue
        self.max_connections = max_connections
        self.current_connections = 0
        self.logger = logging.getLogger("AIDojo-Server")

    async def handle_new_agent(self, reader, writer):
        async def send_data_to_agent(writer, data: str) -> None:
            """
            Send the world to the agent
            """
            writer.write(bytes(str(data).encode()))

        # Check if the maximum number of connections has been reached
        if self.current_connections >= self.max_connections:
            self.logger.info(
                f"Max connections reached. Rejecting new connection from {writer.get_extra_info('peername')}"
            )
            writer.close()
            return

        # Increment the count of current connections
        self.current_connections += 1

        # Handle the new agent
        try:
            addr = writer.get_extra_info("peername")
            self.logger.info(f"New agent connected: {addr}")
            while True:
                data = await reader.read(500)
                raw_message = data.decode().strip()
                if len(raw_message):
                    self.logger.info(
                        f"Handler received from {addr}: {raw_message!r}, len={len(raw_message)}"
                    )

                    # Put the message and agent information into the queue
                    await self.actions_queue.put((addr, raw_message))

                    # Read messages from the queue and send to the agent
                    message = await self.answers_queue.get()
                    if message:
                        self.logger.info(f"Handle sending to agent {addr}: {message!r}")
                        await send_data_to_agent(writer, message)
                        try:
                            await writer.drain()
                        except ConnectionResetError:
                            self.logger.info("Connection lost. Agent disconnected.")
                else:
                    self.logger.info(
                        f"Handler received from {addr}: {raw_message!r}, len={len(raw_message)}"
                    )
                    self.logger.info(
                        f"\tEmpty message, terminating agent on address {addr}"
                    )
                    break
        except KeyboardInterrupt:
            self.logger.debug("Terminating by KeyboardInterrupt")
            raise SystemExit
        except Exception as e:
            self.logger.error(f"Exception in handle_new_agent(): {e}")
        finally:
            # Decrement the count of current connections
            self.current_connections -= 1

    async def __call__(self, reader, writer):
        await self.handle_new_agent(reader, writer)


class Coordinator:
    def __init__(self, actions_queue, answers_queue, net_set_config, allowed_roles):
        self._actions_queue = actions_queue
        self._answers_queue = answers_queue
        self.ALLOWED_ROLES = allowed_roles
        self.logger = logging.getLogger("AIDojo-Coordinator")
        self._world = NetworkSecurityEnvironment(net_set_config)
        self._action_processor = ActionProcessor()

    async def run(self):
        """
        Main method to be run for coordinating the agent's interaction with the game engine.
        - Reads messages from action queue
        - processes actions based on their type
        - Forwards actions in the game engine
        - Forwards responses to teh answer queue
        """
        try:
            self.logger.info("Main coordinator started.")
            env_observation = self._world.reset()
            self.agents = {}

            while True:
                self.logger.debug("Coordinator running.")
                # Read message from the queue
                agent_addr, message = await self._actions_queue.get()
                if message is not None:
                    self.logger.info(f"Coordinator received: {message}.")
                    try:  # Convert message to Action
                        action = Action.from_json(message)
                    except Exception as e:
                        self.logger.error(
                            f"Error when converting msg to Action using Action.from_json():{e}"
                        )
                    match action.type:  # process action based on its type
                        case ActionType.JoinGame:
                            output_message_dict = self._process_join_game_action(
                                agent_addr, action, env_observation
                            )
                        case ActionType.QuitGame:
                            raise NotImplementedError
                        case ActionType.ResetGame:
                            output_message_dict = self._process_reset_game_action(
                                agent_addr
                            )
                        case _:
                            output_message_dict = self._process_generic_action(
                                agent_addr, action
                            )
                    try:
                        # Convert message into string representation
                        output_message = json.dumps(output_message_dict)
                    except Exception as e:
                        self.logger.error(f"Error when converting msg to Json:{e}")
                        raise e
                    # Send to anwer_queue
                    await self._answers_queue.put(output_message)
                await asyncio.sleep(0.0000001)
        except asyncio.CancelledError:
            self.logger.info("\tTerminating by CancelledError")
        except Exception as e:
            self.logger.error(f"Exception in main_coordinator(): {e}")
            raise e

    def _process_join_game_action(self, agent_addr: tuple, action: Action, current_observation: Observation) -> dict:
        """ "
        Method for processing Action of type ActionType.JoinGame
        """
        if agent_addr not in self.agents:
            self.logger.info(f"Creating new agent for {agent_addr}.")
            agent_name = action.parameters["agent_info"].name
            agent_role = action.parameters["agent_info"].role
            if agent_role in self.ALLOWED_ROLES:
                self.logger.info(f"\tAgent {agent_name}, registred as {agent_role}")
                self.agents[agent_addr] = action.parameters
                agent_observation_str = (
                    self._action_processor.generate_observation_msg_for_agent(
                        agent_addr, current_observation
                    )
                )
                output_message_dict = {
                    "to_agent": agent_addr,
                    "status": str(GameStatus.CREATED),
                    "observation": agent_observation_str,
                    "message": {
                        "message": f"Welcome {agent_name}, registred as {agent_role}",
                        "max_steps": self._world._max_steps,
                        "goal_description": self._world.get_goal_description()
                        },
                }
            else:
                self.logger.info(
                    f"\tError in regitration, unknown agent role: {agent_role}!"
                )
                output_message_dict = {
                    "to_agent": agent_addr,
                    "status": str(GameStatus.BAD_REQUEST),
                    "message": f"Incorrect agent_role {agent_role}",
                }
        else:
            self.logger.info("\tError in regitration, unknown agent already exists!")
            output_message_dict = {
                "to_agent": {agent_addr},
                "status": str(GameStatus.BAD_REQUEST),
                "message": "Agent already exists.",
            }
        return output_message_dict

    def _process_reset_game_action(self, agent_addr: tuple) -> dict:
        """ "
        Method for processing Action of type ActionType.ResetGame
        """
        self.logger.info(
            f"Coordinator received from RESET request from agent {agent_addr}"
        )
        new_env_observation = self._world.reset()
        agent_observation_str = (
            self._action_processor.generate_observation_msg_for_agent(
                agent_addr, new_env_observation
            )
        )
        output_message_dict = {
            "to_agent": agent_addr,
            "status": str(GameStatus.OK),
            "observation": agent_observation_str,
            "message": "Resetting Game and starting again.",
        }
        return output_message_dict

    def _process_generic_action(self, agent_addr: tuple, action: Action) -> dict:
        self.logger.info(f"Coordinator received from agent {agent_addr}: {action}")
        # Process the message
        action_for_env = self._action_processor.process_message_from_agent(
            agent_addr, action
        )
        new_observation = self._world.step(action_for_env)
        agent_observation_str = (
            self._action_processor.generate_observation_msg_for_agent(
                agent_addr, new_observation
            )
        )
        output_message_dict = {
            "to_agent": agent_addr,
            "observation": agent_observation_str,
            "status": str(GameStatus.OK),
        }
        return output_message_dict


__version__ = "v0.2.1"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser = argparse.ArgumentParser(
        description=f"NetSecGame Coordinator Server version {__version__}. Author: Sebastian Garcia, sebastian.garcia@agents.fel.cvut.cz",
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
        "-d",
        "--debug",
        help="Debugging level. This shows inner information about the flows.",
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

    args = parser.parse_args()

    # Set the logging
    log_filename = Path("coordinator.log")
    if not log_filename.parent.exists():
        os.makedirs(log_filename.parent)
    logging.basicConfig(
        filename=log_filename,
        filemode="w",
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.INFO,
    )
    # load config for coordinator
    with open(args.configfile, "r") as jfile:
        confjson = json.load(jfile)
    host = confjson.get("host", None)
    port = confjson.get("port", None)
    # Create AI Dojo
    ai_dojo = AIDojo(host, port, "env/netsecenv_conf.yaml")
    # Run it!
    ai_dojo.run()

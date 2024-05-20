#!/usr/bin/env python
# Server for the Aidojo project, coordinator
# Author: sebastian garcia, sebastian.garcia@agents.fel.cvut.cz
# Author: Ondrej Lukas, ondrej.lukas@aic.fel.cvut.cz
import argparse
import logging
import json
import asyncio
from env.network_security_game import NetworkSecurityEnvironment
from env.game_components import Action, Observation, ActionType, GameStatus, GameState
from utils.utils import observation_as_dict
from pathlib import Path
import os
import signal

class AIDojo:
    def __init__(self, host: str, port: int, net_sec_config: str, world_type) -> None:
        self.host = host
        self.port = port
        self.logger = logging.getLogger("AIDojo-main")
        self._action_queue = asyncio.Queue()
        self._answer_queue = asyncio.Queue()
        self._coordinator = Coordinator(
            self._action_queue,
            self._answer_queue,
            net_sec_config,
            allowed_roles=["Attacker", "Defender", "Benign"],
            world_type = world_type,
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
                max_connections=2
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
        self._num_steps = {}
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
                    quit_message = Action(ActionType.QuitGame, params={}).as_json()
                    self.logger.info(
                        f"Inserting quit message {message}"
                    )
                    await self.actions_queue.put((addr, quit_message))
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
    def __init__(self, actions_queue, answers_queue, net_sec_config, allowed_roles, world_type="netsecenv"):
        self._actions_queue = actions_queue
        self._answers_queue = answers_queue
        self.ALLOWED_ROLES = allowed_roles
        self.logger = logging.getLogger("AIDojo-Coordinator")
        self._world = NetworkSecurityEnvironment(net_sec_config)
        self._action_processor = ActionProcessor()
        self.world_type = world_type
        self._starting_positions_per_role = self._get_starting_position_per_role()
        self._agent_starting_position = {}
        self._win_conditions_per_role = self._get_win_condition_per_role()

    def convert_msg_dict_to_json(self, msg_dict)->str:
            try:
                # Convert message into string representation
                output_message = json.dumps(msg_dict)
            except Exception as e:
                self.logger.error(f"Error when converting msg to Json:{e}")
                raise e
                # Send to anwer_queue
            return output_message

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
            self._agent_steps = {}
            self._reset_requests = {}
            self._agent_observations = {}
            self._agent_states = {}
            self._agent_goal_reached = {}
            self._episode_end = False

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
                            f"Error when converting msg to Action using Action.from_json():{e}, {message}"
                        )
                    match action.type:  # process action based on its type
                        case ActionType.JoinGame:
                            output_message_dict = self._process_join_game_action(
                                agent_addr, action, env_observation
                            )
                            msg_json = self.convert_msg_dict_to_json(output_message_dict)
                            # Send to anwer_queue
                            await self._answers_queue.put(msg_json)
                        case ActionType.QuitGame:
                            self.logger.info(f"Coordinator received from QUIT message from agent {agent_addr}")
                            # remove agent address from the reset request dict
                            self.logger.info(f"Removing {agent_addr} from reset requests")
                            reset_requested = self._reset_requests.pop(agent_addr, None)

                        case ActionType.ResetGame:
                            self._reset_requests[agent_addr] = True
                            self.logger.info(f"Coordinator received from RESET request from agent {agent_addr}")
                            if all(self._reset_requests.values()):
                                # should we discard the queue here?
                                self.logger.info(f"All agents requested reset, action_q:{self._actions_queue.empty()}, answers_q{self._answers_queue.empty()}")
                                new_env_observation = self._world.reset()
                                for agent in self._reset_requests:
                                    self._reset_requests[agent] = False
                                    self._agent_steps[agent] = 0
                                    output_message_dict = self._respond_to_reset_game_action(
                                        agent,
                                        new_env_observation,
                                    )
                                    msg_json = self.convert_msg_dict_to_json(output_message_dict)
                                    # Send to anwer_queue
                                    await self._answers_queue.put(msg_json)
                            else:
                                self.logger.info("\t Waiting for other agetns to request reset")
                        case _:
                            output_message_dict = self._process_generic_action(
                                agent_addr, action
                            )
                            msg_json = self.convert_msg_dict_to_json(output_message_dict)
                            # Send to anwer_queue
                            await self._answers_queue.put(msg_json)

                await asyncio.sleep(0.0000001)
        except asyncio.CancelledError:
            self.logger.info("\tTerminating by CancelledError")
        except Exception as e:
            self.logger.error(f"Exception in main_coordinator(): {e}")
            raise e

    def _initialize_new_player(self, agent_addr, agent_name, agent_role) -> Observation:
        """
        Method to initialize new player upon joining the game.
        Returns initial observation for the agent based on the agent's role
        """
        self.agents[agent_addr] = (agent_name, agent_role)
        self._agent_steps[agent_addr] = 0
        self._reset_requests[agent_addr] = False
        self._agent_starting_position[agent_addr] = self._starting_positions_per_role[agent_role]
        self._agent_states[agent_addr] = self._world.create_state_from_view(self._agent_starting_position[agent_addr])
        self._agent_goal_reached[agent_addr] = self._goal_reached(agent_addr) 
        self.logger.info(f"\tAgent {agent_name} ({agent_addr}), registred as {agent_role}")
        return Observation(self._agent_states[agent_addr], 0, False, {})

    def _get_starting_position_per_role(self)->dict:
        starting_positions = {}
        for agent_role in self.ALLOWED_ROLES:
            try:
                starting_positions[agent_role] = self._world.task_config.get_start_position(agent_role=agent_role)
                self.logger.info(f"Starting position for role '{agent_role}': {starting_positions[agent_role]}")
            except KeyError:
                starting_positions[agent_role] = {}
        return starting_positions
    
    def _get_win_condition_per_role(self)-> dict:
        win_conditions = {}
        for agent_role in self.ALLOWED_ROLES:
            try:
                win_conditions[agent_role] = self._world.task_config.get_win_conditions(agent_role=agent_role)
            except KeyError:
                win_conditions[agent_role] = {}
            self.logger.info(f"Win condition for role '{agent_role}': {win_conditions[agent_role]}")
        return win_conditions

    def _process_join_game_action(self, agent_addr: tuple, action: Action, current_observation: Observation) -> dict:
        """ "
        Method for processing Action of type ActionType.JoinGame
        """
        if agent_addr not in self.agents:
            self.logger.info(f"Creating new agent for {agent_addr}.")
            agent_name = action.parameters["agent_info"].name
            agent_role = action.parameters["agent_info"].role
            if agent_role in self.ALLOWED_ROLES:
                initial_observation = self._initialize_new_player(agent_addr, agent_name, agent_role)
                output_message_dict = {
                    "to_agent": agent_addr,
                    "status": str(GameStatus.CREATED),
                    "observation": observation_as_dict(initial_observation),
                    "message": {
                        "message": f"Welcome {agent_name}, registred as {agent_role}",
                        "max_steps": self._world._max_steps,
                        "goal_description": self._world.goal_description,
                        "num_actions": self._world.num_actions
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

    def _respond_to_reset_game_action(self, agent_addr: tuple , new_env_observation:Observation) -> dict:
        """ "
        Method for generatating answers to Action of type ActionType.ResetGame after all agents requested reset
        """
        self.logger.info(
            f"Coordinator responding to RESET request from agent {agent_addr}"
        )
        # new_env_observation = self._world.reset()
        agent_observation_str = (
            self._action_processor.generate_observation_msg_for_agent(
                agent_addr, new_env_observation
            )
        )
        output_message_dict = {
            "to_agent": agent_addr,
            "status": str(GameStatus.OK),
            "observation": agent_observation_str,
            "message": {
                        "message": "Resetting Game and starting again.",
                        "max_steps": self._world._max_steps,
                        "goal_description": self._world.goal_description
                        },
        }
        return output_message_dict

    def _process_generic_action(self, agent_addr: tuple, action: Action) -> dict:
        self.logger.info(f"Coordinator received from agent {agent_addr}: {action}")
        if not self._episode_end:
            # Process the message
            # increase the action counter
            self._agent_steps[agent_addr] += 1
            self.logger.info(f"{agent_addr} steps: {self._agent_steps[agent_addr]}")
            action_for_env = self._action_processor.process_message_from_agent(
                agent_addr, action
            )
            # Build new Observation for the agent
            next_state = self._world.step(action_for_env, self.world_type).state
            self._agent_goal_reached[agent_addr] = self._goal_reached(agent_addr)

            reward = self._world._rewards["step"]
            if self._agent_goal_reached[agent_addr]:
                reward += self._world._rewards["goal"]
            
            new_observation = Observation(next_state, reward, )
            new_observation = self._world.step(action_for_env, self.world_type)
            self._agent_states[agent_addr] = new_observation.state
            self._agent_observations[agent_addr] = new_observation
            self.logger.info(f"Coordinator goal_check: {self._goal_reached(agent_addr)}")
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
        else:
            # Episode ended tell agent to request reset
            current_observation = self._agent_observations[agent_addr]
            reward = 0 # TODO 
            new_observation = Observation(
                current_observation.state,
                reward=reward,
                end=True,
                info={"Episode ended. Request reset for starting new episode."})
            output_message_dict = {
                "to_agent": agent_addr,
                "observation": agent_observation_str,
                "status": str(GameStatus.BAD_REQUEST),
            }
        return output_message_dict
    
    def reset(self)->None:
        pass

    def _goal_reached(self, agent_addr):
        self.logger.info(f"Coordinator checking goal for {agent_addr}({self.agents[agent_addr][1]})")
        agents_state = self._agent_observations[agent_addr].state
        agent_role = self.agents[agent_addr][1]
        win_condition = self._win_conditions_per_role[agent_role]
        return self._check_goal(agents_state, win_condition)
    
    def _check_goal(self, state:GameState, goal_conditions:dict)->bool:
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
                    #some keys are missing in the known_dict
                    return False
            return False
        # For each part of the state of the game, check if the conditions are met
        goal_reached = {}    
        goal_reached["networks"] = set(goal_conditions["known_networks"]) <= set(state.known_networks)
        goal_reached["known_hosts"] = set(goal_conditions["known_hosts"]) <= set(state.known_hosts)
        goal_reached["controlled_hosts"] = set(goal_conditions["controlled_hosts"]) <= set(state.controlled_hosts)
        goal_reached["services"] = goal_dict_satistfied(goal_conditions["known_services"], state.known_services)
        goal_reached["data"] = goal_dict_satistfied(goal_conditions["known_data"], state.known_data)
        self.logger.info(f"\t{goal_reached}")
        return all(goal_reached.values())

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
    parser.add_argument(
        "-t",
        "--task_config",
        help="Task configuration file.",
        action="store",
        required=False,
        type=str,
        default="env/netsecenv_conf.yaml",
    )

    args = parser.parse_args()
    print(args)
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
    world_type = confjson.get('world_type', 'netsecgame')

    # prioritize task config from CLI
    if args.task_config:
        task_config_file = args.task_config
    else:
        # Try to use task config from coordinator.conf
        task_config_file = confjson.get("task_config", None)
    if task_config_file is None:
        raise KeyError("Task configuration must be provided to start the coordinator! Use -h for more details.")
    # Create AI Dojo
    ai_dojo = AIDojo(host, port, task_config_file, world_type)
    # Run it!
    ai_dojo.run()

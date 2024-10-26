#!/usr/bin/env python
# Server for the Aidojo project, coordinator
# Author: sebastian garcia, sebastian.garcia@agents.fel.cvut.cz
# Author: Ondrej Lukas, ondrej.lukas@aic.fel.cvut.cz
import jsonlines
import argparse
import logging
import json
import asyncio
from datetime import datetime
from env.worlds.network_security_game import NetworkSecurityEnvironment
from env.worlds.network_security_game_real_world import NetworkSecurityEnvironmentRealWorld
from env.worlds.aidojo_world import AIDojoWorld
from env.game_components import Action, Observation, ActionType, GameStatus, GameState
from utils.utils import observation_as_dict, get_logging_level
from pathlib import Path
import os
import signal
from env.global_defender import stochastic_with_threshold

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

class ConnectionLimitProtocol(asyncio.Protocol):
    def __init__(self, actions_queue, answers_queue, max_connections):
        self.actions_queue = actions_queue
        self.answers_queue = answers_queue
        self.max_connections = max_connections
        self.current_connections = 0
        self.logger = logging.getLogger("AIDojo-Server")
        self._stop = False

    def close(self)->None:
        self.logger.info(
           "Stopping server"
        )
        self._stop = True
    
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
            while not self._stop:
                data = await reader.read(500)
                raw_message = data.decode().strip()
                if len(raw_message):
                    self.logger.debug(
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
                        f"\tEmpty message, replacing with QUIT message {message}"
                    )
                    await self.actions_queue.put((addr, quit_message))
                    break
        except KeyboardInterrupt:
            self.logger.debug("Terminating by KeyboardInterrupt")
            raise SystemExit
        except Exception as e:
            self.logger.error(f"Exception in handle_new_agent(): {e}")
        finally:
            # Decrement the count of current connections
            self.current_connections -= 1
            writer.close()
            return
            
    async def __call__(self, reader, writer):
        await self.handle_new_agent(reader, writer)

class Coordinator:
    def __init__(self, actions_queue, answers_queue, net_sec_config, allowed_roles, world_type="netsecenv"):
        # communication channels for asyncio
        self._actions_queue = actions_queue
        self._answers_queue = answers_queue
        self.ALLOWED_ROLES = allowed_roles
        self.logger = logging.getLogger("AIDojo-Coordinator")
        # world definition
        match world_type:
            case "netsecenv":
                self._world = NetworkSecurityEnvironment(net_sec_config)
            case "netsecenv-real-world":
                self._world = NetworkSecurityEnvironmentRealWorld(net_sec_config)
            case _:
                self._world = AIDojoWorld(net_sec_config)
        self.world_type = world_type
        
        

        self._starting_positions_per_role = self._get_starting_position_per_role()
        self._win_conditions_per_role = self._get_win_condition_per_role()
        self._goal_description_per_role = self._get_goal_description_per_role()
        self._steps_limit = self._world.task_config.get_max_steps()
        self._use_global_defender = self._world.task_config.get_use_global_defender()
        # player information
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
        # goal reach status per agent_addr (bool)
        self._agent_goal_reached = {}
        self._agent_episode_ends = {}
        self._agent_detected = {}
        # trajectories per agent_addr
        self._agent_trajectories = {}
    
    @property
    def episode_end(self)->bool:
        # Terminate episode if at least one player wins or reaches the timeout
        self.logger.debug(f"End evaluation: {self._agent_episode_ends.values()}")
        return all(self._agent_episode_ends.values())
    
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
            while True:
                # Read message from the queue
                agent_addr, message = await self._actions_queue.get()
                if message is not None:
                    self.logger.debug(f"Coordinator received: {message}.")
                    try:  # Convert message to Action
                        action = Action.from_json(message)
                    except Exception as e:
                        self.logger.error(
                            f"Error when converting msg to Action using Action.from_json():{e}, {message}"
                        )
                    match action.type:  # process action based on its type
                        case ActionType.JoinGame:
                            output_message_dict = self._process_join_game_action(agent_addr, action)
                            msg_json = self.convert_msg_dict_to_json(output_message_dict)
                            # Send to anwer_queue
                            await self._answers_queue.put(msg_json)
                        case ActionType.QuitGame:
                            self.logger.info(f"Coordinator received from QUIT message from agent {agent_addr}")
                            # remove agent address from the reset request dict
                            self._remove_player(agent_addr)
                        case ActionType.ResetGame:
                            self._reset_requests[agent_addr] = True
                            self.logger.info(f"Coordinator received from RESET request from agent {agent_addr}")
                            if all(self._reset_requests.values()):
                                # should we discard the queue here?
                                self.logger.info(f"All agents requested reset, action_q:{self._actions_queue.empty()}, answers_q:{self._answers_queue.empty()}")
                                self._world.reset()
                                self._get_goal_description_per_role()
                                self._get_win_condition_per_role()
                                for agent in self._reset_requests:
                                    self._reset_requests[agent] = False
                                    self._agent_steps[agent] = 0
                                    self._agent_states[agent] = self._world.create_state_from_view(self._agent_starting_position[agent])
                                    self._agent_goal_reached[agent] = self._goal_reached(agent)
                                    self._agent_episode_ends[agent] = False
                                    output_message_dict = self._create_response_to_reset_game_action(agent)
                                    msg_json = self.convert_msg_dict_to_json(output_message_dict)
                                    # Send to anwer_queue
                                    await self._answers_queue.put(msg_json)
                            else:
                                self.logger.info("\t Waiting for other agents to request reset")
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
            self.logger.error(f"Exception in Class coordinator(): {e}")
            raise e

    def _initialize_new_player(self, agent_addr:tuple, agent_name:str, agent_role:str) -> Observation:
        """
        Method to initialize new player upon joining the game.
        Returns initial observation for the agent based on the agent's role
        """
        self.logger.info(f"\tInitializing new player{agent_addr} with role {agent_role}")
        self.agents[agent_addr] = (agent_name, agent_role)
        self._agent_steps[agent_addr] = 0
        self._reset_requests[agent_addr] = False
        self._agent_starting_position[agent_addr] = self._starting_positions_per_role[agent_role]
        self._agent_states[agent_addr] = self._world.create_state_from_view(self._agent_starting_position[agent_addr])
        self._agent_goal_reached[agent_addr] = self._goal_reached(agent_addr) 
        self._agent_detected[agent_addr] = self._check_detection(agent_addr, None) 
        self._agent_episode_ends[agent_addr] = False
        if self._world.task_config.get_store_trajectories() or self._use_global_defender:
            self._agent_trajectories[agent_addr] = self._reset_trajectory(agent_addr)
        self.logger.info(f"\tAgent {agent_name} ({agent_addr}), registred as {agent_role}")
        return Observation(self._agent_states[agent_addr], 0, False, {})

    def _remove_player(self, agent_addr:tuple)->dict:
        """
        Removes player from the game.
        """
        self.logger.info(f"Removing player {agent_addr}")
        agent_info = {}
        if agent_addr in self.agents:
            agent_info["state"] = self._agent_states.pop(agent_addr)
            agent_info["goal_reached"] = self._agent_goal_reached.pop(agent_addr)
            agent_info["num_steps"] = self._agent_steps.pop(agent_addr)
            agent_info["reset_request"] = self._reset_requests.pop(agent_addr)
            agent_info["episode_end"] = self._agent_episode_ends.pop(agent_addr)
            agent_info["agent_info"] = self.agents.pop(agent_addr)
            self.logger.debug(f"\t{agent_info}")
        else:
            self.logger.info(f"\t Player {agent_addr} not present in the game!")
        return agent_info

    def _get_starting_position_per_role(self)->dict:
        """
        Method for finding starting position for each agent role in the game.
        """
        starting_positions = {}
        for agent_role in self.ALLOWED_ROLES:
            try:
                starting_positions[agent_role] = self._world.task_config.get_start_position(agent_role=agent_role)
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
                win_conditions[agent_role] = self._world.update_goal_dict(
                    self._world.task_config.get_win_conditions(agent_role=agent_role)
                )
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
                goal_descriptions[agent_role] = self._world.update_goal_descriptions(
                    self._world.task_config.get_goal_description(agent_role=agent_role)
                )
            except KeyError:
                goal_descriptions[agent_role] = ""
            self.logger.info(f"Goal description for role '{agent_role}': {goal_descriptions[agent_role]}")
        return goal_descriptions
    
    def _process_join_game_action(self, agent_addr: tuple, action: Action) -> dict:
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
                        "goal_description": self._goal_description_per_role[agent_role],
                        "num_actions": self._world.num_actions
                        },
                }
            else:
                self.logger.info(
                    f"\tError in registration, unknown agent role: {agent_role}!"
                )
                output_message_dict = {
                    "to_agent": agent_addr,
                    "status": str(GameStatus.BAD_REQUEST),
                    "message": f"Incorrect agent_role {agent_role}",
                }
        else:
            self.logger.info("\tError in registration, unknown agent already exists!")
            output_message_dict = {
                "to_agent": {agent_addr},
                "status": str(GameStatus.BAD_REQUEST),
                "message": "Agent already exists.",
            }
        return output_message_dict

    def _create_response_to_reset_game_action(self, agent_addr: tuple) -> dict:
        """ "
        Method for generatating answers to Action of type ActionType.ResetGame after all agents requested reset
        """
        self.logger.info(
            f"Coordinator responding to RESET request from agent {agent_addr}"
        )
        # store trajectory in file if needed
        if self._world.task_config.get_store_trajectories():
            self._store_trajectory_to_file(agent_addr)
        new_observation = Observation(self._agent_states[agent_addr], 0, self.episode_end, {})
        # reset trajectory
        self._agent_trajectories[agent_addr] = self._reset_trajectory(agent_addr)
        output_message_dict = {
            "to_agent": agent_addr,
            "status": str(GameStatus.OK),
            "observation": observation_as_dict(new_observation),
            "message": {
                        "message": "Resetting Game and starting again.",
                        "max_steps": self._world._max_steps,
                        "goal_description": self._goal_description_per_role[self.agents[agent_addr][1]]
                        },
        }
        return output_message_dict

    def _add_step_to_trajectory(self, agent_addr:tuple, action:Action, reward:float, next_state:GameState, end_reason:str)->None:
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
    
    def _store_trajectory_to_file(self, agent_addr, location="./trajectories"):
        self.logger.debug(f"Storing Trajectory of {agent_addr}in file")
        if agent_addr in self._agent_trajectories:
            agent_name, agent_role = self.agents[agent_addr] 
            filename = os.path.join(location, f"{datetime.now():%Y-%m-%d}_{agent_name}_{agent_role}.jsonl")
            with jsonlines.open(filename, "a") as writer:
                writer.write(self._agent_trajectories[agent_addr])
            self.logger.info(f"Trajectory of {agent_addr} strored in {filename}")
    
    def _reset_trajectory(self,agent_addr)->dict:
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
    
    def _process_generic_action(self, agent_addr: tuple, action: Action) -> dict:
        """
        Method processing the Actions relevant to the environment
        """
        self.logger.info(f"Processing {action} from {agent_addr}")
        if not self.episode_end:
            # Process the message
            # increase the action counter
            self._agent_steps[agent_addr] += 1
            self.logger.info(f"{agent_addr} steps: {self._agent_steps[agent_addr]}")
            
            current_state = self._agent_states[agent_addr]
            # Build new Observation for the agent
            self._agent_states[agent_addr] = self._world.step(current_state, action, agent_addr)
            self._agent_goal_reached[agent_addr] = self._goal_reached(agent_addr)

            self._agent_detected[agent_addr] = self._check_detection(agent_addr, action)

            reward = self._world._rewards["step"]
            obs_info = {}
            end_reason = None
            if self._agent_goal_reached[agent_addr]:
                reward += self._world._rewards["goal"]
                self._agent_episode_ends[agent_addr] = True
                end_reason = "goal_reached"
                obs_info = {'end_reason': "goal_reached"}
            elif self._agent_steps[agent_addr] >= self._steps_limit:
                self._agent_episode_ends[agent_addr] = True
                obs_info = {"end_reason": "max_steps"}
                end_reason = "max_steps"
            elif self._agent_detected[agent_addr]:
                reward += self._world._rewards["detection"]
                self._agent_episode_ends[agent_addr] = True
                obs_info = {"end_reason": "max_steps"}
            
            # record step in trajecory
            self._add_step_to_trajectory(agent_addr, action, reward,self._agent_states[agent_addr], end_reason)
            new_observation = Observation(self._agent_states[agent_addr], reward, self.episode_end, info=obs_info)

            self._agent_observations[agent_addr] = new_observation

            output_message_dict = {
                "to_agent": agent_addr,
                "observation": observation_as_dict(new_observation),
                "status": str(GameStatus.OK),
            }
        else:
            self.logger.error(f"{self.episode_end}, {self._agent_episode_ends}")
            output_message_dict = self._generate_episode_end_message(agent_addr)
        return output_message_dict
    
    def _generate_episode_end_message(self, agent_addr:tuple)->dict:
        """
        Method for generating response when agent attemps to make a step after episode ended.
        """
        current_observation = self._agent_observations[agent_addr]
        reward = 0 # TODO
        end_reason = ""
        if self._agent_goal_reached[agent_addr]:
            end_reason = "goal_reached"
        elif self._agent_steps[agent_addr] >= self._world.timeout:
            end_reason = "max_steps"
        else:
            end_reason = "game_lost"
            reward += self._world._rewards["detection"]
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
        return output_message_dict

    def _goal_reached(self, agent_addr:tuple)->bool:
        """
        Determines if and agent reached a goal state
        """
        self.logger.info(f"Goal check for {agent_addr}({self.agents[agent_addr][1]})")
        agents_state = self._agent_states[agent_addr]
        agent_role = self.agents[agent_addr][1]
        win_condition = self._world.update_goal_dict(self._win_conditions_per_role[agent_role])
        goal_check = self._check_goal(agents_state, win_condition)
        if goal_check:
            self.logger.info("\tGoal reached!")
        else:
            self.logger.info("\tGoal not reached!")
        return goal_check
    
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
        goal_reached["known_blocks"] = goal_dict_satistfied(goal_conditions["known_blocks"], state.known_blocks)
        self.logger.debug(f"\t{goal_reached}")
        return all(goal_reached.values())

    def _check_detection(self, agent_addr:tuple, last_action:Action)->bool:
        self.logger.info(f"Detection check for {agent_addr}({self.agents[agent_addr][1]})")
        detection = False
        if last_action:
            if self._use_global_defender:
                self.logger.warning("Global defender - ONLY use for backward compatibility!")
                episode_actions = self._agent_trajectories[agent_addr]["actions"] if "actions" in self._agent_trajectories[agent_addr] else []
                detection =  stochastic_with_threshold(last_action, episode_actions)
        if detection:
            self.logger.info("\tDetected!")
        else:
            self.logger.info("\tNot detected!")
        return detection
__version__ = "v0.2.2"


if __name__ == "__main__":
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
    parser.add_argument(
        "-l",
        "--debug_level",
        help="Define the debug level for the logs. DEBUG, INFO, WARNING, ERROR, CRITICAL",
        action="store",
        required=False,
        type=str,
        default="INFO",
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
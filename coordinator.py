#!/usr/bin/env python
# Server for the Aidojo project, coordinator
# Author: sebastian garcia, sebastian.garcia@agents.fel.cvut.cz
# Author: Ondrej Lukas, ondrej.lukas@aic.fel.cvut.cz
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
from env.game_components import Action, Observation, ActionType, GameStatus, GameState
from utils.utils import observation_as_dict, get_logging_level, get_file_hash
from pathlib import Path
import os
import signal
from env.global_defender import stochastic_with_threshold
from utils.utils import ConfigParser

@enum.unique
class AgentStatus(enum.Enum):
    """
    Class representing the current status for each agent connected to the coordinator
    """
    JoinRequested = 0
    Ready = 1
    Playing = 2
    PlayingActive = 3
    FinishedMaxSteps = 4
    FinishedBlocked = 5
    FinishedGoalReached = 6
    FinishedGameLost = 7
    ResetRequested = 8
    Quitting = 9


class AIDojo:
    def __init__(self, host: str, port: int, net_sec_config: str, world_type) -> None:
        self.host = host
        self.port = port
        self.logger = logging.getLogger("AIDojo-main")
        self._agent_action_queue = asyncio.Queue()
        self._agent_response_queues = {}
        self._coordinator = Coordinator(
            self._agent_action_queue,
            self._agent_response_queues,
            net_sec_config,
            allowed_roles=["Attacker", "Defender", "Benign"],
            world_type = world_type,
        )

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
        # Everything stopped correctly, terminate
        self.logger.info("AIDojo terminating")

class ConnectionLimitProtocol(asyncio.Protocol):
    def __init__(self, actions_queue, agent_response_queues, max_connections):
        self.actions_queue = actions_queue
        self.answers_queues = agent_response_queues
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
        addr = writer.get_extra_info("peername")
        self.logger.info(f"New agent connected: {addr}")
        # Ensure a queue exists for this agent
        if addr not in self.answers_queues:
            self.answers_queues[addr] = asyncio.Queue(maxsize=2)
            self.logger.info(f"Created queue for agent {addr}")

        try:
            while not self._stop:
                # Step 1: Read data from the agent
                data = await reader.read(500)
                if not data:
                    self.logger.info(f"Agent {addr} disconnected.")
                    quit_message = Action(ActionType.QuitGame, params={}).as_json()
                    await self.actions_queue.put((addr, quit_message))
                    break

                raw_message = data.decode().strip()
                self.logger.debug(f"Handler received from {addr}: {raw_message}")

                # Step 2: Forward the message to the Coordinator
                await self.actions_queue.put((addr, raw_message))
                await asyncio.sleep(0.001)
                # Step 3: Get a matching response from the answers queue
                response_queue = self.answers_queues[addr]
                response = await response_queue.get()
                self.logger.info(f"Sending response to agent {addr}: {response}")

                # Step 4: Send the response to the agent
                writer.write(bytes(str(response).encode()))
                await writer.drain()
        except KeyboardInterrupt:
            self.logger.debug("Terminating by KeyboardInterrupt")
            raise SystemExit
        except Exception as e:
            self.logger.error(f"Exception in handle_new_agent(): {e}")
        finally:
            # Decrement the count of current connections
            self.current_connections -= 1
            if addr in self.answers_queues:
                self.answers_queues.pop(addr)
                self.logger.info(f"Removed queue for agent {addr}")
            else:
                self.logger.warning(f"Queue for agent {addr} not found during cleanup.")
            writer.close()
            return
            
    async def __call__(self, reader, writer):
        await self.handle_new_agent(reader, writer)

class Coordinator:
    def __init__(self, actions_queue, answers_queues, net_sec_config, allowed_roles, world_type="netsecenv"):
        # communication channels for asyncio
        self._actions_queue = actions_queue
        self._answers_queues = answers_queues
        self._world_action_queue = asyncio.Queue()
        self._world_response_queue = asyncio.Queue()
        self.task_config = ConfigParser(net_sec_config)
        self.ALLOWED_ROLES = allowed_roles
        self.logger = logging.getLogger("AIDojo-Coordinator")
        
        # world definition
        match world_type:
            case "netsecenv":
                self._world = NetworkSecurityEnvironment(net_sec_config,self._world_action_queue, self._world_response_queue)
            case "netsecenv-real-world":
                self._world = NetworkSecurityEnvironmentRealWorld(net_sec_config, self._world_action_queue, self._world_response_queue)
            case _:
                self._world = AIDojoWorld(net_sec_config, self._world_action_queue, self._world_response_queue)
        self.world_type = world_type
        self._CONFIG_FILE_HASH = get_file_hash(net_sec_config)        
        self._starting_positions_per_role = self._get_starting_position_per_role()
        self._win_conditions_per_role = self._get_win_condition_per_role()
        self._goal_description_per_role = self._get_goal_description_per_role()
        self._steps_limit_per_role = self._get_max_steps_per_role()
        self._use_global_defender = self.task_config.get_use_global_defender()
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
        # last action played by agent (Action)
        self._agent_last_action = {}
        # agent status dict {agent_addr: AgentStatus}
        self._agent_statuses = {}
        # agent status dict {agent_addr: int}
        self._agent_rewards = {}
        # trajectories per agent_addr
        self._agent_trajectories = {}
    
    @property
    def episode_end(self)->bool:
        # Episode ends ONLY IF all agents with defined max_steps reached the end fo the episode
        exists_active_player = any(status is AgentStatus.PlayingActive for status in self._agent_statuses.values())
        self.logger.debug(f"End evaluation: {self._agent_statuses.items()} - Episode end:{not exists_active_player}")
        return not exists_active_player
    
    @property
    def config_file_hash(self):
        return self._CONFIG_FILE_HASH

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
            # Start World Response handler task
            world_response_task = asyncio.create_task(self._handle_world_responses())
            world_processing_task = asyncio.create_task(self._world.handle_incoming_action())        
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
                            self.logger.debug(f"Start processing of ActionType.JoinGame by {agent_addr}")
                            await self._process_join_game_action(agent_addr, action)
                        case ActionType.QuitGame:
                            self.logger.info(f"Coordinator received from QUIT message from agent {agent_addr}")
                            # update agent status
                            self._agent_statuses[agent_addr] = AgentStatus.Quitting
                            # forward the message to the world
                            await self._world_action_queue.put((agent_addr, action, self._agent_states[agent_addr]))
                        case ActionType.ResetGame:
                            self._reset_requests[agent_addr] = True
                            self._agent_statuses[agent_addr] = AgentStatus.ResetRequested
                            self.logger.info(f"Coordinator received from RESET request from agent {agent_addr}")
                            if all(self._reset_requests.values()):
                                # should we discard the queue here?
                                self.logger.info("All active agents requested reset")
                                # send WORLD reset request to the world
                                await self._world_action_queue.put(("world", Action(ActionType.ResetGame, params={}), None))
                                # send request for each of the agents (to get new initial state)
                                for agent in self._reset_requests:
                                    await self._world_action_queue.put((agent, Action(ActionType.ResetGame, params={}), self._agent_starting_position[agent]))
                            else:
                                self.logger.info("\t Waiting for other agents to request reset")
                        case _:
                            # actions in the game
                            await self._process_generic_action(agent_addr, action)
                await asyncio.sleep(0.0000001)
        except asyncio.CancelledError:
            world_response_task.cancel()
            world_processing_task.cancel()
            asyncio.gather(world_processing_task, world_response_task, return_exceptions=True)
            self.logger.info("\tTerminating by CancelledError")
        except Exception as e:
            self.logger.error(f"Exception in Class coordinator(): {e}")
            raise e

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
        self._agent_statuses[agent_addr] = AgentStatus.PlayingActive if agent_role == "Attacker" else AgentStatus.Playing
        self._agent_states[agent_addr] = agent_current_state


        #self._agent_states[agent_addr] = self._world.create_state_from_view(self._agent_starting_position[agent_addr])
        
        # if self._steps_limit_per_role[agent_role]:
        #     # This agent can force episode end (has timeout and goal defined)
        #     self._agent_statuses[agent_addr] = AgentStatus.PlayingActive
        # else:
        #     # This agent can NOT force episode end (does NOT timeout or goal defined)
        #     self._agent_statuses[agent_addr] = AgentStatus.Playing    

        if self.task_config.get_store_trajectories() or self._use_global_defender:
            self._agent_trajectories[agent_addr] = self._reset_trajectory(agent_addr)
        self.logger.info(f"\tAgent {agent_name} ({agent_addr}), registred as {agent_role}")
        return Observation(self._agent_states[agent_addr], 0, False, {})

    def _remove_player(self, agent_addr:tuple)->dict:
        """
        Removes player from the game.
        """
        self.logger.info(f"Removing player {agent_addr} from the Coordinator")
        agent_info = {}
        if agent_addr in self.agents:
            agent_info["state"] = self._agent_states.pop(agent_addr)
            agent_info["status"] = self._agent_statuses.pop(agent_addr)
            agent_info["num_steps"] = self._agent_steps.pop(agent_addr)
            agent_info["reset_request"] = self._reset_requests.pop(agent_addr)
            agent_info["end_reward"] = self._agent_rewards.pop(agent_addr, None)
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
                win_conditions[agent_role] = self._world.update_goal_dict(
                    self.task_config.get_win_conditions(agent_role=agent_role)
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
                    self.task_config.get_goal_description(agent_role=agent_role)
                )
            except KeyError:
                goal_descriptions[agent_role] = ""
            self.logger.info(f"Goal description for role '{agent_role}': {goal_descriptions[agent_role]}")
        return goal_descriptions
    
    def _get_max_steps_per_role(self)->dict:
        """
        Method for finding max amount of steps in 1 episode for each agent role in the game.
        """
        max_steps = {}
        for agent_role in self.ALLOWED_ROLES:
            try:
                max_steps[agent_role] = self.task_config.get_max_steps(agent_role)
            except KeyError:
                max_steps[agent_role] = None
            self.logger.info(f"Max steps in episode for '{agent_role}': {max_steps[agent_role]}")
        return max_steps
    
    async def _process_join_game_action(self, agent_addr: tuple, action: Action)->None:
        """ "
        Method for processing Action of type ActionType.JoinGame
        """
        self.logger.info(f"New Join request by  {agent_addr}.")
        if agent_addr not in self.agents:
            agent_name = action.parameters["agent_info"].name
            agent_role = action.parameters["agent_info"].role
            if agent_role in self.ALLOWED_ROLES:
                self.agents[agent_addr] = (agent_name, agent_role)
                self._agent_statuses[agent_addr] = AgentStatus.JoinRequested
                self.logger.debug(f"Sending JoinRequest by {agent_addr} to the world_action_queue")
                await self._world_action_queue.put((agent_addr, action, self._starting_positions_per_role[agent_role]))
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
                await self._answers_queues[agent_addr].put(response_msg_json)
        else:
            self.logger.info("\tError in registration, agent already exists!")
            output_message_dict = {
                    "to_agent": agent_addr,
                    "status": str(GameStatus.BAD_REQUEST),
                    "message": "Agent already exists.",
                }
            response_msg_json = self.convert_msg_dict_to_json(output_message_dict)
            await self._answers_queues[agent_addr].put(response_msg_json)

    def _create_response_to_reset_game_action(self, agent_addr: tuple) -> dict:
        """ "
        Method for generatating answers to Action of type ActionType.ResetGame after all agents requested reset
        """
        self.logger.info(
            f"Coordinator responding to RESET request from agent {agent_addr}"
        )
        # store trajectory in file if needed
        if self.task_config.get_store_trajectories():
            self._store_trajectory_to_file(agent_addr)
        new_observation = Observation(self._agent_states[agent_addr], 0, self.episode_end, {})
        # reset trajectory
        self._agent_trajectories[agent_addr] = self._reset_trajectory(agent_addr)
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
    
    async def _process_generic_action(self, agent_addr: tuple, action: Action) ->None:
        """
        Method processing the Actions relevant to the environment
        """
        self.logger.info(f"Processing {action} from {agent_addr}")
        if not self.episode_end:
            self._agent_last_action[agent_addr] = action
            await self._world_action_queue.put((agent_addr, action, self._agent_states[agent_addr]))
        else:
            # Episode finished, just send back the rewards and final episode info
            self._assign_end_rewards()
            self.logger.info(f"{self.episode_end}, {self._agent_statuses[agent_addr]}")
            output_message_dict = self._generate_episode_end_message(agent_addr)
            response_msg_json = self.convert_msg_dict_to_json(output_message_dict)
            await self._answers_queues[agent_addr].put(response_msg_json)
    
    def _generate_episode_end_message(self, agent_addr:tuple)->dict:
        """
        Method for generating response when agent attemps to make a step after episode ended.
        """
        current_observation = self._agent_observations[agent_addr]
        reward = self._agent_rewards[agent_addr]
        end_reason = str(self._agent_statuses[agent_addr])
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
                    # some keys are missing in the known_dict
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
    
    def _max_steps_reached(self, agent_addr:tuple) ->bool:
        """
        Checks if the agent reached the max allowed steps. Only applies to role 'Attacker'
        """
        self.logger.debug(f"Checking timout for {self.agents[agent_addr]}")
        agent_role = self.agents[agent_addr][1]
        if self._steps_limit_per_role[agent_role]:
            if self._agent_steps[agent_addr] >= self._steps_limit_per_role[agent_role]:
                self.logger.info("Timeout reached by {self.agents[agent_addr]}!")
                return True
        else:
            self.logger.debug(f"No max steps defined for role {agent_role}")
            return False

    def _assign_end_rewards(self)->None:
        """
        Method which assings rewards to each agent which has finished playing
        """
        self.logger.debug("Assigning rewards")
        is_episode_over = self.episode_end
        for agent, status in self._agent_statuses.items():
            if agent not in self._agent_rewards.keys(): # reward has not been assigned yet
                agent_name, agent_role = self.agents[agent]
                if agent_role == "Attacker":
                    match status:
                        case AgentStatus.FinishedGoalReached:
                            self._agent_rewards[agent] = self._world._rewards["goal"]
                        case AgentStatus.FinishedMaxSteps:
                            self._agent_rewards[agent] = 0
                        case AgentStatus.FinishedBlocked:
                            self._agent_rewards[agent] = self._world._rewards["detection"]
                    self.logger.info(f"End reward for {agent_name}({agent_role}, status: '{status}') = {self._agent_rewards[agent]}")
                elif agent_role == "Defender":
                    if self._agent_statuses[agent] is AgentStatus.FinishedMaxSteps: #defender was responsible for the end
                        raise NotImplementedError
                        self._agent_rewards[agent] = 0
                    else:
                        if is_episode_over: #only assign defender's reward when episode ends
                            sucessful_attacks = list(self._agent_statuses.values).count("goal_reached")
                            if sucessful_attacks > 0:
                                self._agent_rewards[agent] = sucessful_attacks*self._world._rewards["detection"]
                                self._agent_statuses[agent] = "game_lost"
                            else: #no successful attacker
                                self._agent_rewards[agent] = self._world._rewards["goal"]
                                self._agent_statuses[agent] = "goal_reached"
                            self.logger.info(f"End reward for {agent_name}({agent_role}, status: '{status}') = {self._agent_rewards[agent]}")
                else:
                    if is_episode_over:
                        self._agent_rewards[agent] = 0
                        self.logger.info(f"End reward for {agent_name}({agent_role}, status: '{status}') = {self._agent_rewards[agent]}")
                        
    async def _handle_world_responses(self):
        """
        Continuously processes responses from the AIDojo World, evaluates them and sends messages to agents
        """
        try:
            self.logger.info("\tStarting task to handle AIDojo World responses")
            while True:
                try:
                    # Get a response from the World Response Queue
                    agent_id, response = await self._world_response_queue.get()
                    self.logger.info(f"Received response for agent {agent_id}: {response}")

                    # Processing of the response
                    response_msg_json = self._process_world_response(agent_id, response)
                    # Notify the agent if there is message
                    if len(response_msg_json) > 2: # we have NON EMPTY JSON  (len('{}') = 2)
                        self.logger.info(f"Generated response for agent {agent_id}: {response_msg_json}") 
                        await self._answers_queues[agent_id].put(response_msg_json)
                        self.logger.info(f"Placed response in answers queue for agent {agent_id}")
                    else:
                        self.logger.info(f"Empty response for agent {agent_id}: {response_msg_json}. Skipping") 
                    await asyncio.sleep(0.0000001)
                except Exception as e:
                    self.logger.error(f"Error handling world response: {e}")
        except asyncio.CancelledError:
            self.logger.info("\tTerminating by CancelledError")
        
    def _process_world_response(self, agent_addr:tuple, response:tuple)->str:
        """
        Method for generation of messages to the agent based on the  world response
        """
        agent_new_state, game_status = response
        output_message_dict = {}
        try:
            agent_status = self._agent_statuses[agent_addr]
            if agent_status is AgentStatus.JoinRequested:
                output_message_dict = self._process_world_response_created(agent_addr, game_status, agent_new_state)
            elif agent_status is AgentStatus.ResetRequested:
                output_message_dict = self._process_world_response_reset_done(agent_addr, game_status, agent_new_state)
            elif agent_status is AgentStatus.Quitting:
                if game_status is GameStatus.OK:
                    self.logger.debug(f"Agent {agent_addr} removed successfuly from the world")
                else:
                    self.logger.warning(f"Error when removing Agent {agent_addr} from the world")
                self._remove_player(agent_addr)
            elif agent_status in [AgentStatus.Ready, AgentStatus.Playing, AgentStatus.PlayingActive]:
                output_message_dict = self._process_world_response_step(agent_addr, game_status, agent_new_state)
            elif agent_status in [AgentStatus.FinishedBlocked, AgentStatus.FinishedGameLost, AgentStatus.FinishedGoalReached, AgentStatus.FinishedMaxSteps]:
                output_message_dict = self._process_world_response_step(agent_addr, game_status, agent_new_state)
            else:
                self.logger.error(f"Unsupported value '{agent_status}'!")
            
            msg_json = self.convert_msg_dict_to_json(output_message_dict)
            return msg_json
        except KeyError as e :
            self.logger.error(f"Agent {agent_addr} not found! {e}")

    def _process_world_response_created(self, agent_addr:tuple, game_status:GameStatus, new_agent_game_state:GameState)->dict:
        """
        Handles reply to Action.JoinGame for agent based on the response of the AIDojo World
        """
        # is agent correctly started in the world
        if game_status is GameStatus.CREATED: 
            observation = self._initialize_new_player(agent_addr, new_agent_game_state)
            agent_name, agent_role = self.agents[agent_addr]
            output_message_dict = {
                "to_agent": agent_addr,
                "status": str(game_status),
                "observation": observation_as_dict(observation),
                "message": {
                    "message": f"Welcome {agent_name}, registred as {agent_role}",
                    "max_steps": self._steps_limit_per_role[agent_role],
                    "goal_description": self._goal_description_per_role[agent_role],
                    "actions": [str(a) for a in ActionType],
                    "configuration_hash": self._CONFIG_FILE_HASH
                    },
            }
        else:
            # remove traces of agent from the game
            self._remove_player(agent_addr)
            output_message_dict = {
                "to_agent": agent_addr,
                "status": str(game_status),
                "message": f"Error when initializing the agent {agent_name}({agent_role})",
            }
        return output_message_dict

    def _process_world_response_reset_done(self, agent_addr, game_status, agent_new_state)->dict:
        """
        Handles  reply to Action.JoinGame for agent based on the response of the AIDojo World
        """
        if game_status is GameStatus.RESET_DONE:
            self._reset_requests[agent_addr] = False
            self._agent_steps[agent_addr] = 0
            self._agent_states[agent_addr] = agent_new_state
            self._agent_rewards.pop(agent_addr, None)
            if self._steps_limit_per_role[self.agents[agent_addr][1]]:
                # This agent can force episode end (has timeout and goal defined)
                self._agent_statuses[agent_addr] = AgentStatus.PlayingActive
            else:
                # This agent can NOT force episode end (does NOT timeout or goal defined)
                self._agent_statuses[agent_addr] = AgentStatus.Playing      
            output_message_dict = self._create_response_to_reset_game_action(agent_addr)
        else:
            # remove traces of agent from the game
            agent_name, agent_role = self.agents
            self._remove_player(agent_addr)
            output_message_dict = {
                "to_agent": agent_addr,
                "status": str(game_status),
                "message": f"Error when resetting the agent {agent_name} ({agent_role})",
            }
        return output_message_dict

    def _process_world_response_step(self, agent_addr, game_status, agent_new_state)->dict:
        if game_status is GameStatus.OK:
            if not self.episode_end:
                # increase the action counter
                self._agent_steps[agent_addr] += 1
                self.logger.info(f"{agent_addr} steps: {self._agent_steps[agent_addr]}")
                # register the new state
                self._agent_states[agent_addr] = agent_new_state
                # load the action which lead to the new state
                last_action = self._agent_last_action[agent_addr]
                # check timeout
                if self._max_steps_reached(agent_addr):
                    self._agent_statuses[agent_addr] = AgentStatus.FinishedMaxSteps        
                # check detection
                if self._check_detection(agent_addr, last_action):
                    self._agent_statuses[agent_addr] = AgentStatus.FinishedBlocked          
                # check goal
                if self._goal_reached(agent_addr):
                    self._agent_statuses[agent_addr] = AgentStatus.FinishedGoalReached
                # add reward for taking a step
                reward = self._world._rewards["step"]
                
                obs_info = {}
                end_reason = None
                if self._agent_statuses[agent_addr] is AgentStatus.FinishedGoalReached:
                    self._assign_end_rewards()
                    reward += self._agent_rewards[agent_addr]
                    end_reason = "goal_reached"
                    obs_info = {'end_reason': "goal_reached"}
                elif self._agent_statuses[agent_addr] is AgentStatus.FinishedMaxSteps:
                    self._assign_end_rewards()
                    reward += self._agent_rewards[agent_addr]
                    obs_info = {"end_reason": "max_steps"}
                    end_reason = "max_steps"
                elif self._agent_statuses[agent_addr] is AgentStatus.FinishedBlocked:
                    self._assign_end_rewards()
                    reward += self._agent_rewards[agent_addr]
                    obs_info = {"end_reason": "blocked"}
                
                # record step in trajecory
                self._add_step_to_trajectory(agent_addr, last_action, reward,self._agent_states[agent_addr], end_reason)
                new_observation = Observation(self._agent_states[agent_addr], reward, self.episode_end, info=obs_info)

                self._agent_observations[agent_addr] = new_observation

                output_message_dict = {
                    "to_agent": agent_addr,
                    "observation": observation_as_dict(new_observation),
                    "status": str(GameStatus.OK),
                }
            else:
                self._assign_end_rewards()
                output_message_dict = self._generate_episode_end_message(agent_addr)
        else: 
            output_message_dict = {
                "to_agent": agent_addr,
                "status": str(game_status),
                "message": f"Error when playing action {last_action}",
            }
        return output_message_dict

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
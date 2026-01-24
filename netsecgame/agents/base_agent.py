# Author: Ondrej Lukas, ondrej.lukas@aic.cvut.cz
# Basic agent class that is to be extended in each agent classes
import logging
import socket
import json
from abc import ABC 

from netsecgame.game_components import Action, GameState, Observation, ActionType, GameStatus, AgentInfo, ProtocolConfig, AgentRole

class BaseAgent(ABC):
    """
    Author: Ondrej Lukas, ondrej.lukas@aic.cvut.cz
    Basic agent for the network based NetSecGame environment. Implemenets communication with the game server.
    """

    def __init__(self, host, port, role:str)->None:
        self._connection_details = (host, port)
        self._logger = logging.getLogger(self.__class__.__name__)
        self._role = role
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect((host, port))
        except socket.error as e:
            self._logger.error(f"Socket error: {e}")
            self.sock = None
        self._logger.info("Agent created")
    
    def __del__(self):
        "In case the extending class did not close the connection, terminate the socket when the object is deleted."
        if self._socket:
            try:
                self._socket.close()
                self._logger.info("Socket closed")
            except socket.error as e:
                print(f"Error closing socket: {e}")
    
    def terminate_connection(self)->None:
        """Method for graceful termination of connection. Should be used by any class extending the BaseAgent."""
        if self._socket:
            try:
                self._socket.close()
                self._socket = None
                self._logger.info("Socket closed")
            except socket.error as e:
                print(f"Error closing socket: {e}")
    @property
    def socket(self)->socket.socket | None:
        return self._socket
    
    @property
    def role(self)->str:
        return self._role
    
    @property
    def logger(self)->logging.Logger:
        return self._logger

    def make_step(self, action: Action) -> Observation | None:
        """
        Executes a single step in the environment by sending the agent's action to the server and receiving the resulting observation.

        Args:
            action (Action): The action to be performed by the agent.

        Returns:
            Observation: The new observation received from the server, containing the updated game state, reward, end flag, and additional info.
            None: If no observation is received from the server.

        Raises:
            Any exceptions raised by the `communicate` method are propagated.
        """
        _, observation_dict, _ = self.communicate(action)
        if observation_dict:
            return Observation(GameState.from_dict(observation_dict["state"]), observation_dict["reward"], observation_dict["end"], observation_dict["info"])
        else:
            return None
    
    def communicate(self, data:Action)-> tuple:
        """
        Exchanges data with the server and returns the server's response.
        This method sends an `Action` object to the server and waits for a response.
        The response is expected to be a JSON-encoded string containing status, observation, and message fields.
        The method returns a tuple containing the parsed status, observation, and message.
        Args:
            data (Action): The action to send to the server. Must be an instance of `Action`.
        Returns:
            tuple: A tuple containing:
                - status (GameStatus): The status object parsed from the server response.
                - observation (dict): The observation data from the server.
                - message (str or None): An optional message from the server.
        Raises:
            ValueError: If `data` is not of type `Action`.
            ConnectionError: If the server response is incomplete or missing the end-of-message marker.
            Exception: If there is an error sending data to the server.
        """

        def _send_data(socket, msg:str)->None:
            try:
                self._logger.debug(f'Sending: {msg}')
                socket.sendall(msg.encode())
            except Exception as e:
                self._logger.error(f'Exception in _send_data(): {e}')
                raise e
            
        def _receive_data(socket)->tuple:
            """
            Receive data from server
            """
            # Receive data from the server
            data = b""  # Initialize an empty byte string

            while True:
                chunk = socket.recv(ProtocolConfig.BUFFER_SIZE)  # Receive a chunk
                if not chunk:  # If no more data, break (connection closed)
                    break
                data += chunk
                if ProtocolConfig.END_OF_MESSAGE in data:  # Check if EOF marker is present
                    break
            if ProtocolConfig.END_OF_MESSAGE not in data:
                raise ConnectionError("Unfinished connection.")
            data = data.replace(ProtocolConfig.END_OF_MESSAGE, b"")  # Remove EOF marker
            data = data.decode() 
            self._logger.debug(f"Data received from env: {data}")
            # extract data from string representation
            data_dict = json.loads(data)
            # Add default values if dict keys are missing
            status = data_dict["status"] if "status" in data_dict else ""
            observation = data_dict["observation"] if "observation" in data_dict else {}
            message = data_dict["message"] if "message" in data_dict else None

            return GameStatus.from_string(str(status)), observation, message
        
        if isinstance(data, Action):
            data = data.to_json()
        else:
            raise ValueError("Incorrect data type! Data should be ONLY of type Action")
        
        _send_data(self._socket, data)
        return _receive_data(self._socket)
    
    def register(self)->Observation | None:
        """
        Method for registering agent to the game server.
        Classname is used as agent name and the role is based on the 'role' argument.
        Returns initial observation if registration was successful, None otherwise.

        Args:
            role (str): Role of the agent, either 'attacker' or 'defender'.
        Returns:
            Observation: Initial observation if registration was successful, None otherwise.
        """
        try:
            self._logger.info(f'Registering agent as {self.role}')
            status, observation_dict, message = self.communicate(Action(ActionType.JoinGame,
                                                                         parameters={"agent_info":AgentInfo(self.__class__.__name__,self.role.value)}))
            if status is GameStatus.CREATED:
                self._logger.info(f"\tRegistration successful! {message}")
                return Observation(GameState.from_dict(observation_dict["state"]), observation_dict["reward"], observation_dict["end"], message)
            else:
                self._logger.error(f'\tRegistration failed! (status: {status}, msg:{message}')
                return None
        except Exception as e:
            self._logger.error(f'Exception in register(): {e}')

    def request_game_reset(self, request_trajectory=False, randomize_topology=True, randomize_topology_seed=None) -> Observation|None:
        """
        Requests a game reset from the server. Optionally requests a trajectory and/or topology randomization.
        Args:
            request_trajectory (bool): If True, requests the server to provide a trajectory of the last episode.
            randomize_topology (bool): If True, requests the server to randomize the network topology for the next episode. Defaults to True.
            randomize_topology_seed (int): If provided, requests the server to use this seed for randomizing the network topology. Defaults to None.
        Returns:
            Observation: The initial observation after the reset if successful, None otherwise.
        """
        self._logger.debug("Requesting game reset")
        status, observation_dict, message = self.communicate(Action(ActionType.ResetGame, parameters={"request_trajectory": request_trajectory, "randomize_topology": randomize_topology}))
        if status:
            self._logger.debug('\tReset successful')
            return Observation(GameState.from_dict(observation_dict["state"]), observation_dict["reward"], observation_dict["end"], message)
        else:
            self._logger.error(f'\rReset failed! (status: {status}, msg:{message}')
            return None

if __name__ == "__main__":
    # Example usage of BaseAgent
    GAME_PORT = 5000 # Change to the appropriate port
    agent = BaseAgent("localhost", GAME_PORT, AgentRole.Attacker)
    # Register the agent
    observation = agent.register()
    if observation:
        print("Initial Observation:", observation)
    # Gracefully terminate the connection
    agent.terminate_connection()
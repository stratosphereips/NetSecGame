import logging
import asyncio
from netsecgame.game_components import Action, ActionType, ProtocolConfig

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
        self.logger = logging.getLogger("AgentServer")
    
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

#!/usr/bin/env python
# Server for the Aidojo project, coordinator
# Author: sebastian garcia, sebastian.garcia@agents.fel.cvut.cz
import argparse
from datetime import datetime
import logging
import json
import asyncio
#from env.network_security_game import NetworkSecurityEnvironment
from env.NetSecGame import NetSecGame
from pathlib import Path
import os
import time

# Set the logging
log_filename=Path('coordinator.log')
if not log_filename.parent.exists():
    os.makedirs(log_filename.parent)
logging.basicConfig(filename=log_filename, filemode='w', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S',level=logging.INFO)
logger = logging.getLogger('Coordinator')

# Get a new world
myworld = NetSecGame('env/netsecenv_conf.yaml')

__version__ = 'v0.1'

async def start_tasks():
    """
    High level funciton to start all the other asynchronous tasks and queues
    - Reads the conf of the coordinator
    - Creates queues 
    - Start the main part of the coordinator
    - Start a server that listens for agents
    """
    logger.info('Starting all tasks')

    # Read the configuration
    logger.info('Read configuration of coordinator.')
    with open(args.configfile, 'r') as jfile:
        confjson = json.load(jfile)
    host = confjson.get('host', None)
    port = confjson.get('port', None)

    # Create two asyncio queues
    actions_queue = asyncio.Queue()
    answers_queue = asyncio.Queue()

    logger.info('Starting the server listening for agents')
    # start_server returns a coroutine, so 'await' runs this coroutine
    server = await asyncio.start_server(lambda r, w: handle_new_agent(r, w, actions_queue, answers_queue), host, port)

    logger.info('Starting main coordinator tasks')
    asyncio.create_task(main_coordinator(actions_queue, answers_queue))

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    logger.info(f'\tServing on {addrs}')

    try:
        async with server:
            # The server will keep running concurrently due to serve_forever
            await server.serve_forever()
            # When you call await server.serve_forever(), it doesn't block the execution of the program. Instead, it starts an event loop that keeps running in the background, accepting and handling connections as they come in. The await keyword allows the event loop to run other asynchronous tasks while waiting for events like incoming connections.
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        await server.wait_closed()

def send_to_agent(message, answers_queue):
    """
    Send a message string to the agent
    """
    pass

async def main_coordinator(actions_queue, answers_queue):
    """
    The main coordinator is in charge of everything exept the coomuncation with agents
    Work includes:
    - Accesing the queue of actions
    - Checking the actions done
    - Contacting the environment
    - Accesing the queue of answers
    """
    try:
        global myworld
        world_env = myworld.get_world()

        logger.info("Main coordinator started.")

        # First send them options
        # - Start alone 
        # - wait for other players
        # - give a nick name
        # - version

        while True:

            logger.info("Coordinator running.")
            # Read messages from the queue
            agent_addr, message = await actions_queue.get()
            if message is not None:
                logger.info(f"Coordinator received: {message}.")
                # Convert message to dict
                message_dict = json.loads(message)
                if message_dict['message'] == 'New agent':
                    # Send initial message
                    logger.info("Coordinator sending welcome message.")
                    output_message = '{"to_agent": "all", "status": {"#players": 1, "running": "True", "time": "0"}, "message": "Welcome to the NetSecEnv game! Insert your nickname."}'
                    await answers_queue.put(output_message)
                else:
                    # Access agent information
                    logger.info(f'Coordinator received from agent {agent_addr}: {message}')
                    # Answer the agents
                    message_out = f"I received your message {message}"
                    output_message_dict = {"agent": agent_addr, "message": message_out}
                    output_message = json.dumps(output_message_dict)
                    await answers_queue.put(output_message)
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.debug('Terminating by KeyboardInterrupt')
        raise SystemExit
    except Exception as e:
        logger.error(f'Exception in main_coordinator(): {e}')
        print(f'Exception in main_coordinator(): {e}')

async def send_world(writer, world_json):
    """
    Send the world to the agent
    """
    writer.write(bytes(str(world_json).encode()))

async def handle_new_agent(reader, writer, actions_queue, answers_queue):
    """
    Function to deal with each new agent
    """
    try:
        addr = writer.get_extra_info('peername')
        logger.info(f"New agent connected: {addr}")

        # Tell the coordinator a new agent connected
        message = '{"message": "New agent"}'
        await actions_queue.put((addr, message))

        # Get the message from the coordinator
        message = await answers_queue.get()
        if message is None:
            message = '{"message":"Waiting..."}'

        logger.info(f"Sending to agent {addr}: {message}")
        await send_world(writer, message)
        await writer.drain()

        while True:
            data = await reader.read(100)
            raw_message = data.decode().strip()

            logger.info(f"Handler received from {addr}: {raw_message!r}")

            # Build the correct message format for the coordinator
            message_dict = {"message": str(raw_message)}
            message_str = json.dumps(message_dict)

            # Put the message and agent information into the queue
            await actions_queue.put((addr, message_str))

            # Read messages from the queue and send to the agent
            message = await answers_queue.get()
            if message is None:
                message = '{"message":"Waiting..."}'

            logger.info(f"Handle sending to agent {addr}: {message!r}")
            await send_world(writer, message)
            try:
                await writer.drain()
            except ConnectionResetError:
                logger.info(f'Connection lost. Agent disconnected.')
    except KeyboardInterrupt:
        logger.debug('Terminating by KeyboardInterrupt')
        raise SystemExit
    except Exception as e:
        logger.error(f'Exception in handle_new_agent(): {e}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser = argparse.ArgumentParser(description=f"NetSecGame Coordinator Server version {__version__}. Author: Sebastian Garcia, sebastian.garcia@agents.fel.cvut.cz", usage='%(prog)s [options]')
    parser.add_argument('-v', '--verbose', help='Verbosity level. This shows more info about the results.', action='store', required=False, type=int)
    parser.add_argument('-d', '--debug', help='Debugging level. This shows inner information about the flows.', action='store', required=False, type=int)
    parser.add_argument('-c', '--configfile', help='Configuration file.', action='store', required=True, type=str)

    args = parser.parse_args()
    # Get the event loop and run it
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(start_tasks())
    except KeyboardInterrupt:
        logger.debug('Terminating by KeyboardInterrupt')
        raise SystemExit
    except Exception as e:
        logger.error(f'Exception in __main__: {e}')
    finally:
        loop.close()
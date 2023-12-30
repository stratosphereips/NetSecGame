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

clients = {}


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

    logger.info('Starting the server listening for clients')
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
        logger.info("Main coordinator running.")
        while True:
            logger.info("Coordinator waiting.")
            # Read messages from the queue
            item = await actions_queue.get()
            client_addr, message = item
            if message is not None:
                # Access client information
                logger.info(f'Main received from client {client_addr}: {message}')

                # Answer the agents
                message_out = f"Message from Coordinator: I received your message {message}"
                output_message_dict = {"agent": client_addr, "message": message_out}
                output_message = json.dumps(output_message_dict)
                await answers_queue.put(output_message)
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.debug('Terminating by KeyboardInterrupt')
        raise SystemExit
    except Exception as e:
        logger.error(f'Exception in main_coordinator(): {e}')

async def send_world(writer, world_json):
    """
    Send the world to the client
    """
    writer.write(bytes(str(world_json).encode()))

async def handle_new_agent(reader, writer, actions_queue, answers_queue):
    """
    Function to deal with each new agent
    """
    try:
        global myworld
        addr = writer.get_extra_info('peername')
        logger.info(f"New client connected: {addr}")

        world_env = myworld.get_world()

        # Mix the message with the world data
        first_message = '{"message": "Shall we play a game?"}'
        json_message = json.loads(first_message)
        json_message.update(world_env)
        message = json.dumps(json_message, indent=2)

        logger.info(f"Sending to client {addr}: {message}")
        await send_world(writer, message)
        await writer.drain()

        while True:
            try:
                data = await reader.read(20)
                message = data.decode()

                logger.info(f"Handle received from {addr}: {message!r}")

                # Put the message and client information into the queue
                await actions_queue.put((addr, message))

                # Read messages from the queue and send to the client
                message = await answers_queue.get()
                if message is None:
                    message = '{"message":"Waiting..."}'

                logger.info(f"Handle sending to client {addr}: {message!r}")
                await send_world(writer, message)
                try:
                    await writer.drain()
                except ConnectionResetError:
                    logger.info(f'Connection lost. Client disconnected.')

            except Exception as e:
                logger.info(f"Client disconnected: {e}")
                break
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
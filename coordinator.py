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
    Start the coordinator main part
    This is an asynchronous function that deals with both the synchronous and asynchronous code
    """
    # Read the configuration
    logger.info('Starting all coordinator tasks')

    with open(args.configfile, 'r') as jfile:
        confjson = json.load(jfile)
    logger.info('Configuration of coordination read.')
    host = confjson.get('host', None)
    port = confjson.get('port', None)

    logger.info('Starting main coordinator tasks')
    asyncio.create_task(main_coordinator())

    logger.info('Starting the server listening for clients')
    # start_server returns a coroutine, so 'await' runs this coroutine
    server = await asyncio.start_server(handle_new_client, host, port)
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

async def main_coordinator():
    """
    The main coordinator is in charge of everything exept the coomuncation with agents
    Work includes:
    - Accesing the queue of actions
    - Checking the actions done
    - Contacting the environment
    - Accesing the queue of answers
    """
    global myworld
    while True:
        print("Asynchronous function running...")
        await asyncio.sleep(2)

async def send_world(writer, world_json):
    """
    Send the world to the client
    """
    writer.write(bytes(str(world_json).encode()))

async def handle_new_client(reader, writer):
    """
    Function to deal with each new client
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

                logger.info(f"Received {message!r} from {addr}")

                #myworld.process_input_key(message)

                message = '{"message":"Sup?"}'
                logger.info(f"Sending to client {addr}: {message!r}")
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
        logger.error(f'Exception in handle_new_client(): {e}')


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
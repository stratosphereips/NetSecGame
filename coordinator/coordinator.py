#!/usr/bin/env python
# Server for the Aidojo project, coordinator
# Author: sebastian garcia, eldraco@gmail.com. 

import argparse
from datetime import datetime
import logging
import json
import time
import asyncio


__version__ = 'v0.1'

async def server(host, port):
    """
    Start the socket server
    Define the function to deal with data
    """
    logger = logging.getLogger('SERVER')
    logger.info('Starting server')
    server = await asyncio.start_server(handle_new_client, host, port)
    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    logger.info(f'Serving on {addrs}')
    async with server:
        await server.serve_forever()


async def send_world(writer, world_json):
    """
    Send the world to the client
    """
    writer.write(bytes(str(world_json).encode()))


class Game_HGW(object):
    """
    Class Game_HGW
    Organizes and implements the logic of the game
    """
    def __init__(self):
        """
        Initialize the game env
        Returns a game object

        The game has a world, with characters and positions
        it also has rules, rewards actions and dynamics of movements
        """
        # Read the conf
        with open(args.configfile, 'r') as jfile:
            confjson = json.load(jfile)

        # Create the world as a dict
        logging.info(f"Starting a new world")
        self.world = {}
    

    def get_world(self):
        """
        Get the world
        """
        return self.world

    def check_collisions(self):
        """
        Check goal of world and other collisions
        """
        pass

    def check_end(self):
        """
        Check the end

        Two OR conditions
        - If steps is 0 then the game ends
        - If the output gate was crossed, the game ends
        """
        logging.info('Checking end')

    def process_input_key(self, key):
        """
        process input key
        """
        # The world positions is a 100-values vector (in 100 states)
        # X (horizontal in the grid) goes from 0 to 9 to the right, Y (vertical in the grid) goes from 0 to 9 down
        # The top-left corner is X=0, Y=0
        # The lower-right corner is X=9, Y=9
        # The position vector starts with all the X positions for Y=0, then all the X positions for Y=1, etc.
        # [Y0X0, Y0X1, ..., Y0X9, Y1X0, Y1X1, ..., Y9X9]

        # To transform from a X, Y system to the large position vector that goes from 0 to 99 we do
        # position = X + (Y * 10)
        # examples
        #  X=0, Y=0 -> pos=0
        #  X=9, Y=0 -> pos=9
        #  X=8, Y=0 -> pos=8
        #  X=3, Y=1 -> pos=13
        #  X=0, Y=9 -> pos=90

        # Find the new positions of the character
        # Delete the current character
        self.world['positions'][self.objects['character']['x'] + (self.objects['character']['y'] * self.world['size_x'])] = self.background
        if "UP" in key:
            # Check that the boundaries of the game were not violated
            if not self.check_walls(0, -1):
                self.objects['character']['y'] -= 1
        elif "DOWN" in key:
            if not self.check_walls(0, 1):
                self.objects['character']['y'] += 1
        elif "RIGHT" in key:
            if not self.check_walls(1, 0):
                self.objects['character']['x'] += 1
        elif "LEFT" in key:
            if not self.check_walls(-1, 0):
                self.objects['character']['x'] -= 1
        logging.info(f"The char was moved to {self.objects['character']['x']} {self.objects['character']['y']} ")

        # Compute the character move penalty in reward
        self.world['reward'] = self.move_penalty
        # Decrease one step
        self.steps -= 1

        # Check that the boundaries of the game were not violated
        self.check_boundaries()

        # Check if there were any collisions
        self.check_collisions()

        # Check if the game ended
        self.check_end()

        # Move the character
        self.world['positions'][self.objects['character']['x'] + (self.objects['character']['y'] * self.world['size_x'])] = self.objects['character']['icon']
        self.world['current_character_position'] = self.objects['character']['x'] + (self.objects['character']['y'] * self.world['size_x'])

        # Put fixed objects back
        self.put_fixed_items()

        logging.info(f"Score after key: {self.world['reward']}")

        # Cooldown period
        # Each key inputted is forced to wait a little
        # This should be at least 0.1 for human play or replay mode
        # Should be 0 for agents to play
        time.sleep(confjson.get('speed', 0))


# Main
####################
if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser = argparse.ArgumentParser(description=f"Hacker Grid World Server version {__version__}. Author: Sebastian Garcia, eldraco@gmail.com", usage='%(prog)s -n <screen_name> [options]')
    parser.add_argument('-v', '--verbose', help='Verbosity level. This shows more info about the results.', action='store', required=False, type=int)
    parser.add_argument('-d', '--debug', help='Debugging level. This shows inner information about the flows.', action='store', required=False, type=int)
    parser.add_argument('-c', '--configfile', help='Configuration file.', action='store', required=True, type=str)
    parser.add_argument('-t', '--test', help='Run serve in test mode. Speed is 0.1 and port is the port in the conf + 1', action='store_true', required=False)

    args = parser.parse_args()
    logging.basicConfig(filename='server.log', filemode='a', format='%(asctime)s, %(name)s: %(message)s', datefmt='%H:%M:%S', level=logging.CRITICAL)

    with open(args.configfile, 'r') as jfile:
        confjson = json.load(jfile)
        if args.test:
            confjson['speed'] = 0.1
            confjson['port'] = confjson['port'] + 1

    try:
        logging.debug('Server start')
        asyncio.run(server(confjson.get('host', None), confjson.get('port', None)))
    except KeyboardInterrupt:
        logging.debug('Terminating by KeyboardInterrupt')
        raise SystemExit
    except Exception as e:
        logging.error(f'Exception in __main__: {e}')
    finally:
        logging.debug('Goodbye')
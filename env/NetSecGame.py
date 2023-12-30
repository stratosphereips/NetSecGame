import logging
from utils.utils import ConfigParser
import time

class NetSecGame(object):
    """
    Class Game_HGW
    Organizes and implements the logic of the game
    """
    def __init__(self, config_file):
        """
        Initialize the game env
        Returns a game object

        The game has a world, with characters and positions
        it also has rules, rewards actions and dynamics of movements
        """
        # Read the conf
        self.task_config = ConfigParser(config_file)

        # Create the world as a dict
        logger = logging.getLogger('NetSecEnv')
        logger.info(f"Starting a new world")
        self.world = {}

    def get_world(self):
        """
        Get the world
        """
        return {"World": "Earth"}
        #return self.world

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
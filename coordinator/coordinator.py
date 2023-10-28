#!/usr/bin/env python
# Authors:
# Sebastian Garcia, sebastian.garcia@agents.fel.cvut.cz, eldraco@gmail.com
# Stratosphere Laboratory, Czech Technical University in Prague
#
# Coordinator
# This program is the start of the multi-agent coordination betwen agents and the environments

import sys
from os import path
sys.path.append( path.dirname(path.dirname( path.abspath(__file__) ) ))
import argparse    
from os import path
import logging
from utils.utils import ConfigParser

class Agent():
    """
    Class Agent to control and manage one individual agent
    """
    def __init__(self) -> None:
        """
        Init class
        """
        pass

class Coordinator():
    """
    Class coordinator
    """
    def __init__(self) -> None:
        """
        Init class
        """
        pass

    def read_configuration(self, conf_file):
        """
        Read the configuration of the coordinator
        """
        if args.verbose > 0:
            print('Read the configuration')
        self.task_config = ConfigParser(conf_file)
        agents = self.task_config.config['agents']
        if args.verbose > 0:
            print(f'Amount of agents read: {len(agents)}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-v',
                        '--verbose',
                        help='Verbosity level. This shows more info about the results.',
                        action='store',
                        required=False,
                        default=1,
                        type=int)
    parser.add_argument('-d',
                        '--debug',
                        help='Debugging level. This shows inner information about the flows.',
                        action='store',
                        required=False,
                        default=0,
                        type=int)
    parser.add_argument('-c',
                        '--configuration',
                        help='Name of the configuration file to read.',
                        action='store',
                        required=True,
                        type=str)
    parser.add_argument("--task_config_file", help="Reads the task definition from a configuration file", default=path.join(path.dirname(__file__), 'coordinator-conf.yaml'), action='store', required=False)
    logging.basicConfig(filename=path.join(path.dirname(__file__), 'logs/coordinator-conf.log'), filemode='a', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.INFO)
    logger = logging.getLogger('DoubleQ-agent')

    args = parser.parse_args()

coordintor = Coordinator()

if args.configuration:
    # Read the conf
    coordintor.read_configuration(args.configuration)
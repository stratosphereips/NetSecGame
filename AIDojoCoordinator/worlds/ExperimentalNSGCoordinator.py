import itertools
import argparse
import logging
import os
from pathlib import Path
from AIDojoCoordinator.utils.utils import get_logging_level
from AIDojoCoordinator.game_components import GameState, Action, ActionType, Service,IP
from AIDojoCoordinator.worlds.NSEGameCoordinator import NSGCoordinator




class ExperimentalNSGCoordinator(NSGCoordinator):

    def __init__(self, game_host, game_port, task_config, allowed_roles=["Attacker", "Defender", "Benign"], seed=42, include_block_action=True):
        super().__init__(game_host, game_port, task_config, allowed_roles, seed)
        self._action_mapping = None
        self._include_block_action = include_block_action

    def _initialize(self):
        # First do the parent initialization
        super()._initialize()
        # All components are initialized, now we can set the action mapping
        self.logger.debug("Creating action mapping for the game.")
        self._create_action_mapping()

    def _create_action_mapping(self)-> dict:
        """
        Create the action mapping for the game.
        This method should be overridden in subclasses to provide specific action mappings.
        """
        actions = {}
        all_ips = [self._ip_mapping[ip] for ip in self._ip_to_hostname.keys()]
        print(all_ips)
        all_networks = self._networks.keys()
        all_data = set()
        ip_with_services = {}
        for ip in all_ips:
            if ip in self._ip_to_hostname:
                hostname = self._ip_to_hostname[ip]
                if hostname in self._services:
                    ip_with_services[ip] = self._services[hostname]
        
        # Collect all data from all hosts
        for data in self._data.values():
            all_data.update(data)
        host_combinations = itertools.product(all_ips, all_ips)
        
        
        # Network Scans
        for source_host, target_network in itertools.product(all_ips, all_networks):
            actions[len(actions)] = Action(
                ActionType.ScanNetwork,
                parameters={
                    "source_host": source_host,
                    "target_network": target_network
                }
            )
        # Service Scans
        for source_host, target_host in host_combinations:
            actions[len(actions)] = Action(
                ActionType.FindServices,
                parameters={
                    "source_host": source_host,
                    "target_host": target_host
                }
            )
        # Service Exploits
        for source_host, target_host in itertools.product(all_ips, ip_with_services.keys()):
            for service in ip_with_services[target_host]:
                actions[len(actions)] = Action(
                    ActionType.ExploitService,
                    parameters={
                        "source_host": source_host,
                        "target_host": target_host,
                        "service": service
                    }
                )
        # Data Scans
        for source_host, target_host in itertools.product(all_ips, all_ips):
            actions[len(actions)] = Action(
                ActionType.FindData,
                parameters={
                    "source_host": source_host,
                    "target_host": target_host
                }
            )
        # Data transfers
        for (source_host, target_host), datum in itertools.product(itertools.product(all_ips, all_ips), all_data):
            actions[len(actions)] = Action(
                ActionType.ExfiltrateData,
                parameters={
                    "source_host": source_host,
                    "target_host": target_host,
                    "data": datum
                }
            )

        # Blocks
        if self._include_block_action:
            for (source_host, target_host), blocked_ip in itertools.product(itertools.product(all_ips, all_ips), all_ips):
                actions[len(actions)] = Action(
                    ActionType.BlockIP,
                    parameters={
                        "source_host": source_host,
                        "target_host": target_host,
                        "blocked_ip": blocked_ip
                    }
                )
        self.logger.info(f"Created action mapping with {len(actions)} actions.")
        for action_id, action in actions.items():
            self.logger.debug(f"Action {action_id}: {action.type} with parameters {action.parameters}")
        self._action_mapping = actions

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NetSecGame Coordinator Server Author: Ondrej Lukas ondrej.lukas@aic.fel.cvut.cz",
        usage="%(prog)s [options]",
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
    
    parser.add_argument(
        "-gh",
        "--game_host",
        help="host where to run the game server",
        action="store",
        required=False,
        type=str,
        default="127.0.0.1",
    )
    
    parser.add_argument(
        "-gp",
        "--game_port",
        help="Port where to run the game server",
        action="store",
        required=False,
        type=int,
        default="9000",
    )

    parser.add_argument(
        "-c",
        "--task_config",
        help="File with the task configuration",
        action="store",
        required=True,
        type=str,
        default="netsecenv_conf.yaml",
    )

    args = parser.parse_args()
    print(args)
    # Set the logging
    log_filename = Path("logs/EXPERIMENTAL_NSG_coordinator.log")
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
  
    game_server = ExperimentalNSGCoordinator(args.game_host, args.game_port, args.task_config)
    # Run it!
    game_server.run()
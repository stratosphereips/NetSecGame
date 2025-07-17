import itertools
from AIDojoCoordinator.utils.utils import get_logging_level
from AIDojoCoordinator.game_components import GameState, Action, ActionType, Service,IP
from AIDojoCoordinator.worlds.NSEGameCoordinator import NSGCoordinator




class ExperimentalNSGCoordinator(NSGCoordinator):

    def __init__(self, game_host, game_port, task_config, allowed_roles=..., seed=42):
        super().__init__(game_host, game_port, task_config, allowed_roles, seed)
        self._action_mapping = None

    def _initialize(self):
        # First do the parent initialization
        super()._initialize()
        # All components are initialized, now we can set the action mapping
        self._create_action_mapping()

    def _create_action_mapping(self)-> dict:
        """
        Create the action mapping for the game.
        This method should be overridden in subclasses to provide specific action mappings.
        """
        actions = {}
        all_ips = [self._ip_mapping[ip] for ip in self._ip_to_hostname.values()]
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
                ActionType.ScanServices,
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
        for source_host, target_host in host_combinations:
            actions[len(actions)] = Action(
                ActionType.FindData,
                parameters={
                    "source_host": source_host,
                    "target_host": target_host
                }
            )
        # Data transfers
        for (source_host, target_host), datum in itertools.product(host_combinations, all_data):
            actions[len(actions)] = Action(
                ActionType.ExfiltrateData,
                parameters={
                    "source_host": source_host,
                    "target_host": target_host,
                    "data": datum
                }
            )

        # Blocks
        for (source_host, target_host), blocked_ip in itertools.product(host_combinations, all_ips):
            actions[len(actions)] = Action(
                ActionType.BlockHost,
                parameters={
                    "source_host": source_host,
                    "target_host": target_host,
                    "blocked_ip": blocked_ip
                }
            )
        self.logger.info(f"Created action mapping with {len(actions)} actions.")
        for action_id, action in actions.items():
            self.logger.warning(f"Action {action_id}: {action.type} with parameters {action.parameters}")
        self._action_mapping = actions
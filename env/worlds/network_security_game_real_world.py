#Authors
# Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
# Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz

from env.game_components import GameState, Action, ActionType, Service,IP,Network
from env.worlds.network_security_game import NetworkSecurityEnvironment
from env.worlds.NSEGameCoordinator import NSGCoordinator
import subprocess
import xml.etree.ElementTree as ElementTree

class NSERealWorldGameCoordinator(NSGCoordinator):
    
    def _execute_action(self, current_state:GameState, action:Action)-> GameState:
        """
        Execute the action and update the values in the state
        Before this function it was checked if the action was successful
        So in here all actions were already successful.

        - actions_type: Define if the action is simulated in netsecenv or in the real world
        - agent_id: is the name or type of agent that requested the action

        Returns: A new GameState
        """
        next_state = None
        match action.type:
            case ActionType.ScanNetwork:
                next_state = self._execute_scan_network_action_real_world(current_state, action)
            case ActionType.FindServices:   
                next_state = self._execute_find_services_action_real_world(current_state, action)
            case ActionType.FindData:
                next_state = self._execute_find_data_action(current_state, action)
            case ActionType.ExploitService:
                next_state = self._execute_exploit_service_action(current_state, action)
            case ActionType.ExfiltrateData:
                next_state = self._execute_exfiltrate_data_action(current_state, action)
            case ActionType.BlockIP:
                next_state = self._execute_block_ip_action(current_state, action)
            case _:
                raise ValueError(f"Unknown Action type or other error: '{action.type}'")
        return next_state

    def _execute_scan_network_action_real_world(self, current_state:GameState, action:Action)->GameState:
        """
        Executes the ScanNetwork action in the the real world
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data, next_blocked = self._state_parts_deep_copy(current_state)
        self.logger.info(f"\t\tScanning {action.parameters['target_network']} in real world.")
        nmap_file_xml = 'nmap-result.xml'
        command = f"nmap -sn {action.parameters['target_network']} -oX {nmap_file_xml}"
        _ = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        # We ignore the result variable for now
        tree = ElementTree.parse(nmap_file_xml)
        root = tree.getroot()
        new_ips = set()
        for host in root.findall('.//host'):
            status_elem = host.find('./status')
            if status_elem is not None:
                status = host.find('./status').get('state')
            else:
                status = ""
            ip_elem = host.find('./address[@addrtype="ipv4"]')
            if ip_elem is not None:
                ip = IP(str(ip_elem.get('addr')))
            else:
                ip = ""
            
            mac_elem = host.find('./address[@addrtype="mac"]')
            if mac_elem is not None:
                mac_address = mac_elem.get('addr', '')
                vendor = mac_elem.get('vendor', '')
            else:
                mac_address = ""
                vendor = ""

            self.logger.debug(f"\t\t\tAdding {ip} to new_ips. {status}, {mac_address}, {vendor}")
            new_ips.add(ip)
        next_known_h = next_known_h.union(new_ips)
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)
    
    def _execute_find_services_action_real_world(self, current_state:GameState, action:Action)->GameState:
        """
        Executes the FindServices action in the real world
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data, next_blocked = self._state_parts_deep_copy(current_state)
        self.logger.info(f"\t\tScanning ports in {action.parameters['target_host']} in real world.")
        nmap_file_xml = 'nmap-result.xml'
        command = f"nmap -sT -n {action.parameters['target_host']} -oX {nmap_file_xml}"
        _ = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        # We ignore the result variable for now
        tree = ElementTree.parse(nmap_file_xml)
        root = tree.getroot()

        # service_dict is a dict. Key=IP(), values= set of Service() objects
        found_services = set()
        port_id = ''
        protocol = ''
        for host in root.findall('.//host'):
            status_elem = host.find('./status')
            if status_elem is not None and status_elem.get('state') == 'up':
                ports_elem = host.find('./ports')
                if ports_elem is not None:
                    for port in root.findall('.//port[@protocol="tcp"]'):
                        state_elem = port.find('./state[@state="open"]')
                        if state_elem is not None:
                            port_id = port.get('portid')
                            protocol = port.get('protocol')
                            service_elem = port.find('./service[@name]')
                            service_name = service_elem.get('name') if service_elem is not None else "Unknown"
                            service_fullname = f'{port_id}/{protocol}/{service_name}'
                            service = Service(name=service_fullname, type=service_name, version='', is_local=False)
                            found_services.add(service)

                next_services[action.parameters["target_host"]] = found_services
        
        # If host was not known, add it to the known_hosts and known_networks ONLY if there are some found services
        if action.parameters["target_host"] not in next_known_h:
            self.logger.info(f"\t\tAdding {action.parameters['target_host']} to known_hosts")
            next_known_h.add(action.parameters["target_host"])
            next_nets = next_nets.union({net for net, values in self._networks.items() if action.parameters["target_host"] in values})
        return GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)


class NetworkSecurityEnvironmentRealWorld(NetworkSecurityEnvironment):
    """
    Class to manage the whole network security game in the real world (current network)
    It uses some Cyst libraries for the network topology
    It presents a env environment to play
    """
    def __init__(self, task_config_file, world_name="NetSecEnvRealWorld") -> None:
        super().__init__(task_config_file, world_name)

    def _execute_scan_network_action_real_world(self, current_state:components.GameState, action:components.Action)->components.GameState:
        """
        Executes the ScanNetwork action in the the real world
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data, next_blocked = self._state_parts_deep_copy(current_state)
        self.logger.info(f"\t\tScanning {action.parameters['target_network']} in real world.")
        nmap_file_xml = 'nmap-result.xml'
        command = f"nmap -sn {action.parameters['target_network']} -oX {nmap_file_xml}"
        _ = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        # We ignore the result variable for now
        tree = ElementTree.parse(nmap_file_xml)
        root = tree.getroot()
        new_ips = set()
        for host in root.findall('.//host'):
            status_elem = host.find('./status')
            if status_elem is not None:
                status = host.find('./status').get('state')
            else:
                status = ""
            ip_elem = host.find('./address[@addrtype="ipv4"]')
            if ip_elem is not None:
                ip = components.IP(str(ip_elem.get('addr')))
            else:
                ip = ""
            
            mac_elem = host.find('./address[@addrtype="mac"]')
            if mac_elem is not None:
                mac_address = mac_elem.get('addr', '')
                vendor = mac_elem.get('vendor', '')
            else:
                mac_address = ""
                vendor = ""

            self.logger.debug(f"\t\t\tAdding {ip} to new_ips. {status}, {mac_address}, {vendor}")
            new_ips.add(ip)
        next_known_h = next_known_h.union(new_ips)
        return components.GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)
    
    def _execute_find_services_action_real_world(self, current_state:components.GameState, action:components.Action)->components.GameState:
        """
        Executes the FindServices action in the real world
        """
        next_nets, next_known_h, next_controlled_h, next_services, next_data, next_blocked = self._state_parts_deep_copy(current_state)
        self.logger.info(f"\t\tScanning ports in {action.parameters['target_host']} in real world.")
        nmap_file_xml = 'nmap-result.xml'
        command = f"nmap -sT -n {action.parameters['target_host']} -oX {nmap_file_xml}"
        _ = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        # We ignore the result variable for now
        tree = ElementTree.parse(nmap_file_xml)
        root = tree.getroot()

        # service_dict is a dict. Key=IP(), values= set of Service() objects
        found_services = set()
        port_id = ''
        protocol = ''
        for host in root.findall('.//host'):
            status_elem = host.find('./status')
            if status_elem is not None and status_elem.get('state') == 'up':
                ports_elem = host.find('./ports')
                if ports_elem is not None:
                    for port in root.findall('.//port[@protocol="tcp"]'):
                        state_elem = port.find('./state[@state="open"]')
                        if state_elem is not None:
                            port_id = port.get('portid')
                            protocol = port.get('protocol')
                            service_elem = port.find('./service[@name]')
                            service_name = service_elem.get('name') if service_elem is not None else "Unknown"
                            service_fullname = f'{port_id}/{protocol}/{service_name}'
                            service = components.Service(name=service_fullname, type=service_name, version='', is_local=False)
                            found_services.add(service)

                next_services[action.parameters["target_host"]] = found_services
        
        # If host was not known, add it to the known_hosts and known_networks ONLY if there are some found services
        if action.parameters["target_host"] not in next_known_h:
            self.logger.info(f"\t\tAdding {action.parameters['target_host']} to known_hosts")
            next_known_h.add(action.parameters["target_host"])
            next_nets = next_nets.union({net for net, values in self._networks.items() if action.parameters["target_host"] in values})
        return components.GameState(next_controlled_h, next_known_h, next_services, next_data, next_nets, next_blocked)

    def _execute_action(self, current_state:components.GameState, action:components.Action, agent_id)-> components.GameState:
        """
        Execute the action and update the values in the state
        Before this function it was checked if the action was successful
        So in here all actions were already successful.

        - actions_type: Define if the action is simulated in netsecenv or in the real world
        - agent_id: is the name or type of agent that requested the action

        Returns: A new GameState
        """
        next_state = None
        match action.type:
            case components.ActionType.ScanNetwork:
                    next_state = self._execute_scan_network_action_real_world(current_state, action)
            case components.ActionType.FindServices:
                next_state = self._execute_find_services_action_real_world(current_state, action)
            case components.ActionType.FindData:
                # This Action type is not implemente in real world - use the simualtion
                next_state = self._execute_find_data_action(current_state, action)
            case components.ActionType.ExploitService:
                # This Action type is not implemente in real world - use the simualtion
                next_state = self._execute_exploit_service_action(current_state, action)
            case components.ActionType.ExfiltrateData:
                # This Action type is not implemente in real world - use the simualtion
                next_state = self._execute_exfiltrate_data_action(current_state, action)
            case components.ActionType.BlockIP:
                # This Action type is not implemente in real world - use the simualtion
                next_state = self._execute_block_ip_action(current_state, action)
            case _:
                raise ValueError(f"Unknown Action type or other error: '{action.type}'")
        return next_state

    def step(self, state:components.GameState, action:components.Action, agent_id:tuple)-> components.GameState:
        """
        Take a step in the environment given an action
        in: action
        out: observation of the state of the env
        """
        self.logger.info(f"Agent {agent_id}. Action: {action}")
        # Reward for taking an action
        reward = self._rewards["step"]

        # 1. Perform the action
        self._actions_played.append(action)
        
        # No randomness in action success - we are playing in real world
        next_state = self._execute_action(state, action, agent_id)
        

        
        # Make the state we just got into, our current state
        current_state = state
        self.logger.info(f'New state: {next_state} ')


        # Save the transition to the episode replay buffer if there is any
        if self._episode_replay_buffer is not None:
            self._episode_replay_buffer.append((current_state, action, reward, next_state))
        # Return an observation
        return next_state
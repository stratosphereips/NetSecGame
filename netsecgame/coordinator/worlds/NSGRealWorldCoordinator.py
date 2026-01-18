#Authors
# Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
# Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz

import subprocess
import xml.etree.ElementTree as ElementTree
import logging
import argparse
import os
from pathlib import Path

from netsecgame.utils.utils import get_logging_level
from netsecgame.game_components import GameState, Action, ActionType, Service,IP
from netsecgame.worlds.NSEGameCoordinator import NSGCoordinator

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NetSecGame Coordinator Server (Real World) Author: Ondrej Lukas ondrej.lukas@aic.fel.cvut.cz; sebastian.garcia@agents.fel.cvut.cz",
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
    log_filename = Path("NSG_real_world_coordinator.log")
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
  
    game_server = NSERealWorldGameCoordinator(args.game_host, args.game_port, args.task_config)
    # Run it!
    game_server.run()
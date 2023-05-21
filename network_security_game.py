#Author: Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import netaddr
from random import random
from game_components import *
import yaml
from random import choice, seed
import random
import copy
from cyst.api.configuration import *
import numpy as np
#from scenarios.scenario_configuration import *
import scenarios.scenario_configuration
import scenarios.smaller_scenario_configuration
import scenarios.tiny_scenario_configuration
import logging

# Set the logging
logging.basicConfig(filename='netsecenv.log', filemode='a', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.INFO)
logger = logging.getLogger('Net-sec-env')

class Network_Security_Environment(object):
    def __init__(self, random_start=True, verbosity=0) -> None:
        """
        Class to manage the whole network security game
        It uses some Cyst libraries for the network topology
        It presents a env environment to play
        """
        # Dictionary of all the nodes in environment
        # Nodes are hosts, attackers, etc (but not router, connections or exploits)
        self._nodes = {}
        # Connections are how can connect to whom.
        self._connections = {}
        # A list of all ips in the sytem?
        self._ips = {}
        # A list of the networks we know
        self._networks = []
        # All the exploits in the environment
        self._exploits = {}
        # If the game starts randomly or not
        self._random_start = random_start
        # Place of the defender
        self._defender_placements = None
        # Current state of the game
        self._current_state = None
        # If the game finished
        self._done = False
        # ?
        self._src_file = None
        # Verbosity. 
        # If the episode/action was detected by the defender
        self.detected = False
        # TODO change to logging level
        self.verbosity = verbosity
    
    @property
    def timestamp(self)->int:
        """
        Property used to show an interface to agents about what timestamp it is
        """
        return self._step_counter
    
    def get_all_actions(self):
        """
        Return all the possible actions in the game
        """
        logger.info(f'All actions requested')
        actions = {}
        # For each...?
        for ip, name in self._ips.items():
            #network scans
            for net in self._get_networks_from_host(ip):
                actions[len(actions)] = Action("ScanNetwork",{"target_network":net})
            #portscans
            actions[len(actions)] = Action("FindServices", {"target_host":ip})

            #Run Code in service
            for service in self._get_services_from_host(ip):
                actions[len(actions)] = Action("ExecuteCodeInService", {"target_host":ip, "target_service":service.name})
            #find data
            actions[len(actions)] = Action("FindData", {"target_host":ip})

            #exfiltrate data
            for data in self._get_data_in_host(ip):
                for src in self._ips.keys():
                    for trg in self._ips.keys():
                        actions[len(actions)] = Action("ExfiltrateData", {"target_host":trg, "data":data, "source_host":src})
        return actions

    def initialize(self, win_conditons:dict, defender_positions:dict, attacker_start_position:dict, max_steps=10, agent_seed=False)-> Observation:
        """
        Initializes the environment with start and goal configuraions.
        Entities in the environment are either read from CYST objects directly or from the serialization file.
        It ALSO resets the environment, so it returns a full state. This is different from other gym envs.
        """
        # Process parameters
        self._attacker_start_position = attacker_start_position
        self.max_steps = max_steps
        if not defender_positions:
            self._defender_placements = False
        else:
            self._place_defences(defender_positions)
        self._win_conditions = win_conditons

        # Set the seed if passed by the agent
        if agent_seed:
            np.random.seed(agent_seed)
            random.seed(agent_seed)
            logger.info(f'Agent passed a seed, setting to {agent_seed}')
        
        # Check if position of data is randomized 
        logger.info(f"Checking if we need to set the data to win in a random location.")
        # For each known data point in the conditions to win
        for k, v in win_conditons["known_data"].items():
            # Was the position defined as random?
            if isinstance(v, str) and v.lower() == "random":
                logger.info(f"\tYes we do.")
                # Load all the available data from all hosts
                available_data = []
                for node in self._nodes.values():
                    # For each node, independent of what type of node they are...
                    try:                   
                        # Search for passive services, since this is where the 'DataConfig' is
                        for service in node.passive_services:
                            # Search for private data
                            for dataconfig in service.private_data:
                                # Store all places where we can put the data
                                available_data.append((dataconfig.owner, dataconfig.description))
                    except AttributeError:
                        pass
                # From all available data, randomly pick the one that is going to be used to win the game
                self._win_conditions["known_data"][k] = {choice(available_data)}
                logger.info(f"\tWinning condition of `known_data` randomly set to {self._win_conditions['known_data']}")
            else:
                logger.info(f"\tNo we don't.")
        return self.reset()
    
    def _create_starting_state(self) -> GameState:
        """
        Builds the starting GameState. Currently, we artificially extend the knonw_networks with +- 1 in the third octet.
        """
        logging.info('Creating the starting state')
        if self._random_start:
            logging.info('Start position of agent is random')
            controlled_hosts = set()
                    # Random choose a host from all the possible in the network
                    controlled_hosts.add(choice(hosts))
                    logging.info(f'\t\tMaking agent start in {controlled_host}')
                """
                # Im deleting the option to be 'random' but also specify a certain host to start. 
                # If the agent has random start, it must specify a network to start
                else:
                    logging.info('\t\t{controlled_host} is a host, so start here.')
                    controlled_hosts.add(controlled_host)
                """
        else:
            logging.info('Start position of agent is fixed in a host')
            controlled_hosts = self._attacker_start_position["controlled_hosts"]

        known_networks = set()
        # Extend the known networks with the neighbouring networks
        # TODO remove this!
        for controlled_host in controlled_hosts:
            for net in self._get_networks_from_host(controlled_host): #TODO
                known_networks.add(str(net))
                if net.is_private(): #TODO
                    net.value += 256
                    if net.is_private():
                        known_networks.add(str(net))
                    net.value -= 2*256
                    if net.is_private():
                        known_networks.add(str(net))
                    #return value back to the original
                    net.value += 256

        known_hosts = self._attacker_start_position["known_hosts"].union(controlled_hosts)

        return GameState(controlled_hosts, known_hosts, self._attacker_start_position["known_services"],self._attacker_start_position["known_data"], known_networks)
    
    def _place_defences(self, placements:dict)->None:
        # TODO
        if placements:
            self._defender_placements = True
        else:
            self._defender_placements = False
        # assert self._defender_placements ==  None
        # self._defender_placements = placements
    
    def process_cyst_config(self, configuration_objects:list)->None:
        """
        Process the cyst configuration file
        """
        # Define inner functions
        def process_node_config(node):
            # Process a node
            self._nodes[node.id] = node
            # Get all the IPs of this node and store them in our list of known IPs
            for interface in node.interfaces:
                self._ips[str(interface.ip)] = node.id

        def process_router_config(router):
            # Process a router
            # Add the router to the list of nodes. This goes
            # against CYST definition. Check if we can modify it in CYST
            if router.id.lower() == 'internet':
                # Ignore the router called 'internet' because it is not a router
                # in our network
                return False
            self._nodes[router.id] = router

            # Get all the IPs of this node and store them in our list of known IPs
            for interface in router.interfaces:
                self._ips[str(interface.ip)] = router.id
                # Get the networks where this router is connected and add them as known networks
                self._networks.append(str(interface.net))
                logging.info(f'Added {str(interface.net)} to the list of available networks in the game.')

        def process_exploit_config(exploit):
            # Process an exploit
            self._exploits = exploit

        def process_connection_config(connection):
            # Process the connections
            # self._connections = np.zeros([len(node_to_id),len(node_to_id)])
            #for connection in connections:
            #    self._connections[node_to_id[connection.src_id],node_to_id[connection.dst_id]] = 1
            pass

        # Store all objects into local categories.
        # Objects are all the nodes, routers, connections and exploits
        # In Cyst a node can be many things, from a device, to an attacker. :-(
        # But for some reason is not a router, a connection or an exploit
        for object in configuration_objects:
            if isinstance(object, NodeConfig):
                process_node_config(object)
            elif isinstance(object, RouterConfig):
                process_router_config(object)
            elif isinstance(object, ConnectionConfig):
                process_connection_config(object)
            elif isinstance(object, ExploitConfig):
                process_exploit_config(object)

    
    def get_valid_actions(self, state:GameState)->list:
        """
        Returns list of valid actions in a given state.
        """
        actions = []
        #Scan network
        for net in state.known_networks:
            actions.append(Action("ScanNetwork",{"target_network":net}))
        #Find services
        for host in state.known_hosts:
            actions.append(Action("FindServices", {"target_host":host}))
        #Find Data
        for host in state.known_hosts.union(state.controlled_hosts):
            a = Action("FindData", {"target_host":host})
            if a not in actions:
                actions.append(a)
        #ExecuteCodeInService
        for host, services in state.known_services.items():
            for s in services:
                actions.append(Action("ExecuteCodeInService", {"target_host":host, "target_service":s.name}))
        #ExfiltrateData
        for source, data in state.known_data.items():
            for target in state.controlled_hosts:
                if source != target and len(data) > 0:
                    for d in data:
                        actions.append(Action("ExfiltrateData", {"target_host":target, "data":d, "source_host":source}))
        return actions

    def _get_services_from_host(self, host_ip)-> set:
        """
        Returns set of Service tuples from given hostIP
        TODO active services
        """
        try:
            # Check if the IP has a correct IP format
            netaddr.IPAddress(host_ip)
            # Do we have this IP in our list of ips?
            if host_ip in self._ips:
                # Get the information we have about this ip
                host = self._nodes[self._ips[host_ip]]
                services = set()
                # Is the host of type NodeConfig?
                if isinstance(host, NodeConfig):
                    for service in host.passive_services:
                        if service.local:
                            if host_ip in self._current_state.controlled_hosts:
                                services.add(Service(service.type, "passive", service.version))
                        else:
                            services.add(Service(service.type, "passive", service.version))
                return services
            # Return empty services
            return {}
        except (ValueError, netaddr.core.AddrFormatError) as error:
            logging.error("HostIP is invalid. Due to {error}")
            # Return empty services
            return {}
    
    def _get_networks_from_host(self, host_ip)->set:
        try:
            host = self._ips[host_ip]
        except KeyError:
            print(f"Given host IP '{host_ip}' is unknown!")
        networks = set()
        for interface in self._nodes[host].interfaces:
            if isinstance(interface, InterfaceConfig):
                networks.add(interface.net)
        #print(host_ip, networks, self._nodes[host].interfaces)
        return networks
    
    def _get_data_in_host(self, host_ip)->list:
        data = set()
        if host_ip in self._ips:
            host = self._nodes[self._ips[host_ip]]
            if isinstance(host, NodeConfig):
                for service in host.passive_services:
                    try:
                        for d in service.private_data:
                            data.add((d.owner, d.description))
                    except AttributeError:
                        pass
                        #service does not contain any data
        return data

    def _execute_action(self, current:GameState, action:Action)-> GameState:

        if action.transition.type == "ScanNetwork":
            #does the network exist?
            new_ips = set()
            # Read all the theoretically possible IPs in a network
            for ip in netaddr.IPNetwork(action.parameters["target_network"]):
                # If any of those IPs is in our list of known IPs, return it
                if str(ip) in self._ips.keys():
                    new_ips.add(str(ip))

            # Add the IPs in the network to the list of known hosts
            extended_hosts = current.known_hosts.union(new_ips)
            return GameState(current.controlled_hosts, extended_hosts, current.known_services, current.known_data, current.known_networks)

        elif action.transition.type == "FindServices":
            found_services =  self._get_services_from_host(action.parameters["target_host"])
            extended_services = {k:v for k,v in current.known_services.items()}
            if len(found_services) > 0:
                if action.parameters["target_host"] not in extended_services.keys():
                    extended_services[action.parameters["target_host"]] = frozenset(found_services)
                else:
                    extended_services[action.parameters["target_host"]] = frozenset(extended_services[action.parameters["target_host"]]).union(found_services)
            return GameState(current.controlled_hosts, current.known_hosts, extended_services, current.known_data, current.known_networks)
        elif action.transition.type == "FindData":
            extended_data = {k:v for k,v in current.known_data.items()}
            new_data = self._get_data_in_host(action.parameters["target_host"])
            if len(new_data) > 0:
                if action.parameters["target_host"] not in extended_data.keys():
                    extended_data[action.parameters["target_host"]] = new_data
                else:
                    extended_data[action.parameters["target_host"]].union(new_data)
            return GameState(current.controlled_hosts, current.known_hosts, current.known_services, extended_data, current.known_networks)
        
        elif action.transition.type == "ExecuteCodeInService":
            extended_controlled_hosts = set([x for x in current.controlled_hosts])
            if action.parameters["target_host"] not in current.controlled_hosts:
                extended_controlled_hosts.add(action.parameters["target_host"])
            new_networks = self._get_networks_from_host(action.parameters["target_host"])
            extended_networks = current.known_networks.union(new_networks)
            return GameState(extended_controlled_hosts, current.known_hosts, current.known_services, current.known_data, extended_networks)
        
        elif action.transition.type == "ExfiltrateData":
            extended_data = {k:v for k,v in current.known_data.items()}
            if len(action.parameters["data"]) > 0:
                if action.parameters["target_host"] not in current.known_data.keys():
                    extended_data[action.parameters["target_host"]] = {action.parameters["data"]}
                else:
                    extended_data[action.parameters["target_host"]].union(action.parameters["data"])
            return GameState(current.controlled_hosts, current.known_hosts, current.known_services, extended_data, current.known_networks)
        else:
            raise ValueError(f"Unknown Action type: '{action.transition.type}'")
    
    def is_valid_action(self, state:GameState, action:Action)-> bool:
        if action.transition.type == "ScanNetwork":
            try:
                net = netaddr.IPNetwork(action.parameters["target_network"])
                return True
            except netaddr.core.AddrFormatError:
                return False
        elif action.transition.type == "FindServices":
            target = action.parameters["target_host"]
            accessible = [target in netaddr.IPNetwork(n) for n in state.known_networks] #TODO Add check for FW rules
            return action.parameters["target_host"] in self._ips and any(accessible)
        elif action.transition.type == "FindData":
            return action.parameters["target_host"] in state.controlled_hosts or action.parameters["target_host"] in state.known_hosts
        elif action.transition.type == "ExecuteCodeInService":
            return action.parameters["target_host"] in state.known_services and action.parameters["target_service"] in [x.name for x in state.known_services[action.parameters["target_host"]]]
        elif action.transition.type == "ExfiltrateData":
            if action.parameters["source_host"] in state.controlled_hosts or action.parameters["source_host"] in state.known_hosts:
                try:
                    data_accessible = action.parameters["data"] in state.known_data[action.parameters["source_host"]]
                    target = action.parameters["target_host"]
                    target_accessible = [target in netaddr.IPNetwork(n) for n in state.known_networks] #TODO Add check for FW rules
                    return data_accessible and target_accessible  and len(action.parameters["data"]) > 0
                except KeyError as e:
                    #print(e)
                    return False
            else:
                return False #for now we don't support this option TODO
        else:
            print(f"Unknown transition type '{action.transition.type}'")
            return False
    
    def is_goal(self, state:GameState)->bool:
        #check if all netoworks are known
        networks = set(self._win_conditions["known_networks"]) <= set(state.known_networks) 
        known_hosts = set(self._win_conditions["known_hosts"]) <= set(state.known_hosts)
        controlled_hosts = set(self._win_conditions["controlled_hosts"]) <= set(state.controlled_hosts)
        try:
            services = True
            keys_services = [k for k in self._win_conditions["known_services"].keys() if k not in state.known_services]
            if len(keys_services) == 0:
                for k in self._win_conditions["known_services"].keys():
                    for s in self._win_conditions["known_services"][k]:
                        if s not in state.known_services[k]:
                            services = False
                            break

            else:
                services = False
        except KeyError:
            services = False
        
        try:
            data = True
            keys_data = [k for k in self._win_conditions["known_data"].keys() if k not in state.known_data]
            if len(keys_data) == 0:
                for k in self._win_conditions["known_data"].keys():
                    if not set(self._win_conditions["known_data"][k]) <= set(state.known_data[k]):
                        data = False
                        break

            else:
                data = False
        except KeyError:
            data = False
        if self.verbosity > 1:
            print("networks", networks)
            print("known", known_hosts)
            print("controlled", controlled_hosts)
            print("services", services)
            print("data", data)
        return networks and known_hosts and controlled_hosts and services and data
    
    def _is_detected(self, state, action:Action)->bool:
        if self._defender_placements:
            value = random.random() < action.transition.default_detection_p     
            logger.info(f'There is a defender and the detection is {value}')
            return value
        else: #no defender
            logger.info(f'There is NO defender')
            return False 
    
    def reset(self)->Observation:
        """
        Function to reset the state of the game 
        and play a new episode
        """
        logger.info(f'------Game resetted. New startging ------')
        self._done = False
        self._step_counter = 0
        self.detected = False  
        self._current_state = self._create_starting_state()
        return Observation(self._current_state, 0, self._done, {})
    
    def step(self, action:Action)-> Observation:
        """
        Take a step in the environment given an action

        in:
        - action
        out:
        - observation of the state of the env
        """
        if not self._done:
            logger.info(f'Step taken')
            self._step_counter += 1

            reason = {}
            # 1. Check if the action was successful or not
            if random.random() <= action.transition.default_success_p:
                # The action was successful
                logger.info(f'Action {action} sucessful')

                # Get the next state given the action
                next_state = self._execute_action(self._current_state, action)

                # Reard for making an action
                reward = -1     #action.transition.default_reward - action.transition.default_cost
            else: 
                # The action was not successful
                logger.info(f'Action {action} not sucessful')

                # State does not change
                next_state = self._current_state

                # Reward for taking an action
                reward = -1 #action.transition.default_cost

                if self.verbosity >=1:
                    print("Action unsuccessful")

            # 2. Check if the new state is the goal state
            is_goal = self.is_goal(next_state)
            if is_goal:
                # It is the goal
                # Give reward
                reward += 100  
                logger.info(f'Goal reached')
                # Game ended
                self._done = True
                logger.info(f'Game ended')
                reason = {'end_reason':'goal_reached'}

            # 3. Check if the action was detected
            detected = self._is_detected(self._current_state, action)
            if detected:
                logger.info(f'Action detected')
                # Reward should be negative
                reward -= 50
                # Mark the environment as detected
                self.detected = True
                reason = {'end_reason':'detected'}
                self._done = True
                logger.info(f'Game ended')

            # 4. Check if the max number of steps of the game passed already
            if self._step_counter >= self.max_steps:
                logger.info(f'Game timeout')
                self._done = True
                logger.info(f'Game ended')
                reason = {'end_reason':'timeout'}

            # Make the state we just got into, our current state
            self._current_state = next_state

            # Return an observation
            return Observation(next_state, reward, self._done, reason)
        else:
            raise ValueError("Interaction over! No more steps can be made in the environment")


if __name__ == "__main__":
    # Create the network security environment
    env = Network_Security_Environment(random_start=True, verbosity=0)
    
    # Read network setup from predefined CYST configuration
    env.process_cyst_config(scenarios.scenario_configuration.configuration_objects)

    # Test random data and start position
    goal = {
        "known_networks":set(),
        "known_hosts":set(),
        "controlled_hosts":set(),
        "known_services":{},
        "known_data":{"213.47.23.195":"random"}
    }
    attacker_start = {
        "known_networks":set(),
        "known_hosts":set(),
        "controlled_hosts":{"213.47.23.195","192.168.2.0/24"},
        "known_services":{},
        "known_data":{}
    }

    # Test normal winning conditions and starting position
    """
    goal = {
        "known_networks":set(),
        "known_hosts":{},
        "controlled_hosts":{},
        "known_services":{},
        "known_data":{"213.47.23.195":{("User1", "DataFromServer1"),("User1", "DatabaseData")}}
    }

    # Define where the attacker will start
    attacker_start = {
        "known_networks":set(),
        "known_hosts":set(),
        "controlled_hosts":{"192.168.2.2", "213.47.23.195"},
        "known_services":{'213.47.23.195': [Service(name='listener', type='passive', version='1.0.0'), Service(name='bash', type='passive', version='5.0.0')]},
        "known_data":{"213.47.23.195":{("User1", "DataFromServer1"),("User1", "DatabaseData")}}
    }
    """

    # Do we have a defender? 
    defender = True

    # Initialize the game
    state_1 = env.initialize(win_conditons=goal, defender_positions=defender, attacker_start_position=attacker_start, max_steps=50, agent_seed=42)
    print(state_1)
    env.get_all_actions()
    print(state_1.controlled_hosts)

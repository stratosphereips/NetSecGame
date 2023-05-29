#Author: Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import netaddr
from game_components import *
import yaml
from random import choice, seed
import random
import copy
from cyst.api.configuration import *
import numpy as np
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
        # All the nodes in the game. Node are hosts, attackers, etc (but not router, connections or exploits)
        self._nodes = {}
        # Connections are how can connect to whom.
        self._connections = {}
        # A dict of all ips in the env, ordered by IP as str() and the object is the id in the _nodes dictionary
        self._ips = {}
        # A dict of the networks present in the game. These are NOT the known networks by the agents
        # self._networks has as key the str of the network and as values a list of the object ids contained in this network.
        self._networks = {}
        # A list of all the hosts where the attacker can start in a random start
        self.hosts_to_start = []
        # All the exploits in the game
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
        # Return an observation after reset
        obs = self.reset()
        return obs
    
    def _create_starting_state(self) -> GameState:
        """
        Builds the starting GameState. Currently, we artificially extend the knonw_networks with +- 1 in the third octet.
        """
        known_networks = set()
        controlled_hosts = set()

        logging.info('Creating the starting state')

        if self._random_start:
            # Random start
            logging.info('Start position of agent is random')
            logging.info(f'Choosing from {self.hosts_to_start}')
            controlled_hosts.add(str(choice(self.hosts_to_start)))
            logging.info(f'\t\tMaking agent start in {controlled_hosts}')
        else:
            # Not random start
            logging.info('Start position of agent is fixed in a host')
            controlled_hosts = self._attacker_start_position["controlled_hosts"]

        # Extend the known networks with the neighbouring networks
        # TODO remove this!
        for controlled_host in controlled_hosts:
            for net in self._get_networks_from_host(controlled_host): #TODO
                known_networks.add(str(net))
                if net.is_private(): #TODO
                    net.value += 256
                    if net.is_private():
                        known_networks.add(str(net))
                        if str(net) not in self._networks:
                            self._networks[str(net)] = []
                    net.value -= 2*256
                    if net.is_private():
                        known_networks.add(str(net))
                        if str(net) not in self._networks:
                            self._networks[str(net)] = []
                    #return value back to the original
                    net.value += 256

        # Add the controlled hosts to the list of known hosts
        known_hosts = self._attacker_start_position["known_hosts"].union(controlled_hosts)

        game_state = GameState(controlled_hosts, known_hosts, self._attacker_start_position["known_services"], self._attacker_start_position["known_data"], known_networks)
        return game_state
    
    def _place_defences(self, placements:dict)->None:
        """
        Place the defender
        For now only if it is present
        """
        if placements:
            self._defender_placements = True
        else:
            self._defender_placements = False
    
    def process_cyst_config(self, configuration_objects:list)->None:
        """
        Process the cyst configuration file
        """
        # Define inner functions
        def process_node_config(node):
            # Process a node
            self._nodes[node.id] = node
            logging.info(f'\tAdded {str(node.id)} to the list of available nodes.')
            # Get all the IPs of this node and store them in our list of known IPs
            for interface in node.interfaces:
                # Store in _ips . This is candidate for deletion
                self._ips[str(interface.ip)] = node.id
                logging.info(f'\tAdded IP {str(interface.ip)} to the list of available ips.')

                # Check if it is a candidate for random start
                # Becareful, it will add all the IPs for this node
                for service in node.passive_services:
                    if service.type == "can_attack_start_here":
                        self.hosts_to_start.append(str(interface.ip))

                # Store the networks where this node is connected in the list of networks of the env
                # If the network does not exist it will be created in our dict
                try:
                    _ = self._networks[str(interface.net)]
                except KeyError:
                    # First time
                    self._networks[str(interface.net)] = []
                self._networks[str(interface.net)].append(node.id)
                logging.info(f'\tAdded network {str(interface.net)} to the list of available nets, with node {node.id}.')

        def process_router_config(router):
            # Process a router
            # Add the router to the list of nodes. This goes
            # against CYST definition. Check if we can modify it in CYST
            if router.id.lower() == 'internet':
                # Ignore the router called 'internet' because it is not a router
                # in our network
                return False

            # Add the router as node in our net
            self._nodes[router.id] = router

            # Get all the IPs and nets of this router and store them in our dicts
            for interface in router.interfaces:
                self._ips[str(interface.ip)] = router.id
                # Get the networks where this router is connected and add them as networks in the env
                try:
                    _ = self._networks[str(interface.net)]
                except KeyError:
                    # First time
                    self._networks[str(interface.net)] = []
                self._networks[str(interface.net)].append(router.id)
                logging.info(f'\tAdded {str(interface.net)} to the list of available networks in the game.')

        def process_exploit_config(exploit):
            # Process an exploit
            logging.info(f'\t\tAdding exploit {exploit.id}')
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
        logging.info(f'Reading CYST conf')
        for object in configuration_objects:
            logging.info(f'\tProcesssing obj {object.id}')
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
        
        # For each action, return all the objects that are known to the agent as parameter for that action
        """
        actions = []
        # ScanNetwork
        for net in state.known_networks:
            actions.append(Action("ScanNetwork",{"target_network":net}))

        # FindServices
        for host in state.known_hosts:
            actions.append(Action("FindServices", {"target_host":host}))

        # Find Data
        for host in state.known_hosts:
            actions.append(Action("FindData", {"target_host":host}))

        # ExecuteCodeInService
        for host, services in state.known_services.items():
            for service in services:
                actions.append(Action("ExecuteCodeInService", {"target_host":host, "target_service":service.name}))

        # ExfiltrateData
        for source, data in state.known_data.items():
            for target in state.controlled_hosts:
                if source != target and len(data) > 0:
                    for datum in data:
                        actions.append(Action("ExfiltrateData", {"target_host":target, "data":datum, "source_host":source}))
        return actions

    def _get_services_from_host(self, host_ip)-> set:
        """
        Returns set of Service tuples from given IP
        This is an access to the data for that IP, without regard of
        any checking of IP in the env or state
        """
        services = set()

        # Do we have this ip in our env?
        try:
            node_id = self._ips[host_ip]
        except KeyError:
            return services

        # Get the information we have about this ip
        node = self._nodes[node_id]
        # Is the host of type NodeConfig? We could have given an NodeExploit
        if isinstance(node, NodeConfig):
            for service in node.passive_services:
                #services.add(service)
                services.add(Service(service.type, "passive", service.version))
        return services

    def _get_networks_from_host(self, host_ip)->set:
        """
        Get all the networks that this IP is connected to
        """
        try:
            host = self._ips[host_ip]
        except KeyError:
        # Get all the interfaces of this node
            if isinstance(interface, InterfaceConfig):
                networks.add(interface.net)
        #print(host_ip, networks, self._nodes[host].interfaces)
        return networks
    
    def _get_data_in_host(self, host_ip)->list:
        """
        Get all the data in this IP
        """
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
        """
        Execute the action and update the values in the state
        Before this function it was checked if the action was successful
        So in here all actions were already successful.
        """

        # ScanNetwork
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
            # Action FindServices
            # Get all the available services in the host that was attacked
            found_services =  self._get_services_from_host(action.parameters["target_host"])
            logging.info(f'Done action FoundServices. Services found: {found_services}')

            # Copy the known services in the current state. The current one is frozen
            extended_services = {k:v for k,v in current.known_services.items()}
            if len(found_services) > 0:
                if action.parameters["target_host"] not in extended_services.keys():
                    extended_services[action.parameters["target_host"]] = frozenset(found_services)
                else:
                    # The host is already there, extend its services in case new were added
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
        """
        Check if this action was detected by the global defender
        based on the probabilitiy distribution in the action configuration
        """
        if self._defender_placements:
            # There is a defender
            value = random.random() < action.transition.default_detection_p     
            logger.info(f'There is a defender and the detection is {value}')
            return value
        else: 
            # There is no defender
            logger.info(f'There is NO defender')
            return False 
    
    def reset(self)->Observation:
        """
        Function to reset the state of the game 
        and play a new episode
        """
        logger.info(f'------Game resetted. New starting ------')
        self._done = False
        self._step_counter = 0
        self.detected = False  
        self._current_state = self._create_starting_state()
        initial_reward = 0
        info = {}
        # An observation has inside ["state", "reward", "done", "info"]
        return Observation(self._current_state, initial_reward, self._done, info)
    
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
                logger.info(f'{action} sucessful')

                # Get the next state given the action
                next_state = self._execute_action(self._current_state, action)

                # Reard for making an action
                reward = -1     
            else: 
                # The action was not successful
                logger.info(f'{action} not sucessful')

                # State does not change
                next_state = self._current_state

                # Reward for taking an action
                reward = -1 

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

    # Test random data and start positio
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
        "controlled_hosts":{"213.47.23.195"},
        "known_services":{},
        "known_data":{}
    }
    random_start = True
    env = Network_Security_Environment(random_start=random_start, verbosity=0)
    
    # Read network setup from predefined CYST configuration
    env.process_cyst_config(scenarios.scenario_configuration.configuration_objects)

    # Do we have a defender? 
    defender = False

    # Initialize the game
    observation = env.initialize(win_conditons=goal, defender_positions=defender, attacker_start_position=attacker_start, max_steps=50, agent_seed=42)
    print(f'The complete observation is: {observation}')
    print(f'The state is: {observation.state}')
    print(f'Networks in the env: {env._networks}')
    print(f'\tContr hosts: {observation.state._controlled_hosts}')
    print(f'\tKnown nets: {observation.state._known_networks}')
    print(f'\tKnown host: {observation.state._known_hosts}')
    print(f'\tKnown serv: {observation.state._known_services}')
    print(f'\tKnown data: {observation.state._known_data}')

    print()
    print('Start testing rounds of all actions')

    for i in range(2):
        actions = env.get_valid_actions(observation.state)
        for action in actions:
            print(f'\t- Taking Valid action from this state: {action}')
            observation = env.step(action)
            print(f'\t\tContr hosts: {observation.state._controlled_hosts}')
            print(f'\t\tKnown nets: {observation.state._known_networks}')
            print(f'\t\tKnown host: {observation.state._known_hosts}')
            print(f'\t\tKnown serv: {observation.state._known_services}')
            print(f'\t\tKnown data: {observation.state._known_data}')

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

        logger.info('Creating the starting state')

        if self._random_start:
            # Random start
            logger.info('Start position of agent is random')
            logger.info(f'Choosing from {self.hosts_to_start}')
            controlled_hosts.add(str(choice(self.hosts_to_start)))
            logger.info(f'\t\tMaking agent start in {controlled_hosts}')
        else:
            # Not random start
            logger.info('Start position of agent is fixed in a host')
        
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

        # Be careful. This line must go alone. Because it should be possible
        # to have a random start position, but also to 'force' a controlled host
        # for the case of controlling a command and controll server to exfiltrate.
        controlled_hosts = self._attacker_start_position["controlled_hosts"]

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
            logger.info(f'\tAdded {str(node.id)} to the list of available nodes.')
            # Get all the IPs of this node and store them in our list of known IPs
            for interface in node.interfaces:
                # Store in _ips . This is candidate for deletion
                self._ips[str(interface.ip)] = node.id
                logger.info(f'\tAdded IP {str(interface.ip)} to the list of available ips.')

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
                logger.info(f'\tAdded network {str(interface.net)} to the list of available nets, with node {node.id}.')

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
                logger.info(f'\tAdded {str(interface.net)} to the list of available networks in the game.')

        def process_exploit_config(exploit):
            # Process an exploit
            logger.info(f'\t\tAdding exploit {exploit.id}')
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
        logger.info(f'Reading CYST conf')
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
                services.add(Service(service.type, "passive", service.version))
        return services

    def _get_networks_from_host(self, host_ip)->set:
        """
        Get all the networks that this IP is connected to
        """
        networks = set()
        try:
            node_id = self._ips[host_ip]
        except KeyError:
            print(f"Tried to get networks from an unknown IP '{host_ip}'!")
            return networks

        # Get all the interfaces of this node
        for interface in self._nodes[node_id].interfaces:
            if isinstance(interface, InterfaceConfig):
                networks.add(interface.net)
        return networks
    
    def _get_data_in_host(self, host_ip)->list:
        """
        Get all the data in this IP
        """
        data = set()
        try:
            node_id = self._ips[host_ip]
        except KeyError:
            print(f"Tried to get data from an unknown IP '{host_ip}'!")
            return data

        node = self._nodes[node_id]
        if isinstance(node, NodeConfig):
            for service in node.passive_services:
                try:
                    for datum in service.private_data:
                        data.add((datum.owner, datum.description))
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
            logger.info(f'Executing action {action}')
            # Is the network in the list of networks of the env. Give back the ips there
            new_ips = set()
            try:
                logger.info(f'All nets: {self._networks}')
                # For each node in our network
                for node_id in self._networks[action.parameters["target_network"]]:
                    logger.info(f'\tChecking node {node_id}')
                    # For each interface
                    for interface in self._nodes[node_id].interfaces:
                        logger.info(f'\t\tChecking interface {interface}')
                        # Get the ip
                        # Be sure the ip is still in our network, since routers have many ips!
                        if interface.ip in IPNetwork(action.parameters["target_network"]):
                            logger.info(f'\t\t\tThe IP {interface.ip} is in the scanned network {action.parameters["target_network"]}. Adding it.')
                            new_ips.add(str(interface.ip))
            except KeyError:
                # We dont have this network or
                # it is an invalid network (that we dont have)
                pass

            # Add the IPs in the network to the list of known hosts
            extended_hosts = current.known_hosts.union(new_ips)
            return GameState(current.controlled_hosts, extended_hosts, current.known_services, current.known_data, current.known_networks)

        elif action.transition.type == "FindServices":
            # Action FindServices
            # Get all the available services in the host that was attacked
            found_services =  self._get_services_from_host(action.parameters["target_host"])
            logger.info(f'Done action FoundServices. Services found: {found_services}')

            # Copy the known services in the current state to the future services to return. 
            # The current one is frozen and can not be extended
            extended_services = {k:v for k,v in current.known_services.items()}
            if action.parameters["target_host"] not in extended_services.keys():
                # The host is not in our list of services. Add it and add the service
                extended_services[action.parameters["target_host"]] = frozenset(found_services)
            else:
                # The host is already there, extend its services in case new were added
                extended_services[action.parameters["target_host"]] = frozenset(extended_services[action.parameters["target_host"]]).union(found_services)
            return GameState(current.controlled_hosts, current.known_hosts, extended_services, current.known_data, current.known_networks)

        elif action.transition.type == "FindData":
            # Find data in a host
            # Copy the current data in the variable to return. 
            # Original can not be extended
            extended_data = {k:v for k,v in current.known_data.items()}
            # Get data in the host
            new_data = self._get_data_in_host(action.parameters["target_host"])
            if action.parameters["target_host"] not in extended_data.keys():
                # The host was not in our current list. Add it and the datas
                extended_data[action.parameters["target_host"]] = new_data
            else:
                # Host was known to have some data, add the found data in case it is new
                extended_data[action.parameters["target_host"]].union(new_data)
            return GameState(current.controlled_hosts, current.known_hosts, current.known_services, extended_data, current.known_networks)
        
        elif action.transition.type == "ExecuteCodeInService":
            # Execute code and get control of new hosts
            # Copy the current data in a new var to return
            # Original is frozen and can not be extended

            # Probably this line can be extended_controlled_hosts = current.controlled_hosts
            # Not sure why the fanciness copy
            extended_controlled_hosts = set([x for x in current.controlled_hosts])
            extended_networks = current.known_networks
            if action.parameters["target_host"] not in current.controlled_hosts:
                # This host is not already controlled, add it
                extended_controlled_hosts.add(action.parameters["target_host"])
                # Get the networks that this host belongs to and make them known too
                new_networks = self._get_networks_from_host(action.parameters["target_host"])
                extended_networks = current.known_networks.union(new_networks)
            return GameState(extended_controlled_hosts, current.known_hosts, current.known_services, current.known_data, extended_networks)
        
        elif action.transition.type == "ExfiltrateData":
            # Exfiltrate data TO a target host. So copy the data there
            # After this, the data will be also INSIDE the target
            # Make a copy in the new var to return. 
            # Original is frozen
            extended_data = {k:v for k,v in current.known_data.items()}
            if action.parameters["target_host"] not in current.known_data.keys():
                # We didnt exfiltrate to this host, add it and the data
                extended_data[action.parameters["target_host"]] = {action.parameters["data"]}
            else:
                # We already exfiltrated to this host, copy the new data.
                extended_data[action.parameters["target_host"]].union(action.parameters["data"])
            return GameState(current.controlled_hosts, current.known_hosts, current.known_services, extended_data, current.known_networks)

        else:
            raise ValueError(f"Unknown Action type: '{action.transition.type}'")
    
    def is_goal(self, state:GameState)->bool:
        """
        Check if the goal was reached for the game
        """
        # For each part of the state of the game, check if the conditions are met

        # Networks
        if set(self._win_conditions["known_networks"]) <= set(state.known_networks):
            networks_goal = True

        # Known hosts
        if set(self._win_conditions["known_hosts"]) <= set(state.known_hosts):
            known_hosts_goal = True
        
        # Controlled hosts
        if set(self._win_conditions["controlled_hosts"]) <= set(state.controlled_hosts):
            controlled_hosts_goal = True

        # Known services
        # Be careful. Any bug in the following lines may make the goal true
        known_services_goal = True
        # Do we have any service to know in goal?
        if self._win_conditions["known_services"]:
            # For each host with a service agent should get
            for ip_service in self._win_conditions["known_services"].keys():
                # For each service in this host agent should get
                for service in self._win_conditions["known_services"][ip_service]:
                    # Does the agent know this service?
                    if service not in state.known_services[ip_service]:
                        known_services_goal = False
                        break

        # Known data
        # Be careful. Any bug in the following lines may make the goal true
        known_data_goal = True
        # Do we have any data to know in goal?
        if self._win_conditions["known_data"]:
            # For each host with data the agent should get
            for ip_data in self._win_conditions["known_data"].keys():
                # For each data in this host the agent should get
                try:
                    if set(self._win_conditions["known_data"][ip_data]) > set(state.known_data[ip_data]):
                        known_data_goal = False
                        break
                except KeyError:
                    # The ip is not known yet to the defender. So no.
                    known_data_goal = False
                    break



        return networks_goal and known_hosts_goal and controlled_hosts_goal and known_services_goal and known_data_goal
    
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
        logger.info(f'------ Game resetted. New starting ------')
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
            logger.info(f'Step taken: {self._step_counter}')
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
            # Be sure that if the action was detected the game ends with the
            # correct penalty, even if the action was successfully executed.
            # This means defender wins if both defender and attacker are successful
            # simuntaneously in the same step
            detected = self._is_detected(self._current_state, action)
            if detected:
                logger.info(f'Action detected')
                # Reward should be negative
                reward -= 50
                # Mark the environment as detected
                self.detected = True
                reason = {'end_reason':'detected'}
                # End the game
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
    observation = env.initialize(win_conditons=goal, defender_positions=defender, attacker_start_position=attacker_start, max_steps=500, agent_seed=42)
    print(f'The complete observation is: {observation}')
    print(f'The state is: {observation.state}')
    print(f'Networks in the env: {env._networks}')
    print(f'\tContr hosts: {observation.state._controlled_hosts}')
    print(f'\tKnown nets: {observation.state._known_networks}')
    print(f'\tKnown host: {observation.state._known_hosts}')
    print(f'\tKnown serv:')
    for ip_service in observation.state._known_services:
        print(f'\t\t{observation.state._known_services[ip_service]}:{ip_service}')
    print(f'\tKnown data: {observation.state._known_data}')

    print()
    print('Start testing rounds of all actions')

    num_iterations = 10
    for i in range(num_iterations):
        actions = env.get_valid_actions(observation.state)
        for action in actions:
            print(f'\t- Taking Valid action from this state: {action}')
            try:
                observation = env.step(action)
            except ValueError as e:
                print(f'Game ended. {e}')
                break
            print(f'\t\tContr hosts: {observation.state._controlled_hosts}')
            print(f'\t\tKnown nets: {observation.state._known_networks}')
            print(f'\t\tKnown host: {observation.state._known_hosts}')
            print(f'\t\tKnown serv:')
            for ip_service in observation.state._known_services:
                print(f'\t\t\t{ip_service}')
                for serv in observation.state._known_services[ip_service]:
                    print(f'\t\t\t\t{serv.name}')
            print(f'\t\tKnown data: {observation.state._known_data}')
            for ip_data in observation.state._known_data:
                if observation.state._known_data[ip_data]:
                    print(f'\t\t\t{ip_data}')
                    for data in observation.state._known_data[ip_data]:
                        print(f'\t\t\t\t{data}')
    print(f'The {num_iterations} iterations of test actions ended.')

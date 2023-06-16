"""
Tests related to the game components in the Network Security Game Environment
Author: Maria Rigaki - maria.rigaki@fel.cvut.cz
"""
import sys
from os import path
sys.path.append( path.dirname(path.dirname( path.abspath(__file__) ) ))
from env.game_components import ActionType, Action, IP, Data, Network, Service, GameState

class TestComponentsIP:
    """
    Tests related to the IP datclass
    """
    def test_ip_repr(self):
        """Test the object representation"""
        ip_1 = IP("192.168.1.15")
        assert repr(ip_1) == "192.168.1.15"

    def test_ip_equal(self):
        """Test that two IP objects with the same IP are equal"""
        ip_1 = IP("192.168.1.15")
        ip_2 = IP("192.168.1.15")
        assert ip_1 == ip_2

    def test_ip_not_equal(self):
        """Test that two IP objects with different IPs are not equal"""
        ip_1 = IP("192.168.1.15")
        ip_2 = IP("192.168.2.15")
        assert ip_1 != ip_2

    def test_ip_not_str(self):
        """Test that the IP object is not equal to a string"""
        ip_1 = IP("192.168.1.15")
        ip_2 = "192.168.2.15"
        assert ip_1 != ip_2

class TestServices:
    """
    Tests related to the Service dataclass
    """
    def test_service_creation(self):
        """
        Test that the service is created and all elements can be accessed
        """
        service = Service("rdp", "passive", "1.067", True)
        assert service.name == "rdp"
        assert service.type == "passive"
        assert service.version == "1.067"
        assert service.is_local

    def test_services_equal(self):
        """
        Test that two services with the same parameters are equal
        """
        service_1 = Service("rdp", "passive", "1.067", True)
        service_2 = Service("rdp", "passive", "1.067", True)
        assert service_1 == service_2
        assert service_1 is not service_2

    def test_services_not_equal(self):
        """
        Test that two services with different parameters are not equal
        """
        service_1 = Service("rdp", "passive", "1.067", True)
        service_2 = Service("sql", "passive", "5.0", True)
        assert service_1 != service_2

class TestNetwork:
    """
    Test cases for the Network dataclass
    """
    def test_net_creation(self):
        """
        Test that the network is created and all elements can be accessed
        """
        net = Network("125.36.21.3", 16)
        assert net.ip == "125.36.21.3"
        assert net.mask == 16

    def test_net_str(self):
        """
        Test the string representaion of the network
        """
        net = Network("125.36.21.3", 16)
        assert str(net) == "125.36.21.3/16"

    def test_net_repr(self):
        """
        Test the repr of the Network
        """
        net = Network("125.36.21.3", 16)
        assert repr(net) == "125.36.21.3/16"

    def test_net_equal(self):
        """
        Test that two network objects with the same paramters are equal
        """
        net_1 = Network("125.36.21.3", 16)
        net_2 = Network("125.36.21.3", 16)
        assert net_1 == net_2

    def test_net_not_equal(self):
        """
        Test that two network objects with different paramters are not equal
        """
        net_1 = Network("125.36.21.3", 16)
        net_2 = Network("192.168.1.3", 16)
        assert net_1 != net_2

class TestData:
    """
    Test cases for the Data class
    """
    def test_create_data(self):
        """
        Test that the data are created and all elements can be accessed 
        """
        data = Data("Ondra", "Password")
        assert data.owner == "Ondra"
        assert data.id == "Password"

    def test_data_equal(self):
        """
        Test that two data objects with the same parameters are equal
        """
        data = Data("Ondra", "Password")
        data2 = Data("Ondra", "Password")
        assert data == data2

    def test_data_not_equal(self):
        """
        Test that two data objects with different parameters are not equal
        """
        data = Data("Ondra", "Password")
        data2 = Data("User2", "WebData")
        assert data != data2

class TestAction:
    """
    Test cases for the Action class
    """
    def test_create_find_data(self):
        """
        Test the creation of the FindData action
        """
        action = Action(action_type=ActionType.FindData, params={"target_host":IP("192.168.12.12")})
        assert action.type == ActionType.FindData
        assert action.parameters["target_host"] == IP("192.168.12.12")

    def test_create_find_data_str(self):
        """
        Test the string representation of the FindData action
        """
        action = Action(action_type=ActionType.FindData, params={"target_host":IP("192.168.12.12")})
        assert str(action) == "Action <ActionType.FindData|{'target_host': 192.168.12.12}>"

    def test_create_find_data_repr(self):
        """
        Test the repr of the FindData action
        """
        action = Action(action_type=ActionType.FindData, params={"target_host":IP("192.168.12.12")})
        assert repr(action) == "Action <ActionType.FindData|{'target_host': 192.168.12.12}>"

    def test_action_find_services(self):
        """
        Test the creation of the FindServices action
        """
        action = Action(action_type=ActionType.FindServices,
                        params={"target_host":IP("192.168.12.12")})
        assert action.type == ActionType.FindServices
        assert action.parameters["target_host"] == IP("192.168.12.12")

    def test_action_scan_network(self):
        """
        Test the creation of the ScanNetwork action
        """
        action = Action(action_type=ActionType.ScanNetwork,
                        params={"target_network":Network("172.16.1.12", 24)})
        assert action.type == ActionType.ScanNetwork
        assert action.parameters["target_network"] == Network("172.16.1.12", 24)

    def test_action_exploit_services(self):
        """
        Test the creation of the ExploitService action
        """
        action = Action(action_type=ActionType.ExploitService,
                        params={"target_host":IP("172.16.1.12"),
                                "target_service":Service("ssh", "passive", "0.23", False)})
        assert action.type == ActionType.ExploitService
        assert action.parameters["target_host"] == IP("172.16.1.12")
        assert action.parameters["target_service"].name == "ssh"
        assert action.parameters["target_service"].version == "0.23"
        assert action.parameters["target_service"].type == "passive"

    def test_action_equal(self):
        """
        Test that two actions with the same parameters are equal
        """
        action = Action(action_type=ActionType.FindServices,
                        params={"target_host":IP("172.16.1.22")})
        action2 = Action(action_type=ActionType.FindServices,
                         params={"target_host":IP("172.16.1.22")})
        assert action == action2

    def test_action_not_equal_different_target(self):
        """
        Test that two actions with different parameters are not equal
        """
        action = Action(action_type=ActionType.FindServices,
                        params={"target_host":IP("172.16.1.22")})
        action2 = Action(action_type=ActionType.FindServices,
                         params={"target_host":IP("172.15.1.22")})
        assert action != action2

    def test_action_not_equal_different_action_type(self):
        """
        Test that two actions with different parameters are not equal
        """
        action = Action(action_type=ActionType.FindServices,
                        params={"target_host":IP("172.16.1.22")})
        action2 = Action(action_type=ActionType.FindData,
                         params={"target_host":IP("172.16.1.22")})
        assert action != action2

class TestGameState:
    """
    Test cases related to the GameState class
    """
    def test_create_game_state(self):
        """
        Test the correct creation of the GameState class
        """
        game_state = GameState(controlled_hosts={IP("192.168.1.1")},
                  known_hosts={IP("192.168.1.1"), IP("8.8.8.8")},
                  known_services=set(),
                  known_data={Data("User2", "PublicKey")},
                  known_networks={Network('192.168.1.0', 24)})

        assert isinstance(game_state.controlled_hosts, set)
        assert len(game_state.known_hosts) == 2
        assert IP("192.168.1.1") in game_state.known_hosts
        assert IP("192.168.1.1") in game_state.controlled_hosts
        assert Data("User2", "PublicKey") in game_state.known_data
        assert Network("192.168.1.0", 24) in game_state.known_networks

    def test_state_equal(self):
        """
        Test that two game states with the same parameters are equal
        """
        game_state = GameState(controlled_hosts={IP("192.168.1.1")},
                  known_hosts={IP("192.168.1.1"), IP("8.8.8.8")},
                  known_services=set(),
                  known_data={Data("User2", "PublicKey")},
                  known_networks={Network('192.168.1.0', 24)})
        game_state2 = GameState(controlled_hosts={IP("192.168.1.1")},
                  known_hosts={IP("192.168.1.1"), IP("8.8.8.8")},
                  known_services=set(),
                  known_data={Data("User2", "PublicKey")},
                  known_networks={Network('192.168.1.0', 24)})

        assert game_state == game_state2

    def test_state_not_equal_diff_control(self):
        """
        Test that two game states with diffrent parameters are not equal.
        Different controlled hosts.
        """
        game_state = GameState(controlled_hosts={IP("192.168.1.1")},
                  known_hosts={IP("192.168.1.1"), IP("8.8.8.8")},
                  known_services=set(),
                  known_data={Data("User2", "PublicKey")},
                  known_networks={Network('192.168.1.0', 24)})
        game_state2 = GameState(controlled_hosts={IP("172.16.1.1")},
                  known_hosts={IP("192.168.1.1"), IP("8.8.8.8")},
                  known_services=set(),
                  known_data={Data("User2", "PublicKey")},
                  known_networks={Network('192.168.1.0', 24)})

        assert game_state != game_state2

    def test_state_not_equal_diff_known(self):
        """
        Test that two game states with diffrent parameters are not equal
        Different known hosts.
        """
        game_state = GameState(controlled_hosts={IP("192.168.1.1")},
                  known_hosts={IP("192.168.1.1"), IP("8.8.8.8")},
                  known_services=set(),
                  known_data={Data("User2", "PublicKey")},
                  known_networks={Network('192.168.1.0', 24)})

        game_state2 = GameState(controlled_hosts={IP("192.168.1.1")},
                  known_hosts={IP("8.8.8.8")},
                  known_services=set(),
                  known_data={Data("User2", "PublicKey")},
                  known_networks={Network('192.168.1.0', 24)})

        assert game_state != game_state2

    def test_state_not_equal_diff_data(self):
        """
        Test that two game states with diffrent parameters are not equal.
        Different data.
        """
        game_state = GameState(controlled_hosts={IP("192.168.1.1")},
                  known_hosts={IP("192.168.1.1"), IP("8.8.8.8")},
                  known_services=set(),
                  known_data={Data("User2", "PublicKey")})
        game_state2 = GameState(controlled_hosts={IP("192.168.1.1")},
                  known_hosts={IP("192.168.1.1"), IP("8.8.8.8")},
                  known_services=set(),
                  known_data={Data("User", "PublicKey")})
        assert game_state != game_state2

    # def test_game_state_as_json(self):
    #     game_state = GameState(controlled_hosts={IP("192.168.1.1")},
    #               known_hosts={IP("192.168.1.1"), IP("8.8.8.8")},
    #               known_services=set(),
    #               known_data={Data("User2", "PublicKey")},
    #               known_networks={Network('192.168.1.0', 24)})
    #     game_json = game_state.as_json()
    #     assert Network('192.168.1.0', 24) in game_json["known_hosts"]
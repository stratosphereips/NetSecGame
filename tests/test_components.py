"""
Tests related to the game components in the Network Security Game Environment
Author: Maria Rigaki - maria.rigaki@fel.cvut.cz
"""
import json
from AIDojoCoordinator.game_components import ActionType, Action, IP, Data, Network, Service, GameState, AgentInfo

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

    def test_ip_is_private(self):
        ip_1 = IP("192.168.1.15")
        assert ip_1.is_private() is True
    
    def test_ip_is_not_private(self):
        ip_1 = IP("192.143.1.15")
        assert ip_1.is_private() is False

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

    def test_net_is_not_private(self):
        net_1 = Network("125.36.21.3", 16)
        assert net_1.is_private() is False
    
    def test_net_is_private(self):
        net_1 = Network("192.168.1.0", 16)
        assert net_1.is_private() is True

class TestData:
    """
    Test cases for the Data class
    """
    def test_create_data_minimal(self):
        """
        Test that the data object is created with ONLY required fields (using default for the rest)
        """
        data = Data(owner="Ondra", id="Password")
        assert data.owner == "Ondra"
        assert data.id == "Password"
        assert data.type == ""
        assert data.size == 0
    
    def test_create_data_all(self):
        """
        Test that the data object is created with ALL fields (using default for the rest)
        """
        data = Data(owner="Ondra", id="Password",size=42, type="txt")
        assert data.owner == "Ondra"
        assert data.id == "Password"
        assert data.type == "txt"
        assert data.size == 42

    def test_data_equal(self):
        """
        Test that two data objects with the same required parameters are equal
        """
        data = Data("Ondra", "Password")
        data2 = Data("Ondra", "Password")
        # test equality with all fields used
        data3 = Data(owner="Ondra", id="Password",size=42, type="txt")
        data4 = Data(owner="Ondra", id="Password", size=42, type="txt")
        assert data == data2
        assert data3 == data4

    def test_data_not_equal(self):
        """
        Test that two data objects with different required parameters are NOT equal
        """
        data = Data("Ondra", "Password")
        data2 = Data("ChuckNorris", "Password")
        data3 = Data(owner="Ondra", id="Password",size=42, type="txt")
        data4 = Data(owner="Ondra", id="DifferentPassword",size=41, type="rsa")
        assert data != data2
        assert data3 != data4
    
    def test_data_hash_equal(self):
        data = Data("Ondra", "Password")
        data2 = Data("Ondra", "Password")
        # test equality with all fields used
        data3 = Data(owner="Ondra", id="Password",size=42, type="txt")
        data4 = Data(owner="Ondra", id="Password",size=42, type="txt")
        assert hash(data) == hash(data2)
        assert hash(data3) == hash(data4)

    def test_data_hash_not_equal(self):
        data = Data("Ondra", "Password")
        data2 = Data("Ondra", "NewPassword")
        # test equality with all fields used
        data3 = Data(owner="Ondra", id="Password",size=42, type="txt")
        data4 = Data(owner="Ondra", id="Password",size=41, type="rsa")
        assert hash(data) != hash(data2)
        assert hash(data3) != hash(data4)

class TestAction:
    """
    Test cases for the Action class
    """
    def test_create_find_data(self):
        """
        Test the creation of the FindData action
        """
        action = Action(action_type=ActionType.FindData, parameters={"source_host":IP("192.168.12.12"),"target_host":IP("192.168.12.12")})
        assert action.type == ActionType.FindData
        assert action.parameters["target_host"] == IP("192.168.12.12")
        assert action.parameters["source_host"] == IP("192.168.12.12")

    def test_create_find_data_str(self):
        """
        Test the string representation of the FindData action
        """
        action = Action(action_type=ActionType.FindData, parameters={"source_host":IP("192.168.12.12"), "target_host":IP("192.168.12.12")})
        assert str(action) == "Action <ActionType.FindData|{'source_host': 192.168.12.12, 'target_host': 192.168.12.12}>"

    def test_create_find_data_repr(self):
        """
        Test the repr of the FindData action
        """
        action = Action(action_type=ActionType.FindData, parameters={"source_host":IP("192.168.12.12"), "target_host":IP("192.168.12.12")})
        assert repr(action) == "Action <ActionType.FindData|{'source_host': 192.168.12.12, 'target_host': 192.168.12.12}>"

    def test_action_find_services(self):
        """
        Test the creation of the FindServices action
        """
        action = Action(action_type=ActionType.FindServices,
                        parameters={"source_host":IP("192.168.12.11"), "target_host":IP("192.168.12.12")})
        assert action.type == ActionType.FindServices
        assert action.parameters["target_host"] == IP("192.168.12.12")
        assert action.parameters["source_host"] == IP("192.168.12.11")

    def test_action_scan_network(self):
        """
        Test the creation of the ScanNetwork action
        """
        action = Action(action_type=ActionType.ScanNetwork,
                        parameters={"source_host":IP("192.168.12.11"), "target_network":Network("172.16.1.12", 24)})
        assert action.type == ActionType.ScanNetwork
        assert action.parameters["target_network"] == Network("172.16.1.12", 24)
        assert action.parameters["source_host"] == IP("192.168.12.11")

    def test_action_exploit_services(self):
        """
        Test the creation of the ExploitService action
        """
        action = Action(action_type=ActionType.ExploitService,
                        parameters={"source_host":IP("192.168.12.11"),"target_host":IP("172.16.1.12"),
                                "target_service":Service("ssh", "passive", "0.23", False)})
        assert action.type == ActionType.ExploitService
        assert action.parameters["target_host"] == IP("172.16.1.12")
        assert action.parameters["target_service"].name == "ssh"
        assert action.parameters["target_service"].version == "0.23"
        assert action.parameters["target_service"].type == "passive"
        assert action.parameters["source_host"] == IP("192.168.12.11")

    def test_action_equal(self):
        """
        Test that two actions with the same parameters are equal
        """
        action = Action(action_type=ActionType.FindServices,
                        parameters={"target_host":IP("172.16.1.22"),"source_host":IP("192.168.12.11")})
        action2 = Action(action_type=ActionType.FindServices,
                         parameters={"target_host":IP("172.16.1.22"), "source_host":IP("192.168.12.11")})
        assert action == action2
    
    def test_action_equal_parameters_order(self):
        """
        Test that two actions with the same parameters are equal
        """
        action = Action(action_type=ActionType.ExploitService,
                    parameters={"target_host":IP("172.16.1.22"),"source_host":IP("192.168.12.11"),"target_service": Service("ssh", "passive", "0.23", False)})
        action2 = Action(action_type=ActionType.ExploitService,
                    parameters={"target_service": Service("ssh", "passive", "0.23", False), "target_host":IP("172.16.1.22"), "source_host":IP("192.168.12.11")})
        assert action == action2

    def test_action_not_equal_different_target(self):
        """
        Test that two actions with different parameters are not equal
        """
        action = Action(action_type=ActionType.FindServices,
                        parameters={"source_host":IP("192.168.12.11"), "target_host":IP("172.16.1.22")})
        action2 = Action(action_type=ActionType.FindServices,
                         parameters={"source_host":IP("192.168.12.11"), "target_host":IP("172.15.1.22")})
        assert action != action2

    def test_action_not_equal_different_source(self):
        """
        Test that two actions with different parameters are not equal
        """
        action = Action(action_type=ActionType.FindServices,
                        parameters={"source_host":IP("192.168.12.12"), "target_host":IP("172.16.1.22")})
        action2 = Action(action_type=ActionType.FindServices,
                         parameters={"source_host":IP("192.168.12.11"), "target_host":IP("172.16.1.22")})
        assert action != action2

    def test_action_not_equal_different_action_type(self):
        """
        Test that two actions with different parameters are not equal
        """
        action = Action(action_type=ActionType.FindServices,
                        parameters={"source_host":IP("192.168.12.11"),"target_host":IP("172.16.1.22")})
        action2 = Action(action_type=ActionType.FindData,
                         parameters={"source_host":IP("192.168.12.11"),"target_host":IP("172.16.1.22")})
        assert action != action2

    def test_action_hash(self):
        action = Action(
            action_type=ActionType.FindServices,
            parameters={"target_host":IP("172.16.1.22"),"source_host":IP("192.168.12.11")}
        )
        action2 = Action(
            action_type=ActionType.FindServices,
            parameters={"target_host":IP("172.16.1.22"), "source_host":IP("192.168.12.11")}
        )
        action3 = Action(
            action_type=ActionType.FindServices,
            parameters={"target_host":IP("172.16.13.48"), "source_host":IP("192.168.12.11")}
        )
        action4 = Action(
            action_type=ActionType.FindData,
            parameters={"target_host":IP("172.16.1.25"), "source_host":IP("192.168.12.11")}
        )
        assert hash(action) == hash(action2)
        assert hash(action) != hash(action3)
        assert hash(action2) != hash(action4)
    
    def test_action_set_member(self):
        action_set = set()
        action_set.add(Action(action_type=ActionType.FindServices,
                        parameters={"source_host":IP("192.168.12.11"),"target_host":IP("172.16.1.22")}))
        action_set.add(Action(action_type=ActionType.FindData,
                        parameters={"source_host":IP("192.168.12.11"), "target_host":IP("172.16.1.24")}))
        action_set.add(Action(action_type=ActionType.ExploitService,
                        parameters={"source_host":IP("192.168.12.11"), "target_host":IP("172.16.1.24"), "target_service": Service("ssh", "passive", "0.23", False)}))
        action_set.add(Action(action_type=ActionType.ScanNetwork,
                        parameters={"source_host":IP("192.168.12.11"), "target_network":Network("172.16.1.12", 24)}))
        action_set.add(Action(action_type=ActionType.ExfiltrateData, parameters={"target_host":IP("172.16.1.3"),
                         "source_host": IP("172.16.1.2"), "data":Data("User2", "PublicKey")}))
        
        assert Action(action_type=ActionType.FindServices, parameters={"source_host":IP("192.168.12.11"), "target_host":IP("172.16.1.22")}) in action_set
        assert Action(action_type=ActionType.FindData, parameters={"source_host":IP("192.168.12.11"), "target_host":IP("172.16.1.24")}) in action_set
        assert Action(action_type=ActionType.ExploitService, parameters={"source_host":IP("192.168.12.11"), "target_host":IP("172.16.1.24"), "target_service": Service("ssh", "passive", "0.23", False)})in action_set
        #reverse parameters order
        assert Action(action_type=ActionType.ExploitService, parameters={"target_service": Service("ssh", "passive", "0.23", False), "target_host":IP("172.16.1.24"), "source_host":IP("192.168.12.11")})in action_set
        assert Action(action_type=ActionType.ScanNetwork, parameters={"target_network":Network("172.16.1.12", 24), "source_host":IP("192.168.12.11")}) in action_set
        assert Action(action_type=ActionType.ExfiltrateData, parameters={"target_host":IP("172.16.1.3"), "source_host": IP("172.16.1.2"), "data":Data("User2", "PublicKey")}) in action_set  
        #reverse parameters orders
        assert Action(action_type=ActionType.ExfiltrateData, parameters={"source_host": IP("172.16.1.2"), "target_host":IP("172.16.1.3"), "data":Data("User2", "PublicKey")}) in action_set
    
    def test_action_to_json(self):
        # Scan Network
        action = Action(action_type=ActionType.ScanNetwork,
                        parameters={"target_network":Network("172.16.1.12", 24)})
        action_json = action.to_json()
        try:
            data = json.loads(action_json)
        except ValueError:
            data = None
        assert data is not None
        assert "ActionType.ScanNetwork" in data["action_type"]
        assert ("parameters", {"target_network": {"ip": "172.16.1.12", "mask":24}}) in data.items()
        
        # Find services
        action = Action(action_type=ActionType.FindServices,
                        parameters={"target_host":IP("172.16.1.22")})
        action_json = action.to_json()
        try:
            data = json.loads(action_json)
        except ValueError:
            data = None
        assert data is not None
        assert "ActionType.FindServices" in data["action_type"]
        assert ("parameters", {"target_host": {"ip": "172.16.1.22"}}) in data.items()

        # Find Data
        action = Action(action_type=ActionType.FindData,
                        parameters={"target_host":IP("172.16.1.22")})
        action_json = action.to_json()
        try:
            data = json.loads(action_json)
        except ValueError:
            data = None
        assert data is not None
        assert "ActionType.FindData" in data["action_type"]
        assert ("parameters", {"target_host": {"ip": "172.16.1.22"}}) in data.items()       

        # Exploit Service
        action = Action(action_type=ActionType.ExploitService,
                        parameters={"target_host":IP("172.16.1.24"), "target_service": Service("ssh", "passive", "0.23", False)})
        action_json = action.to_json()
        try:
            data = json.loads(action_json)
        except ValueError:
            data = None
        assert data is not None
        assert "ActionType.ExploitService" in data["action_type"]
        assert ("parameters", {"target_host": {"ip": "172.16.1.24"},
                    "target_service":{"name":"ssh", "type":"passive", "version":"0.23", "is_local":False}}) in data.items()

        # Exfiltrate Data
        action = Action(action_type=ActionType.ExfiltrateData, parameters={"target_host":IP("172.16.1.3"),
                         "source_host": IP("172.16.1.2"), "data":Data("User2", "PublicKey", size=42, type="pub")})
        action_json = action.to_json()
        try:
            data = json.loads(action_json)
        except ValueError:
            data = None
        assert data is not None
        assert "ActionType.ExfiltrateData" in data["action_type"]
        assert ("parameters", {"target_host": {"ip": "172.16.1.3"},
                    "source_host" : {"ip": "172.16.1.2"},
                    "data":{"owner":"User2", "id":"PublicKey", "size":42 ,"type":"pub", "content":""}}) in data.items()
    
    def test_action_scan_network_serialization(self):
        action = Action(action_type=ActionType.ScanNetwork,
                        parameters={"target_network":Network("172.16.1.12", 24),"source_host": IP("172.16.1.2") })
        action_json = action.to_json()
        new_action = Action.from_json(action_json)
        assert action == new_action
    
    def test_action_find_services_serialization(self):
        action = Action(action_type=ActionType.FindServices,
                        parameters={"target_host":IP("172.16.1.22"), "source_host": IP("172.16.1.2")})
        action_json = action.to_json()
        new_action = Action.from_json(action_json)
        assert action == new_action

    def test_action_find_data_serialization(self):
        action = Action(action_type=ActionType.FindData,
                        parameters={"target_host":IP("172.16.1.22"), "source_host": IP("172.16.1.2")})
        action_json = action.to_json()
        new_action = Action.from_json(action_json)
        assert action == new_action

    def test_action_exploit_service_serialization(self):
        action = Action(action_type=ActionType.ExploitService,
                        parameters={"source_host": IP("172.16.1.2"),
                                "target_host":IP("172.16.1.24"),
                                "target_service": Service("ssh", "passive", "0.23", False)})
        action_json = action.to_json()
        new_action = Action.from_json(action_json)
        assert action == new_action
    
    def test_action_exfiltrate_serialization(self):
        action = Action(action_type=ActionType.ExfiltrateData, parameters={"target_host":IP("172.16.1.3"),
                         "source_host": IP("172.16.1.2"), "data":Data("User2", "PublicKey")})
        action_json = action.to_json()
        new_action = Action.from_json(action_json)
        assert action == new_action
    
    def test_action_exfiltrate_join_game(self):
        action = Action(
                action_type=ActionType.JoinGame,
                parameters={
                    "agent_info": AgentInfo(name="TestingAgent", role="attacker"),
                    }
            )
        action_json = action.to_json()
        new_action = Action.from_json(action_json)
        assert action == new_action
    
    def test_action_exfiltrate_reset_game(self):
        action = Action(
                action_type=ActionType.ResetGame,
                parameters={}
            )
        action_json = action.to_json()
        new_action = Action.from_json(action_json)
        assert action == new_action
    
    def test_action_exfiltrate_quit_game(self):
        action = Action(
                action_type=ActionType.QuitGame,
                parameters={}
            )
        action_json = action.to_json()
        new_action = Action.from_json(action_json)
        assert action == new_action
    
    def test_action_to_dict_scan_network(self):
        action = Action(
            action_type=ActionType.ScanNetwork,
            parameters={
                "target_network":Network("172.16.1.12", 24),
                "source_host": IP("172.16.1.2")
                }
        )
        action_dict = action.as_dict
        new_action = Action.from_dict(action_dict)
        assert action == new_action
        assert action_dict["action_type"] == str(action.type)
        assert action_dict["parameters"]["target_network"] == {'ip': '172.16.1.12', 'mask': 24}
        assert action_dict["parameters"]["source_host"] == {'ip': '172.16.1.2'}

    def test_action_to_dict_find_services(self):
        action = Action(
            action_type=ActionType.FindServices,
            parameters={
                "target_host":IP("172.16.1.22"),
                "source_host": IP("172.16.1.2")
                }
        )
        action_dict = action.as_dict
        new_action = Action.from_dict(action_dict)
        assert action == new_action
        assert action_dict["action_type"] == str(action.type)
        assert action_dict["parameters"]["target_host"] == {'ip': '172.16.1.22'}
        assert action_dict["parameters"]["source_host"] == {'ip': '172.16.1.2'}
    
    def test_action_to_dict_find_data(self):
        action = Action(
            action_type=ActionType.FindData,
            parameters={
                "target_host":IP("172.16.1.22"),
                "source_host": IP("172.16.1.2")
            }
        )
        action_dict = action.as_dict
        new_action = Action.from_dict(action_dict)
        assert action == new_action
        assert action_dict["action_type"] == str(action.type)
        assert action_dict["parameters"]["target_host"] == {'ip': '172.16.1.22'}
        assert action_dict["parameters"]["source_host"] == {'ip': '172.16.1.2'}
    
    def test_action_to_dict_exploit_service(self):
        action = Action(
            action_type=ActionType.ExploitService,
            parameters={
                "source_host": IP("172.16.1.2"),
                "target_host":IP("172.16.1.24"),
                "target_service": Service("ssh", "passive", "0.23", False)
            }
        )
        action_dict = action.as_dict
        new_action = Action.from_dict(action_dict)
        assert action == new_action
        assert action_dict["action_type"] == str(action.type)
        assert action_dict["parameters"]["target_host"] == {'ip': '172.16.1.24'}
        assert action_dict["parameters"]["source_host"] == {'ip': '172.16.1.2'}
        assert action_dict["parameters"]["target_service"]["name"] == "ssh"
        assert action_dict["parameters"]["target_service"]["type"] == "passive"
        assert action_dict["parameters"]["target_service"]["version"] == "0.23"
        assert action_dict["parameters"]["target_service"]["is_local"] is False
    
    def test_action_to_dict_exfiltrate_data(self):
        action = Action(
            action_type=ActionType.ExfiltrateData,
            parameters={
                "target_host":IP("172.16.1.3"),
                "source_host": IP("172.16.1.2"),
                "data":Data("User2", "PublicKey")
            }
        )
        action_dict = action.as_dict
        new_action = Action.from_dict(action_dict)
        assert action == new_action
        assert action_dict["action_type"] == str(action.type)
        assert action_dict["parameters"]["target_host"] == {'ip': '172.16.1.3'}
        assert action_dict["parameters"]["source_host"] == {'ip': '172.16.1.2'}
        assert action_dict["parameters"]["data"]["owner"] == "User2"
        assert action_dict["parameters"]["data"]["id"] == "PublicKey"

    def test_action_to_dict_join_game(self):
            action = Action(
                action_type=ActionType.JoinGame,
                parameters={
                    "agent_info": AgentInfo(name="TestingAgent", role="attacker"),
                    "source_host": IP("172.16.1.2")
                    }
            )
            action_dict = action.as_dict
            new_action = Action.from_dict(action_dict)
            assert action == new_action
            assert action_dict["action_type"] == str(action.type)
            assert action_dict["parameters"]["agent_info"]["name"] == "TestingAgent"
            assert action_dict["parameters"]["agent_info"]["role"] == "attacker"
    
    def test_action_to_dict_reset_game(self):
            action = Action(
                action_type=ActionType.ResetGame,
                parameters={}
            )
            action_dict = action.as_dict
            new_action = Action.from_dict(action_dict)
            assert action == new_action
            assert action_dict["action_type"] == str(action.type)
            assert len(action_dict["parameters"]) == 0
    
    def test_action_to_dict_quit_game(self):
            action = Action(
                action_type=ActionType.QuitGame,
                parameters={}
            )
            action_dict = action.as_dict
            new_action = Action.from_dict(action_dict)
            assert action == new_action
            assert action_dict["action_type"] == str(action.type)
            assert len(action_dict["parameters"]) == 0

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


    def test_game_state_as_json(self):
        game_state = GameState(known_networks={Network("1.1.1.1", 24),Network("1.1.1.2", 24)},
                known_hosts={IP("192.168.1.2"), IP("192.168.1.3")}, controlled_hosts={IP("192.168.1.2")},
                known_services={IP("192.168.1.3"):{Service("service1", "public", "1.01", True)}},
                known_data={IP("192.168.1.3"):{Data("ChuckNorris", "data1"), Data("ChuckNorris", "data2")},
                            IP("192.168.1.2"):{Data("McGiver", "data2", 42, "txt")}})
        game_json = game_state.as_json()
        print(game_json)
        try:
            data = json.loads(game_json)
        except ValueError:
            data = None
        assert data is not None
        assert {"ip": "1.1.1.1", "mask": 24} in data["known_networks"]
        assert {"ip": "192.168.1.3"} in data["known_hosts"]
        assert {"ip": "192.168.1.2"} in data["controlled_hosts"]
        assert ("192.168.1.3", [{"name": "service1", "type": "public", "version": "1.01", "is_local": True}]) in data["known_services"].items()
        assert {"owner": "ChuckNorris", "id": "data1", "size":0, "type":"", "content":""} in  data["known_data"]["192.168.1.3"]
        assert {"owner": "ChuckNorris", "id": "data2", "size":0, "type":"", "content":""} in  data["known_data"]["192.168.1.3"]
        assert {"owner": "McGiver", "id": "data2", "size":42, "type":"txt", "content":""} in  data["known_data"]["192.168.1.2"]
    
    def test_game_state_json_deserialized(self):
        game_state = GameState(known_networks={Network("1.1.1.1", 24),Network("1.1.1.2", 24)},
                known_hosts={IP("192.168.1.2"), IP("192.168.1.3")}, controlled_hosts={IP("192.168.1.2")},
                known_services={IP("192.168.1.3"):{Service("service1", "public", "1.01", True)}},
                known_data={IP("192.168.1.3"):{Data("ChuckNorris", "data1"), Data("ChuckNorris", "data2")},
                            IP("192.168.1.2"):{Data("McGiver", "data2")}})
        state_json = game_state.as_json()
        deserialized_state = GameState.from_json(state_json)
        assert game_state is not deserialized_state
        assert game_state == deserialized_state

    def test_game_state_as_dict(self):
        game_state = GameState(known_networks={Network("1.1.1.1", 24),Network("1.1.1.2", 24)},
                known_hosts={IP("192.168.1.2"), IP("192.168.1.3")}, controlled_hosts={IP("192.168.1.2")},
                known_services={IP("192.168.1.3"):{Service("service1", "public", "1.01", True)}},
                known_data={IP("192.168.1.3"):{Data("ChuckNorris", "data1"), Data("ChuckNorris", "data2")},
                            IP("192.168.1.2"):{Data("McGiver", "data2")}})
        game_dict = game_state.as_dict
        assert game_dict is not None
        assert {"ip": "1.1.1.1", "mask": 24} in game_dict["known_networks"]
        assert {"ip": "192.168.1.3"} in game_dict["known_hosts"]
        assert {"ip": "192.168.1.2"} in game_dict["controlled_hosts"]
        assert ("192.168.1.3", [{"name": "service1", "type": "public", "version": "1.01", "is_local": True}]) in game_dict["known_services"].items()
        assert {"owner": "ChuckNorris", "id": "data1", "size":0, "type":"", "content":""} in  game_dict["known_data"]["192.168.1.3"]
        assert {"owner": "ChuckNorris", "id": "data2", "size":0, "type":"", "content":""} in  game_dict["known_data"]["192.168.1.3"]
    
    def test_game_state_from_dict(self):
        game_state = GameState(known_networks={Network("1.1.1.1", 24),Network("1.1.1.2", 24)},
                known_hosts={IP("192.168.1.2"), IP("192.168.1.3")}, controlled_hosts={IP("192.168.1.2")},
                known_services={IP("192.168.1.3"):{Service("service1", "public", "1.01", True)}},
                known_data={IP("192.168.1.3"):{Data("ChuckNorris", "data1"), Data("ChuckNorris", "data2")},
                            IP("192.168.1.2"):{Data("McGiver", "data2")}})
        game_dict = game_state.as_dict
        deserialized_state = GameState.from_dict(game_dict)
        assert game_state is not deserialized_state
        assert game_state == deserialized_state
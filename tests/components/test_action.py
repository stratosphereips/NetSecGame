# Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
#           Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import json
import pytest
from netsecgame.game_components import Action, ActionType, IP, Network, Data, Service, AgentInfo

class TestComponentActionType:
    """
    Test cases for the ActionType enum
    """
    def test_action_type_str(self):
        """
        Test that the string representation of the ActionType enum is correct
        """
        assert str(ActionType.FindData) == "ActionType.FindData"
        assert str(ActionType.FindServices) == "ActionType.FindServices"
        assert str(ActionType.ScanNetwork) == "ActionType.ScanNetwork"
        assert str(ActionType.ExploitService) == "ActionType.ExploitService"
        assert str(ActionType.ExfiltrateData) == "ActionType.ExfiltrateData"
        assert str(ActionType.JoinGame) == "ActionType.JoinGame"
        assert str(ActionType.ResetGame) == "ActionType.ResetGame"
        assert str(ActionType.QuitGame) == "ActionType.QuitGame"
    
    def test_action_type_hash(self):
        """
        Test that the hash of the ActionType enum is correct
        """
        assert hash(ActionType.FindData) == hash("FindData")
        assert hash(ActionType.FindServices) == hash("FindServices")
        assert hash(ActionType.ScanNetwork) == hash("ScanNetwork")
        assert hash(ActionType.ExploitService) == hash("ExploitService")
        assert hash(ActionType.ExfiltrateData) == hash("ExfiltrateData")
        assert hash(ActionType.JoinGame) == hash("JoinGame")
        assert hash(ActionType.ResetGame) == hash("ResetGame")
        assert hash(ActionType.QuitGame) == hash("QuitGame")

class TestComponentAction:
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
            action = Action(
                action_type=ActionType.ResetGame,
                parameters={"request_trajectory": True, "randomize_topology": False}
            )
            action_dict = action.as_dict
            new_action = Action.from_dict(action_dict)
            assert action == new_action
            assert action_dict["action_type"] == str(action.type)
            assert len(action_dict["parameters"]) == 2
            assert action_dict["parameters"]["request_trajectory"] is True
            assert action_dict["parameters"]["randomize_topology"] is False

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

    def test_action_to_dict_block_ip(self):
            action = Action(
                action_type=ActionType.BlockIP,
                parameters={
                    "target_host": IP("192.168.1.0"),
                    "source_host": IP("192.168.1.1"),
                    "blocked_ip": IP("1.1.1.1")
                }
            )
            action_dict = action.as_dict
            new_action = Action.from_dict(action_dict)
            assert action == new_action
            assert action_dict["action_type"] == str(action.type)
            assert action_dict["parameters"]["target_host"] == {'ip': '192.168.1.0'}
            assert action_dict["parameters"]["source_host"] == {'ip': '192.168.1.1'}
            assert action_dict["parameters"]["blocked_ip"] == {'ip': '1.1.1.1'}

    def test_action_type_eq_unsupported(self):
        """Test ActionType equality with unsupported type"""
        assert (ActionType.FindData == 123) is False

    def test_action_type_from_string_invalid(self):
        """Test ActionType.from_string with invalid string"""
        with pytest.raises(ValueError):
            ActionType.from_string("InvalidAction")

    def test_action_eq_unsupported(self):
        """Test Action equality with unsupported type"""
        action = Action(action_type=ActionType.FindData)
        assert (action == "some_string") is False

    def test_action_from_dict_invalid_parameter(self):
        """Test Action.from_dict with invalid parameter key"""
        data = {
            "action_type": "ActionType.FindData",
            "parameters": {"unknown_param": "value"}
        }
        with pytest.raises(ValueError):
            Action.from_dict(data)

    def test_action_to_dict_bool_parameter(self):
        """Test handling of boolean parameters in as_dict"""
        action = Action(
            action_type=ActionType.ResetGame,
            parameters={"request_trajectory": True}
        )
        d = action.as_dict
        assert d["parameters"]["request_trajectory"] is True

    def test_action_to_dict_str_parameter(self):
        """Test handling of string parameters in as_dict"""
        # Inject a parameter that is just a string (not a dataclass)
        # We need a new ActionType or reuse one that accepts arbitrary params?
        # The existing code mainly expects specific params.
        # But we can force it for testing as_dict logic.
        action = Action(ActionType.FindData, parameters={"simple_param": "simple_value"})
        d = action.as_dict
        assert d["parameters"]["simple_param"] == "simple_value"
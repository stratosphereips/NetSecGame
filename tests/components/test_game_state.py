# Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
#           Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import json
from AIDojoCoordinator.game_components import GameState, IP, Network, Data, Service

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
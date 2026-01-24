import pytest
from netsecgame.game_components import GameStatus, AgentStatus, Observation, GameState, ProtocolConfig, AgentRole
import json

class TestGameStatus:
    def test_from_string_valid(self):
        """Test valid from_string conversions"""
        assert GameStatus.from_string("GameStatus.OK") == GameStatus.OK
        assert GameStatus.from_string("GameStatus.CREATED") == GameStatus.CREATED
        assert GameStatus.from_string("GameStatus.RESET_DONE") == GameStatus.RESET_DONE
        assert GameStatus.from_string("GameStatus.BAD_REQUEST") == GameStatus.BAD_REQUEST
        assert GameStatus.from_string("GameStatus.FORBIDDEN") == GameStatus.FORBIDDEN

    def test_from_string_invalid(self):
        """Test invalid from_string conversion"""
        with pytest.raises(ValueError):
            GameStatus.from_string("GameStatus.INVALID")

    def test_repr(self):
        """Test string representation"""
        assert str(GameStatus.OK) == "GameStatus.OK"
        assert repr(GameStatus.OK) == "GameStatus.OK"

class TestAgentStatus:
    def test_to_string(self):
        """Test to_string method"""
        assert AgentStatus.Playing.to_string() == "Playing"
        assert AgentStatus.Success.to_string() == "Success"

    def test_eq_string(self):
        """Test equality with string"""
        assert AgentStatus.Playing == "Playing"
        assert AgentStatus.Playing == "AgentStatus.Playing"
        assert (AgentStatus.Playing == "Other") is False

    def test_eq_self(self):
        """Test equality with self"""
        assert AgentStatus.Playing == AgentStatus.Playing
        assert (AgentStatus.Playing == AgentStatus.Success) is False

    def test_eq_other(self):
        """Test equality with other types"""
        assert (AgentStatus.Playing == 123) is False

    def test_hash(self):
        """Test hash consistency"""
        assert hash(AgentStatus.Playing) == hash(AgentStatus.Playing.value)

    def test_from_string(self):
        """Test from_string method"""
        assert AgentStatus.from_string("AgentStatus.Playing") == AgentStatus.Playing
        assert AgentStatus.from_string("Playing") == AgentStatus.Playing
        
        with pytest.raises(ValueError):
            AgentStatus.from_string("Invalid")

class TestObservation:
    def test_creation(self):
        """Test creation of Observation named tuple"""
        state = GameState()
        obs = Observation(state=state, reward=1.0, end=False, info={})
        
        assert obs.state == state
        assert obs.reward == 1.0
        assert obs.end is False
        assert obs.info == {}

class TestProtocolConfig:
    def test_constants(self):
        """Test protocol constants"""
        conf = ProtocolConfig()
        assert conf.END_OF_MESSAGE == b"EOF"

class TestAgentRole:
    def test_values(self):
        """Test enum values"""
        assert AgentRole.Attacker.value == "Attacker"
        assert AgentRole.Defender.value == "Defender"
        assert AgentRole.Benign.value == "Benign"

    def test_to_string(self):
        """Test to_string method"""
        assert AgentRole.Attacker.to_string() == "Attacker"
        assert AgentRole.Defender.to_string() == "Defender"

    def test_from_string(self):
        """Test from_string method"""
        assert AgentRole.from_string("Attacker") == AgentRole.Attacker
        assert AgentRole.from_string("attacker") == AgentRole.Attacker
        assert AgentRole.from_string("AgentRole.Attacker") == AgentRole.Attacker
        
        with pytest.raises(ValueError):
            AgentRole.from_string("InvalidRole")

    def test_equality(self):
        """Test equality comparison"""
        # Compare with Enum
        assert AgentRole.Attacker == AgentRole.Attacker
        assert AgentRole.Attacker != AgentRole.Defender
        
        # Compare with String
        assert AgentRole.Attacker == "Attacker"
        assert AgentRole.Attacker == "attacker"  # Case insensitive
        assert AgentRole.Attacker != "Defender"

    def test_hashability(self):
        """Test usage as dictionary key"""
        d = {AgentRole.Attacker: 1, AgentRole.Defender: 2}
        assert d[AgentRole.Attacker] == 1
        assert d["Attacker"] == 1  # Matches string equivalent
        assert d[AgentRole.Defender] == 2

    def test_json_serialization(self):
        """Test native JSON serialization"""
        data = {"role": AgentRole.Attacker}
        json_str = json.dumps(data)
        assert json_str == '{"role": "Attacker"}'
        
        # Round trip
        decoded = json.loads(json_str)
        assert decoded["role"] == "Attacker"

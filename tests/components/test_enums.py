import pytest
from netsecgame.game_components import GameStatus, AgentStatus, Observation, GameState, ProtocolConfig

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
        assert conf.BUFFER_SIZE == 8192

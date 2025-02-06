from AIDojoCoordinator.game_components import ActionType, Action
from AIDojoCoordinator.global_defender import GlobalDefender
import pytest
from unittest.mock import patch

@pytest.fixture
def defender():
    return GlobalDefender()

@pytest.fixture
def episode_actions():
    """Mock episode actions list."""
    return [
        Action(ActionType.ScanNetwork, {}).as_dict,
        Action(ActionType.FindServices, {}).as_dict,
        Action(ActionType.ScanNetwork, {}).as_dict,
        Action(ActionType.FindServices, {}).as_dict,
    ]

def test_short_episode_does_not_detect(defender, episode_actions):
    """Test when the episode action list is too short to make a decision."""
    action = Action(ActionType.ScanNetwork, {})
    assert not defender.stochastic_with_threshold(action, episode_actions[:2], tw_size=5)

def test_below_threshold_does_not_trigger_detection(defender, episode_actions):
    """Test when action thresholds are NOT exceeded (should return False)."""
    action = Action(ActionType.ScanNetwork, {})
    assert not defender.stochastic_with_threshold(action, episode_actions, tw_size=5)

def test_exceeding_threshold_triggers_stochastic(defender, episode_actions):
    """Test when thresholds are exceeded and stochastic is triggered."""
    action = Action(ActionType.ScanNetwork, {})
    episode_actions += [action.as_dict] * 3  # Exceed threshold
    
    with patch.object(defender, "stochastic", return_value=True) as mock_stochastic:
        result = defender.stochastic_with_threshold(action, episode_actions, tw_size=5)
        mock_stochastic.assert_called_once_with("ScanNetwork")  # Ensure stochastic was called
        assert result  # Expecting True since stochastic is triggered

def test_repeated_episode_action_threshold(defender, episode_actions):
    """Test when an action exceeds the episode repeated action threshold."""
    action = Action(ActionType.FindData, {})
    episode_actions += [action.as_dict] * 3    # Exceed repeat threshold
    
    with patch.object(defender, "stochastic", return_value=True) as mock_stochastic:
        result = defender.stochastic_with_threshold(action, episode_actions, tw_size=5)
        mock_stochastic.assert_called_once_with(ActionType.FindData)  # Ensure stochastic was called
        assert result  # Expecting True since stochastic is triggered

def test_other_actions_never_detected(defender, episode_actions):
    """Test that actions not in any threshold lists always return False."""
    action = Action(ActionType.JoinGame, {})
    assert not defender.stochastic_with_threshold(action, episode_actions, tw_size=5)

def test_mock_stochastic_probabilities(defender, episode_actions):
    """Test stochastic function is only called when thresholds are crossed."""
    action = Action(ActionType.ScanNetwork, {})
    episode_actions += [{"action_type": str(ActionType.ScanNetwork)}] * 3  # Exceed threshold
    
    with patch("random.random", return_value=0.01):  # Force detection probability
        result = defender.stochastic_with_threshold(action, episode_actions, tw_size=5)
        assert result  # Should be True since we forced a low probability value
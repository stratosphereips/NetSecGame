from uuid import UUID
from netsecgame.game.worlds.NetSecGame import NetSecGame
from netsecgame.game_components import AccessLevel

def test_users_population_from_config():
    # Load game with the standard testing task config
    game = NetSecGame(game_host="localhost", game_port=9999, task_config="tests/netsecenv-task-for-testing.yaml", seed=42)
    
    # Manually load the configuration and initialize to trigger _process_cyst_config
    game.config_manager._load_local_configuration()
    game._cyst_objects = game.config_manager.get_cyst_objects()
    game._use_dynamic_addresses = game.config_manager.get_use_dynamic_addresses()
    game._initialize()
    
    # Assert self._users is populated
    assert len(game._users) > 0, "self._users should not be empty"

    # Verify that expected nodes are populated in game._users
    expected_hosts = ["smb_server", "db_server", "client_1"]
    for host in expected_hosts:
        assert host in game._users, f"Host '{host}' should have users populated"
        users = game._users[host]
        assert len(users) > 0, f"Host '{host}' should have users populated"

    # Specific assertions for smb_server
    if "smb_server" in game._users:
        users = game._users["smb_server"]
        usernames = {u.username for u in users}
        assert "User1" in usernames
        assert "Administrator" in usernames
        
        # Verify IDs are indeed UUID instances
        for u in users:
            assert isinstance(u.id, UUID)
        
        # Get User1 and check properties
        user1 = next(u for u in users if u.username == "User1")
        assert user1.access_level == AccessLevel.LIMITED
        
        # Administrator should have ELEVATED access level
        admin = next(u for u in users if u.username == "Administrator")
        assert admin.access_level == AccessLevel.ELEVATED
        
        # Check authentication tokens for User1
        token_ids = {t.id for t in user1.authentication_tokens}
        # It should contain the provider name reference or token type name
        assert "windows login" in token_ids or "PASSWORD" in token_ids

    # Specific assertions for db_server
    if "db_server" in game._users:
        users = game._users["db_server"]
        usernames = {u.username for u in users}
        assert "User1" in usernames
        assert "root" in usernames
        
        # root should have ELEVATED access level
        root_user = next(u for u in users if u.username == "root")
        assert root_user.access_level == AccessLevel.ELEVATED
        
        # Check authentication tokens for root user
        root_token_ids = {t.id for t in root_user.authentication_tokens}
        assert "openssh_login_db_server" in root_token_ids or "PASSWORD" in root_token_ids


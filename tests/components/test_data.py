# Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
#           Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
from AIDojoCoordinator.game_components import Data

class TestComponentData:
    """
    Test cases for the Data class
    """
    def test_create_data_minimal(self):
        """
        Test that the data object is created with ONLY required fields (using default for the rest)
        """
        data = Data(owner="User", id="Password")
        assert data.owner == "User"
        assert data.id == "Password"
        assert data.type == ""
        assert data.size == 0
    
    def test_create_data_all(self):
        """
        Test that the data object is created with ALL fields (using default for the rest)
        """
        data = Data(owner="User", id="Password",size=42, type="txt")
        assert data.owner == "User"
        assert data.id == "Password"
        assert data.type == "txt"
        assert data.size == 42

    def test_data_equal(self):
        """
        Test that two data objects with the same required parameters are equal
        """
        data = Data("User", "Password")
        data2 = Data("User", "Password")
        # test equality with all fields used
        data3 = Data(owner="User", id="Password",size=42, type="txt")
        data4 = Data(owner="User", id="Password", size=42, type="txt")
        assert data == data2
        assert data3 == data4

    def test_data_not_equal(self):
        """
        Test that two data objects with different required parameters are NOT equal
        """
        data = Data("User", "Password")
        data2 = Data("ChuckNorris", "Password")
        data3 = Data(owner="User", id="Password",size=42, type="txt")
        data4 = Data(owner="User", id="DifferentPassword",size=41, type="rsa")
        assert data != data2
        assert data3 != data4
    
    def test_data_hash_equal(self):
        data = Data("User", "Password")
        data2 = Data("User", "Password")
        # test equality with all fields used
        data3 = Data(owner="User", id="Password",size=42, type="txt")
        data4 = Data(owner="User", id="Password",size=42, type="txt")
        assert hash(data) == hash(data2)
        assert hash(data3) == hash(data4)

    def test_data_hash_not_equal(self):
        data = Data("User", "Password")
        data2 = Data("User", "NewPassword")
        # test equality with all fields used
        data3 = Data(owner="User", id="Password",size=42, type="txt")
        data4 = Data(owner="User", id="Password",size=41, type="rsa")
        assert hash(data) != hash(data2)
        assert hash(data3) != hash(data4)

    def test_data_from_dict(self):
        d = {"owner": "Alice", "id": "Secret", "size": 10, "type": "txt", "content": "abc"}
        data = Data.from_dict(d)
        assert isinstance(data, Data)
        assert data.owner == "Alice"
        assert data.id == "Secret"
        assert data.size == 10
        assert data.type == "txt"
        assert data.content == "abc"
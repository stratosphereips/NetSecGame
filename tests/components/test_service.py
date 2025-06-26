# Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
#           Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
from AIDojoCoordinator.game_components import Service

class TestComponentService:
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
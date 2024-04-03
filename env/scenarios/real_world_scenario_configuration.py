# This file defines the real world scenario, with only the local host hosts and any external host controlled
import cyst.api.configuration as cyst_cfg

# Get the IP address of the computer
nodes_ip = '172.28.0.1'

# Create a node config for the host
client_1 = cyst_cfg.NodeConfig(
        active_services=[
            cyst_cfg.ActiveServiceConfig(
                type="scripted_actor",
                name="attacker",
                owner="attacker",
                access_level=cyst_cfg.AccessLevel.LIMITED,
                id="attacker_service"
            )
        ],
        passive_services=[
                cyst_cfg.PassiveServiceConfig(
                    type="can_attack_start_here",
                    owner="Local system",
                    version="1",
                    local=True,
                    access_level=cyst_cfg.AccessLevel.LIMITED
                )
        ],
        traffic_processors=[],
        interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress(nodes_ip), cyst_cfg.IPNetwork(nodes_ip+"/24"))],
        shell="powershell",
        id="client_1"
    )

outside_node = cyst_cfg.NodeConfig(
        active_services=[],
        passive_services=[
            cyst_cfg.PassiveServiceConfig(
                type="credentials",
                owner="root/1234",
                version="1",
                local=True,
                access_level=cyst_cfg.AccessLevel.LIMITED
            )
        ],
        traffic_processors=[],
        interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("172.254.254.254"), cyst_cfg.IPNetwork("172.254.254.254/24"))],
        shell="bash",
        id="outside_node"
    ) 
# credentials: {'198.51.100.100': {'user': test1234, 'port': '22', 'password': 'testtest'}}


configuration_objects = [client_1, outside_node]
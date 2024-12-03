from cyst.api.configuration import *


target = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            name="bash",
            owner="root",
            version="8.1.0",
            access_level=AccessLevel.LIMITED,
            local=True,
        ),
        PassiveServiceConfig(
            name="lighttpd",
            owner="www",
            version="1.4.62",
            access_level=AccessLevel.LIMITED,
            local=False,
        )
    ],
    shell="bash",
    traffic_processors=[],
    interfaces=[],
    name="target"
)

attacker_service = ActiveServiceConfig(
    type="netsecenv_agent",
    name="attacker",
    owner="attacker",
    access_level=AccessLevel.LIMITED,
    ref="attacker_service"
)

attacker = NodeConfig(
    active_services=[attacker_service()],
    passive_services=[],
    interfaces=[],
    shell="",
    traffic_processors=[],
    name="attacker_node"
)

attacker2 = NodeConfig(
    active_services=[attacker_service()],
    passive_services=[],
    interfaces=[],
    shell="",
    traffic_processors=[],
    name="attacker_node_2"
)

router = RouterConfig(
    interfaces=[
        InterfaceConfig(
            ip=IPAddress("192.168.0.1"),
            net=IPNetwork("192.168.0.1/24"),
            index=0
        ),
        InterfaceConfig(
            ip=IPAddress("192.168.0.1"),
            net=IPNetwork("192.168.0.1/24"),
            index=1
        ),
        InterfaceConfig(
            ip=IPAddress("192.168.0.1"),
            net=IPNetwork("192.168.0.1/24"),
            index=2
        )
    ],
    traffic_processors=[
        FirewallConfig(
            default_policy=FirewallPolicy.ALLOW,
            chains=[
                FirewallChainConfig(
                    type=FirewallChainType.FORWARD,
                    policy=FirewallPolicy.ALLOW,
                    rules=[]
                )
            ]
        )
    ],
    id="router"
)

exploit1 = ExploitConfig(
    services=[
        VulnerableServiceConfig(
            service="lighttpd",
            min_version="1.4.62",
            max_version="1.4.62"
        )
    ],
    locality=ExploitLocality.REMOTE,
    category=ExploitCategory.CODE_EXECUTION,
    id="http_exploit"
)

connection1 = ConnectionConfig(
    src_ref=target,
    src_port=-1,
    dst_ref=router,
    dst_port=0
)

connection2 = ConnectionConfig(
    src_ref=attacker,
    src_port=-1,
    dst_ref=router,
    dst_port=1
)

connection3 = ConnectionConfig(
    src_ref=attacker2,
    src_port=-1,
    dst_ref=router,
    dst_port=2
)


configuration_objects = [target, attacker_service, attacker, attacker2, router, exploit1, connection2, connection1, connection3]

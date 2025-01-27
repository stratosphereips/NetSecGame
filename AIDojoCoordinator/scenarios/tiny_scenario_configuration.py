import cyst.api.configuration as cyst_cfg


target = cyst_cfg.NodeConfig(
    active_services=[],
    passive_services=[
        cyst_cfg.PassiveServiceConfig(
            name="bash",
            owner="root",
            version="8.1.0",
            access_level=cyst_cfg.AccessLevel.LIMITED,
            local=True,
        ),
        cyst_cfg.PassiveServiceConfig(
            name="lighttpd",
            owner="www",
            version="1.4.62",
            access_level=cyst_cfg.AccessLevel.LIMITED,
            local=False,
        )
    ],
    shell="bash",
    traffic_processors=[],
    interfaces=[],
    name="target"
)

attacker_service = cyst_cfg.ActiveServiceConfig(
    type="netsecenv_agent",
    name="attacker",
    owner="attacker",
    access_level=cyst_cfg.AccessLevel.LIMITED,
    ref="attacker_service"
)

attacker = cyst_cfg.NodeConfig(
    active_services=[attacker_service()],
    passive_services=[],
    interfaces=[],
    shell="",
    traffic_processors=[],
    name="attacker_node"
)

attacker2 = cyst_cfg.NodeConfig(
    active_services=[attacker_service()],
    passive_services=[],
    interfaces=[],
    shell="",
    traffic_processors=[],
    name="attacker_node_2"
)

router = cyst_cfg.RouterConfig(
    interfaces=[
        cyst_cfg.InterfaceConfig(
            ip=cyst_cfg.IPAddress("192.168.0.1"),
            net=cyst_cfg.IPNetwork("192.168.0.1/24"),
            index=0
        ),
        cyst_cfg.InterfaceConfig(
            ip=cyst_cfg.IPAddress("192.168.0.1"),
            net=cyst_cfg.IPNetwork("192.168.0.1/24"),
            index=1
        ),
        cyst_cfg.InterfaceConfig(
            ip=cyst_cfg.IPAddress("192.168.0.1"),
            net=cyst_cfg.IPNetwork("192.168.0.1/24"),
            index=2
        )
    ],
    traffic_processors=[
        cyst_cfg.FirewallConfig(
            default_policy=cyst_cfg.FirewallPolicy.ALLOW,
            chains=[
                cyst_cfg.FirewallChainConfig(
                    type=cyst_cfg.FirewallChainType.FORWARD,
                    policy=cyst_cfg.FirewallPolicy.ALLOW,
                    rules=[]
                )
            ]
        )
    ],
    id="router"
)

exploit1 = cyst_cfg.ExploitConfig(
    services=[
        cyst_cfg.VulnerableServiceConfig(
            service="lighttpd",
            min_version="1.4.62",
            max_version="1.4.62"
        )
    ],
    locality=cyst_cfg.ExploitLocality.REMOTE,
    category=cyst_cfg.ExploitCategory.CODE_EXECUTION,
    id="http_exploit"
)

connection1 = cyst_cfg.ConnectionConfig(
    src_ref=target,
    src_port=-1,
    dst_ref=router,
    dst_port=0
)

connection2 = cyst_cfg.ConnectionConfig(
    src_ref=attacker,
    src_port=-1,
    dst_ref=router,
    dst_port=1
)

connection3 = cyst_cfg.ConnectionConfig(
    src_ref=attacker2,
    src_port=-1,
    dst_ref=router,
    dst_port=2
)


configuration_objects = [target, attacker_service, attacker, attacker2, router, exploit1, connection2, connection1, connection3]

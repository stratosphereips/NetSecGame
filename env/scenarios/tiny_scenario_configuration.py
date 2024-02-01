import cyst.api.configuration as cyst_cfg
from cyst.api.logic.access import AuthenticationProviderType, AuthenticationTokenType, AuthenticationTokenSecurity

''' --------------------------------------------------------------------------------------------------------------------
A template for local password authentication. 
'''
local_password_auth = cyst_cfg.AuthenticationProviderConfig(
    provider_type=AuthenticationProviderType.LOCAL,
    token_type=AuthenticationTokenType.PASSWORD,
    token_security=AuthenticationTokenSecurity.SEALED,
    timeout=30
)

''' --------------------------------------------------------------------------------------------------------------------
Server 1:
- SMB/File sharing (It is vulnerable to some remote exploit)
- Remote Desktop
- Can go to router and internet

- the only windows server. It does not connect to the AD
- access schemes for remote desktop and file sharing are kept separate, but can be integrated into one if needed
'''
smb_server = cyst_cfg.NodeConfig(
    active_services=[],
    passive_services=[
        cyst_cfg.PassiveServiceConfig(
            type="lanman server",
            owner="Local system",
            version="10.0.19041",
            local=False,
            private_data=[
                cyst_cfg.DataConfig(
                    owner="User1",
                    description="DataFromServer1"
                )
            ],
            access_level=cyst_cfg.AccessLevel.LIMITED,
            authentication_providers=[],
            access_schemes=[
                cyst_cfg.AccessSchemeConfig(
                    authentication_providers=["windows login"],
                    authorization_domain=cyst_cfg.AuthorizationDomainConfig(
                        type=cyst_cfg.AuthorizationDomainType.LOCAL,
                        authorizations=[
                            cyst_cfg.AuthorizationConfig("User1", cyst_cfg.AccessLevel.LIMITED),
                            cyst_cfg.AuthorizationConfig("User2", cyst_cfg.AccessLevel.LIMITED),
                            cyst_cfg.AuthorizationConfig("User3", cyst_cfg.AccessLevel.LIMITED),
                            cyst_cfg.AuthorizationConfig("User4", cyst_cfg.AccessLevel.LIMITED),
                            cyst_cfg.AuthorizationConfig("User5", cyst_cfg.AccessLevel.LIMITED),
                            cyst_cfg.AuthorizationConfig("Administrator", cyst_cfg.AccessLevel.ELEVATED)
                        ]
                    )
                )
            ]
        ),
        cyst_cfg.PassiveServiceConfig(
            type="windows login",
            owner="Administrator",
            version="10.0.19041",
            local=True,
            access_level=cyst_cfg.AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("windows login")]
        ),
        cyst_cfg.PassiveServiceConfig(
            type="powershell",
            owner="Local system",
            version="10.0.19041",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.1.2"), cyst_cfg.IPNetwork("192.168.1.0/24"))],
    shell="powershell",
    id="smb_server"
)


''' --------------------------------------------------------------------------------------------------------------------
Client 1

- Remote Desktop
- Accounts
-- Local admin
-- User1
- Can go to server 1, 2, 3, router and internet
- Has the attacker
'''
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
            type="remote desktop service",
            owner="Local system",
            version="10.0.19041",
            local=False,
            access_level=cyst_cfg.AccessLevel.ELEVATED,
            parameters=[
                (cyst_cfg.ServiceParameter.ENABLE_SESSION, True),
                (cyst_cfg.ServiceParameter.SESSION_ACCESS_LEVEL, cyst_cfg.AccessLevel.LIMITED)
            ],
            authentication_providers=[local_password_auth("client_1_windows_login")],
            access_schemes=[
                cyst_cfg.AccessSchemeConfig(
                    authentication_providers=["client_1_windows_login"],
                    authorization_domain=cyst_cfg.AuthorizationDomainConfig(
                        type=cyst_cfg.AuthorizationDomainType.LOCAL,
                        authorizations=[
                            cyst_cfg.AuthorizationConfig("User1", cyst_cfg.AccessLevel.LIMITED),
                            cyst_cfg.AuthorizationConfig("Administrator", cyst_cfg.AccessLevel.ELEVATED)
                        ]
                    )
                )
            ]
        ),
        cyst_cfg.PassiveServiceConfig(
            type="powershell",
            owner="Local system",
            version="10.0.19041",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        ),
        cyst_cfg.PassiveServiceConfig(
            type="can_attack_start_here",
            owner="Local system",
            version="1",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.2.2"), cyst_cfg.IPNetwork("192.168.2.0/24"))],
    shell="powershell",
    id="client_1"
)

router1 = cyst_cfg.RouterConfig(
    interfaces=[
        cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.1.1"), cyst_cfg.IPNetwork("192.168.1.0/24"), index=2),
        cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.2.1"), cyst_cfg.IPNetwork("192.168.2.0/24"), index=3),
    ],
    routing_table=[
        # Push everything not-infrastructure to the internet
        cyst_cfg.RouteConfig(cyst_cfg.IPNetwork("0.0.0.0/0"), 10)
    ],
    # Firewall FORWARD policy specifies inter-network routes that are enabled
    # Firewall INPUT policy specifies who can connect directly to the router. In this scenario, everyone can.
    traffic_processors=[
        cyst_cfg.FirewallConfig(
          default_policy=cyst_cfg.FirewallPolicy.DENY,
          chains=[
              cyst_cfg.FirewallChainConfig(
                type=cyst_cfg.FirewallChainType.INPUT,
                policy=cyst_cfg.FirewallPolicy.DENY,
                rules=[
                    cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.1.0/24"), cyst_cfg.IPNetwork("192.168.1.1/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                    cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.2.0/24"), cyst_cfg.IPNetwork("192.168.2.1/32"), "*", cyst_cfg.FirewallPolicy.ALLOW)
                ]
              ),
              cyst_cfg.FirewallChainConfig(
                  type=cyst_cfg.FirewallChainType.FORWARD,
                  policy=cyst_cfg.FirewallPolicy.DENY,
                  rules=[
                      # Client 1 can go to server 1
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.2.2/32"), cyst_cfg.IPNetwork("192.168.1.2/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                  ]
              )
          ]
        )
    ],
    id="router1"
)

''' --------------------------------------------------------------------------------------------------------------------
Internet

- Represented as a router outside the scenario network 192.168.0.0/16
'''
internet = cyst_cfg.RouterConfig(
    interfaces=[
        cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("213.47.23.193"), cyst_cfg.IPNetwork("213.47.23.192/26"), index=0)
    ],
    routing_table=[
        cyst_cfg.RouteConfig(cyst_cfg.IPNetwork("192.168.0.0/16"), 0)
    ],
    traffic_processors=[],
    id="internet"
)

''' --------------------------------------------------------------------------------------------------------------------
Outside node

- A machine that sits in the internet, controlled by the attacker, used for data exfiltration.
'''
outside_node = cyst_cfg.NodeConfig(
    active_services=[],
    passive_services=[
        cyst_cfg.PassiveServiceConfig(
            type="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        ),
        cyst_cfg.PassiveServiceConfig(
            type="listener",
            owner="attacker",
            version="1.0.0",
            local=False,
            access_level=cyst_cfg.AccessLevel.ELEVATED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("213.47.23.195"), cyst_cfg.IPNetwork("213.47.23.195/26"))],
    shell="bash",
    id="outside_node"
)

''' --------------------------------------------------------------------------------------------------------------------
Connections
'''
connections = [
    cyst_cfg.ConnectionConfig("smb_server", 0, "router1", 0),
    cyst_cfg.ConnectionConfig("client_1", 0, "router1", 5),
    cyst_cfg.ConnectionConfig("internet", 0, "router1", 10),
    cyst_cfg.ConnectionConfig("internet", 1, "outside_node", 0)
]

''' --------------------------------------------------------------------------------------------------------------------
Exploits
- There exists only one for windows lanman server (SMB) and enables data exfiltration. Add others as needed...
'''
exploits = [
    cyst_cfg.ExploitConfig(
        services=[
            cyst_cfg.VulnerableServiceConfig(
                name="lanman server",
                min_version="10.0.19041",
                max_version="10.0.19041"
            )
        ],
        locality=cyst_cfg.ExploitLocality.REMOTE,
        category=cyst_cfg.ExploitCategory.DATA_MANIPULATION,
        id="smb_exploit"
    )
]

configuration_objects = [smb_server, client_1, router1, internet, outside_node, *connections, *exploits]
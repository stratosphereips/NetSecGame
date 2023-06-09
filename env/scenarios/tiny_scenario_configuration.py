from cyst.api.configuration import *
from cyst.api.logic.access import AuthenticationProviderType, AuthenticationTokenType, AuthenticationTokenSecurity

''' --------------------------------------------------------------------------------------------------------------------
A template for local password authentication. 
'''
local_password_auth = AuthenticationProviderConfig(
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
smb_server = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="lanman server",
            owner="Local system",
            version="10.0.19041",
            local=False,
            private_data=[
                DataConfig(
                    owner="User1",
                    description="DataFromServer1"
                )
            ],
            access_level=AccessLevel.LIMITED,
            authentication_providers=[],
            access_schemes=[
                AccessSchemeConfig(
                    authentication_providers=["windows login"],
                    authorization_domain=AuthorizationDomainConfig(
                        type=AuthorizationDomainType.LOCAL,
                        authorizations=[
                            AuthorizationConfig("User1", AccessLevel.LIMITED),
                            AuthorizationConfig("User2", AccessLevel.LIMITED),
                            AuthorizationConfig("User3", AccessLevel.LIMITED),
                            AuthorizationConfig("User4", AccessLevel.LIMITED),
                            AuthorizationConfig("User5", AccessLevel.LIMITED),
                            AuthorizationConfig("Administrator", AccessLevel.ELEVATED)
                        ]
                    )
                )
            ]
        ),
        PassiveServiceConfig(
            type="remote desktop service",
            owner="Local system",
            version="10.0.19041",
            local=False,
            access_level=AccessLevel.ELEVATED,
            parameters=[
                (ServiceParameter.ENABLE_SESSION, True),
                (ServiceParameter.SESSION_ACCESS_LEVEL, AccessLevel.LIMITED)
            ],
            authentication_providers=[],
            access_schemes=[
                AccessSchemeConfig(
                    authentication_providers=["windows login"],
                    authorization_domain=AuthorizationDomainConfig(
                        type=AuthorizationDomainType.LOCAL,
                        authorizations=[
                            AuthorizationConfig("User1", AccessLevel.LIMITED),
                            AuthorizationConfig("User2", AccessLevel.LIMITED),
                            AuthorizationConfig("User3", AccessLevel.LIMITED),
                            AuthorizationConfig("User4", AccessLevel.LIMITED),
                            AuthorizationConfig("User5", AccessLevel.LIMITED),
                            AuthorizationConfig("Administrator", AccessLevel.ELEVATED)
                        ]
                    )
                )
            ]
        ),
        PassiveServiceConfig(
            type="windows login",
            owner="Administrator",
            version="10.0.19041",
            local=True,
            access_level=AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("windows login")]
        ),
        PassiveServiceConfig(
            type="powershell",
            owner="Local system",
            version="10.0.19041",
            local=True,
            access_level=AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.1.2"), IPNetwork("192.168.1.0/24"))],
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
client_1 = NodeConfig(
    active_services=[
        ActiveServiceConfig(
            type="scripted_actor",
            name="attacker",
            owner="attacker",
            access_level=AccessLevel.LIMITED,
            id="attacker_service"
        )
    ],
    passive_services=[
        PassiveServiceConfig(
            type="remote desktop service",
            owner="Local system",
            version="10.0.19041",
            local=False,
            access_level=AccessLevel.ELEVATED,
            parameters=[
                (ServiceParameter.ENABLE_SESSION, True),
                (ServiceParameter.SESSION_ACCESS_LEVEL, AccessLevel.LIMITED)
            ],
            authentication_providers=[local_password_auth("client_1_windows_login")],
            access_schemes=[
                AccessSchemeConfig(
                    authentication_providers=["client_1_windows_login"],
                    authorization_domain=AuthorizationDomainConfig(
                        type=AuthorizationDomainType.LOCAL,
                        authorizations=[
                            AuthorizationConfig("User1", AccessLevel.LIMITED),
                            AuthorizationConfig("Administrator", AccessLevel.ELEVATED)
                        ]
                    )
                )
            ]
        ),
        PassiveServiceConfig(
            type="powershell",
            owner="Local system",
            version="10.0.19041",
            local=True,
            access_level=AccessLevel.LIMITED
        ),
        PassiveServiceConfig(
            type="can_attack_start_here",
            owner="Local system",
            version="1",
            local=True,
            access_level=AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.2.2"), IPNetwork("192.168.2.0/24"))],
    shell="powershell",
    id="client_1"
)

router1 = RouterConfig(
    interfaces=[
        InterfaceConfig(IPAddress("192.168.1.1"), IPNetwork("192.168.1.0/24"), index=2),
        InterfaceConfig(IPAddress("192.168.2.1"), IPNetwork("192.168.2.0/24"), index=3),
    ],
    routing_table=[
        # Push everything not-infrastructure to the internet
        RouteConfig(IPNetwork("0.0.0.0/0"), 10)
    ],
    # Firewall FORWARD policy specifies inter-network routes that are enabled
    # Firewall INPUT policy specifies who can connect directly to the router. In this scenario, everyone can.
    traffic_processors=[
        FirewallConfig(
          default_policy=FirewallPolicy.DENY,
          chains=[
              FirewallChainConfig(
                type=FirewallChainType.INPUT,
                policy=FirewallPolicy.DENY,
                rules=[
                    FirewallRule(IPNetwork("192.168.1.0/24"), IPNetwork("192.168.1.1/32"), "*", FirewallPolicy.ALLOW),
                    FirewallRule(IPNetwork("192.168.2.0/24"), IPNetwork("192.168.2.1/32"), "*", FirewallPolicy.ALLOW)
                ]
              ),
              FirewallChainConfig(
                  type=FirewallChainType.FORWARD,
                  policy=FirewallPolicy.DENY,
                  rules=[
                      # Client 1 can go to server 1
                      FirewallRule(IPNetwork("192.168.2.2/32"), IPNetwork("192.168.1.2/32"), "*", FirewallPolicy.ALLOW),
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
internet = RouterConfig(
    interfaces=[
        InterfaceConfig(IPAddress("213.47.23.193"), IPNetwork("213.47.23.192/26"), index=0)
    ],
    routing_table=[
        RouteConfig(IPNetwork("192.168.0.0/16"), 0)
    ],
    traffic_processors=[],
    id="internet"
)

''' --------------------------------------------------------------------------------------------------------------------
Outside node

- A machine that sits in the internet, controlled by the attacker, used for data exfiltration.
'''
outside_node = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=AccessLevel.LIMITED
        ),
        PassiveServiceConfig(
            type="listener",
            owner="attacker",
            version="1.0.0",
            local=False,
            access_level=AccessLevel.ELEVATED
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("213.47.23.195"), IPNetwork("213.47.23.195/26"))],
    shell="bash",
    id="outside_node"
)

''' --------------------------------------------------------------------------------------------------------------------
Connections
'''
connections = [
    ConnectionConfig("smb_server", 0, "router1", 0),
    ConnectionConfig("client_1", 0, "router1", 5),
    ConnectionConfig("internet", 0, "router1", 10),
    ConnectionConfig("internet", 1, "outside_node", 0)
]

''' --------------------------------------------------------------------------------------------------------------------
Exploits
- There exists only one for windows lanman server (SMB) and enables data exfiltration. Add others as needed...
'''
exploits = [
    ExploitConfig(
        services=[
            VulnerableServiceConfig(
                name="lanman server",
                min_version="10.0.19041",
                max_version="10.0.19041"
            )
        ],
        locality=ExploitLocality.REMOTE,
        category=ExploitCategory.DATA_MANIPULATION,
        id="smb_exploit"
    )
]

configuration_objects = [smb_server, client_1, router1, internet, outside_node, *connections, *exploits]
# This file defines the hosts and their characteristics, the services they run, the users they have and their security levels, the data they have, and in the router/FW all the rules of which host can access what
from cyst.api.configuration import *
from cyst.api.configuration.network.elements import RouteConfig
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
                ),
                DataConfig(
                    owner="User2",
                    description="Data2FromServer1"
                ),
                DataConfig(
                    owner="User1",
                    description="Data3FromServer1"
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
Server 2:
- Database
- SSH
- Can go to router

- I assume that the database is configured locally. There would have to be an access scheme in a real world setting,
  but I will not pollute the scenario with it. 
- The SSH access configuration is very basic.
- Nothing is in the database.
'''
db_server = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="openssh",
            owner="openssh",
            version="8.1.0",
            local=False,
            access_level=AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("openssh_login_db_server")],
            parameters=[
                (ServiceParameter.ENABLE_SESSION, True),
                (ServiceParameter.SESSION_ACCESS_LEVEL, AccessLevel.LIMITED)
            ],
            access_schemes=[AccessSchemeConfig(
                authentication_providers=["openssh_login_db_server"],
                authorization_domain=AuthorizationDomainConfig(
                    type=AuthorizationDomainType.LOCAL,
                    authorizations=[
                        AuthorizationConfig("User1", AccessLevel.LIMITED),
                        AuthorizationConfig("User2", AccessLevel.LIMITED),
                        AuthorizationConfig("User3", AccessLevel.LIMITED),
                        AuthorizationConfig("User4", AccessLevel.LIMITED),
                        AuthorizationConfig("User5", AccessLevel.LIMITED),
                        AuthorizationConfig("root", AccessLevel.ELEVATED)
                    ]
                )
            )]
        ),
        PassiveServiceConfig(
            type="postgresql",
            owner="postgresql",
            version="14.3.0",
            private_data=[
                DataConfig(
                    owner="User1",
                    description="DatabaseData"
            )],
            local=False,
            access_level=AccessLevel.LIMITED
        ),
        PassiveServiceConfig(
            type="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.1.3"), IPNetwork("192.168.1.0/24"))],
    shell="bash",
    id="db_server"
)

''' --------------------------------------------------------------------------------------------------------------------
Server 3:
- Web server
- SSH
- Has a defender
- Can go to router and internet

- Defender will be added as an active service, once the service is created
- The web server is there, but nothing is going on with it
'''
web_server = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="lighttpd",
            owner="lighttpd",
            version="1.4.54",
            local=False,
            private_data=[
                DataConfig(
                    owner="User2",
                    description="WebServerData"
            ),
            DataConfig(
                    owner="User1",
                    description="DataFromServer1"
                )
            ],
            access_level=AccessLevel.LIMITED,
            authentication_providers=[],
            parameters=[],
            access_schemes=[]
        ),
        PassiveServiceConfig(
            type="openssh",
            owner="openssh",
            version="8.1.0",
            local=False,
            access_level=AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("openssh_login_web_server")],
            parameters=[
                (ServiceParameter.ENABLE_SESSION, True),
                (ServiceParameter.SESSION_ACCESS_LEVEL, AccessLevel.LIMITED)
            ],
            access_schemes=[AccessSchemeConfig(
                authentication_providers=["openssh_login_web_server"],
                authorization_domain=AuthorizationDomainConfig(
                    type=AuthorizationDomainType.LOCAL,
                    authorizations=[
                        AuthorizationConfig("User1", AccessLevel.LIMITED),
                        AuthorizationConfig("User2", AccessLevel.LIMITED),
                        AuthorizationConfig("User3", AccessLevel.LIMITED),
                        AuthorizationConfig("User4", AccessLevel.LIMITED),
                        AuthorizationConfig("User5", AccessLevel.LIMITED),
                        AuthorizationConfig("root", AccessLevel.ELEVATED)
                    ]
                )
            )]
        ),
        PassiveServiceConfig(
            type="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.1.4"), IPNetwork("192.168.1.0/24"))],
    shell="bash",
    id="web_server"
)

''' --------------------------------------------------------------------------------------------------------------------
Server 4:
- SSH
- Can go to router and internet

- No users were specified to be able to access the server, so I am keeping only the root
'''
other_server_1 = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="openssh",
            owner="openssh",
            version="8.1.0",
            local=False,
            access_level=AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("openssh_login_other_server_1")],
            parameters=[
                (ServiceParameter.ENABLE_SESSION, True),
                (ServiceParameter.SESSION_ACCESS_LEVEL, AccessLevel.LIMITED)
            ],
            access_schemes=[AccessSchemeConfig(
                authentication_providers=["openssh_login_other_server_1"],
                authorization_domain=AuthorizationDomainConfig(
                    type=AuthorizationDomainType.LOCAL,
                    authorizations=[
                        AuthorizationConfig("root", AccessLevel.ELEVATED)
                    ]
                )
            )]
        ),
        PassiveServiceConfig(
            type="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.1.5"), IPNetwork("192.168.1.0/24"))],
    shell="bash",
    id="other_server_1"
)

''' --------------------------------------------------------------------------------------------------------------------
Server 5:
- SSH
- Can go to router and internet

- No users were specified to be able to access the server, so I am keeping only the root
'''
other_server_2 = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="openssh",
            owner="openssh",
            version="8.1.0",
            local=False,
            access_level=AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("openssh_login_other_server_2")],
            parameters=[
                (ServiceParameter.ENABLE_SESSION, True),
                (ServiceParameter.SESSION_ACCESS_LEVEL, AccessLevel.LIMITED)
            ],
            access_schemes=[AccessSchemeConfig(
                authentication_providers=["openssh_login_other_server_2"],
                authorization_domain=AuthorizationDomainConfig(
                    type=AuthorizationDomainType.LOCAL,
                    authorizations=[
                        AuthorizationConfig("root", AccessLevel.ELEVATED)
                    ]
                )
            )]
        ),
        PassiveServiceConfig(
            type="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress("192.168.1.6"), IPNetwork("192.168.1.0/24"))],
    shell="bash",
    id="other_server_2"
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

''' --------------------------------------------------------------------------------------------------------------------
Client 2

- Remote Desktop
- Accounts
-- Local admin
-- User2
- Can go to server 1, 2, 3, router and internet
'''
client_2 = NodeConfig(
    active_services=[],
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
            authentication_providers=[local_password_auth("client_2_windows_login")],
            access_schemes=[
                AccessSchemeConfig(
                    authentication_providers=["client_2_windows_login"],
                    authorization_domain=AuthorizationDomainConfig(
                        type=AuthorizationDomainType.LOCAL,
                        authorizations=[
                            AuthorizationConfig("User2", AccessLevel.LIMITED),
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
    interfaces=[InterfaceConfig(IPAddress("192.168.2.3"), IPNetwork("192.168.2.0/24"))],
    shell="powershell",
    id="client_2"
)

''' --------------------------------------------------------------------------------------------------------------------
Client 3

- SSH
- Accounts
-- Local admin
-- User3
- Can go to server 1, 2, 3, router and internet
'''
client_3 = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="openssh",
            owner="openssh",
            version="8.1.0",
            local=False,
            access_level=AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("openssh_login_client_3")],
            parameters=[
                (ServiceParameter.ENABLE_SESSION, True),
                (ServiceParameter.SESSION_ACCESS_LEVEL, AccessLevel.LIMITED)
            ],
            access_schemes=[AccessSchemeConfig(
                authentication_providers=["openssh_login_client_3"],
                authorization_domain=AuthorizationDomainConfig(
                    type=AuthorizationDomainType.LOCAL,
                    authorizations=[
                        AuthorizationConfig("User3", AccessLevel.LIMITED),
                        AuthorizationConfig("root", AccessLevel.ELEVATED)
                    ]
                )
            )]
        ),
        PassiveServiceConfig(
            type="bash",
            owner="root",
            version="5.0.0",
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
    interfaces=[InterfaceConfig(IPAddress("192.168.2.4"), IPNetwork("192.168.2.0/24"))],
    shell="bash",
    id="client_3"
)

''' --------------------------------------------------------------------------------------------------------------------
Client 4

- SSH
- Accounts
-- Local admin
-- User4
- Can go to server 1, 2, 3, router and internet
'''
client_4 = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="openssh",
            owner="openssh",
            version="8.1.0",
            local=False,
            access_level=AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("openssh_login_client_4")],
            parameters=[
                (ServiceParameter.ENABLE_SESSION, True),
                (ServiceParameter.SESSION_ACCESS_LEVEL, AccessLevel.LIMITED)
            ],
            access_schemes=[AccessSchemeConfig(
                authentication_providers=["openssh_login_client_4"],
                authorization_domain=AuthorizationDomainConfig(
                    type=AuthorizationDomainType.LOCAL,
                    authorizations=[
                        AuthorizationConfig("User4", AccessLevel.LIMITED),
                        AuthorizationConfig("root", AccessLevel.ELEVATED)
                    ]
                )
            )]
        ),
        PassiveServiceConfig(
            type="bash",
            owner="root",
            version="5.0.0",
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
    interfaces=[InterfaceConfig(IPAddress("192.168.2.5"), IPNetwork("192.168.2.0/24"))],
    shell="bash",
    id="client_4"
)

''' --------------------------------------------------------------------------------------------------------------------
Client 5

- No ports (I assume no remote connection)
- Accounts
-- Local admin
-- User5
- Can go to server 1, 2, 3, router and internet
'''
client_5 = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            type="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=AccessLevel.LIMITED,
            authentication_providers=[local_password_auth("local_login_client_5")],
            access_schemes=[AccessSchemeConfig(
                authentication_providers=["local_login_client_5"],
                authorization_domain=AuthorizationDomainConfig(
                    type=AuthorizationDomainType.LOCAL,
                    authorizations=[
                        AuthorizationConfig("User5", AccessLevel.LIMITED),
                        AuthorizationConfig("root", AccessLevel.ELEVATED)
                    ]
                )
            )]
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
    interfaces=[InterfaceConfig(IPAddress("192.168.2.6"), IPNetwork("192.168.2.0/24"))],
    shell="bash",
    id="client_5"
)

''' --------------------------------------------------------------------------------------------------------------------
Routers

- Has a defender
- SSH (Nope, the routers do not work as normal PCs. But the defender will be ready and will be possible to control it)
'''
router1 = RouterConfig(
    interfaces=[
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.0/16"), index=1),
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
                      # Client 1 can go to server 1, 2, 3
                      FirewallRule(IPNetwork("192.168.2.2/32"), IPNetwork("192.168.1.2/32"), "*", FirewallPolicy.ALLOW),
                      FirewallRule(IPNetwork("192.168.2.2/32"), IPNetwork("192.168.1.3/32"), "*", FirewallPolicy.ALLOW),
                      FirewallRule(IPNetwork("192.168.2.2/32"), IPNetwork("192.168.1.4/32"), "*", FirewallPolicy.ALLOW),
                      # Client 2 can go to server 1, 2, 3
                      FirewallRule(IPNetwork("192.168.2.3/32"), IPNetwork("192.168.1.2/32"), "*", FirewallPolicy.ALLOW),
                      FirewallRule(IPNetwork("192.168.2.3/32"), IPNetwork("192.168.1.3/32"), "*", FirewallPolicy.ALLOW),
                      FirewallRule(IPNetwork("192.168.2.3/32"), IPNetwork("192.168.1.4/32"), "*", FirewallPolicy.ALLOW),
                      # Client 3 can go to server 1, 2, 3
                      FirewallRule(IPNetwork("192.168.2.4/32"), IPNetwork("192.168.1.2/32"), "*", FirewallPolicy.ALLOW),
                      FirewallRule(IPNetwork("192.168.2.4/32"), IPNetwork("192.168.1.3/32"), "*", FirewallPolicy.ALLOW),
                      FirewallRule(IPNetwork("192.168.2.4/32"), IPNetwork("192.168.1.4/32"), "*", FirewallPolicy.ALLOW),
                      # Client 4 can go to server 1, 2, 3
                      FirewallRule(IPNetwork("192.168.2.5/32"), IPNetwork("192.168.1.2/32"), "*", FirewallPolicy.ALLOW),
                      FirewallRule(IPNetwork("192.168.2.5/32"), IPNetwork("192.168.1.3/32"), "*", FirewallPolicy.ALLOW),
                      FirewallRule(IPNetwork("192.168.2.5/32"), IPNetwork("192.168.1.4/32"), "*", FirewallPolicy.ALLOW),
                      # Client 5 can go to server 1, 2, 3
                      FirewallRule(IPNetwork("192.168.2.6/32"), IPNetwork("192.168.1.2/32"), "*", FirewallPolicy.ALLOW),
                      FirewallRule(IPNetwork("192.168.2.6/32"), IPNetwork("192.168.1.3/32"), "*", FirewallPolicy.ALLOW),
                      FirewallRule(IPNetwork("192.168.2.6/32"), IPNetwork("192.168.1.4/32"), "*", FirewallPolicy.ALLOW)
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
    ConnectionConfig("db_server", 0, "router1", 1),
    ConnectionConfig("web_server", 0, "router1", 2),
    ConnectionConfig("other_server_1", 0, "router1", 3),
    ConnectionConfig("other_server_2", 0, "router1", 4),
    ConnectionConfig("client_1", 0, "router1", 5),
    ConnectionConfig("client_2", 0, "router1", 6),
    ConnectionConfig("client_3", 0, "router1", 7),
    ConnectionConfig("client_4", 0, "router1", 8),
    ConnectionConfig("client_5", 0, "router1", 9),
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

configuration_objects = [smb_server, db_server, web_server, other_server_1, other_server_2, client_1, client_2,
                         client_3, client_4, client_5, router1, internet, outside_node, *connections, *exploits]
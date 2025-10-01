# This file defines the hosts and their characteristics, the services they run, the users they have and their security levels, the data they have, and in the router/FW all the rules of which host can access what
import cyst.api.configuration as cyst_cfg
from cyst.api.configuration.network.elements import RouteConfig
from cyst.api.logic.access import AuthenticationProviderType, AuthenticationTokenType, AuthenticationTokenSecurity
from cyst.api.configuration import ExploitConfig, VulnerableServiceConfig
from cyst.api.logic.exploit import ExploitLocality, ExploitCategory
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
- Service types should be derived from nmap services https://svn.nmap.org/nmap/nmap-services
'''
smb_server = cyst_cfg.NodeConfig(
    active_services=[],
    passive_services=[
        cyst_cfg.PassiveServiceConfig(
            name="445/tcp, microsoft-ds",
            owner="Local system",
            version="10.0.19041",
            local=False,
            private_data=[
                cyst_cfg.DataConfig(
                    owner="User1",
                    description="DataFromServer1",
                    path="/etc/"
                ),
                cyst_cfg.DataConfig(
                    owner="User2",
                    description="Data2FromServer1",
                    path="/etc/"
                ),
                cyst_cfg.DataConfig(
                    owner="User1",
                    description="Data3FromServer1",
                    path="/etc/"
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
            name="3389/tcp, ms-wbt-server",
            owner="Local system",
            version="10.0.19041",
            local=False,
            access_level=cyst_cfg.AccessLevel.ELEVATED,
            parameters=[
                (cyst_cfg.ServiceParameter.ENABLE_SESSION, True),
                (cyst_cfg.ServiceParameter.SESSION_ACCESS_LEVEL, cyst_cfg.AccessLevel.LIMITED)
            ],
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
            name="windows login",
            owner="Administrator",
            version="10.0.19041",
            local=True,
            access_level=cyst_cfg.AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("windows login")]
        ),
        cyst_cfg.PassiveServiceConfig(
            name="powershell",
            owner="Local system",
            version="10.0.19041",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.95.2"), cyst_cfg.IPNetwork("192.168.95.0/24"))],
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
db_server = cyst_cfg.NodeConfig(
    active_services=[],
    passive_services=[
        cyst_cfg.PassiveServiceConfig(
            name="22/tcp, ssh",
            owner="openssh",
            version="8.1.0",
            local=False,
            access_level=cyst_cfg.AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("openssh_login_db_server")],
            parameters=[
                (cyst_cfg.ServiceParameter.ENABLE_SESSION, True),
                (cyst_cfg.ServiceParameter.SESSION_ACCESS_LEVEL, cyst_cfg.AccessLevel.LIMITED)
            ],
            access_schemes=[cyst_cfg.AccessSchemeConfig(
                authentication_providers=["openssh_login_db_server"],
                authorization_domain=cyst_cfg.AuthorizationDomainConfig(
                    type=cyst_cfg.AuthorizationDomainType.LOCAL,
                    authorizations=[
                        cyst_cfg.AuthorizationConfig("User1", cyst_cfg.AccessLevel.LIMITED),
                        cyst_cfg.AuthorizationConfig("User2", cyst_cfg.AccessLevel.LIMITED),
                        cyst_cfg.AuthorizationConfig("User3", cyst_cfg.AccessLevel.LIMITED),
                        cyst_cfg.AuthorizationConfig("User4", cyst_cfg.AccessLevel.LIMITED),
                        cyst_cfg.AuthorizationConfig("User5", cyst_cfg.AccessLevel.LIMITED),
                        cyst_cfg.AuthorizationConfig("root", cyst_cfg.AccessLevel.ELEVATED)
                    ]
                )
            )]
        ),
        cyst_cfg.PassiveServiceConfig(
            name="5432/tcp, postgresql",
            owner="postgresql",
            version="14.3.0",
            private_data=[
                cyst_cfg.DataConfig(
                    owner="User1",
                    description="DatabaseData",
                    path="/etc/"
            )],
            local=False,
            access_level=cyst_cfg.AccessLevel.LIMITED
        ),
        cyst_cfg.PassiveServiceConfig(
            name="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.95.3"), cyst_cfg.IPNetwork("192.168.95.0/24"))],
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
web_server = cyst_cfg.NodeConfig(
    active_services=[],
    passive_services=[
        cyst_cfg.PassiveServiceConfig(
            name="80/tcp, http",
            owner="lighttpd",
            version="1.4.54",
            local=False,
            private_data=[
                cyst_cfg.DataConfig(
                    owner="User2",
                    description="WebServerData",
                    path="/etc/"
            ),
            ],
            access_level=cyst_cfg.AccessLevel.LIMITED,
            authentication_providers=[],
            parameters=[],
            access_schemes=[]
        ),
        cyst_cfg.PassiveServiceConfig(
            name="22/tcp, ssh",
            owner="openssh",
            version="8.1.0",
            local=False,
            access_level=cyst_cfg.AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("openssh_login_web_server")],
            parameters=[
                (cyst_cfg.ServiceParameter.ENABLE_SESSION, True),
                (cyst_cfg.ServiceParameter.SESSION_ACCESS_LEVEL, cyst_cfg.AccessLevel.LIMITED)
            ],
            access_schemes=[cyst_cfg.AccessSchemeConfig(
                authentication_providers=["openssh_login_web_server"],
                authorization_domain=cyst_cfg.AuthorizationDomainConfig(
                    type=cyst_cfg.AuthorizationDomainType.LOCAL,
                    authorizations=[
                        cyst_cfg.AuthorizationConfig("User1", cyst_cfg.AccessLevel.LIMITED),
                        cyst_cfg.AuthorizationConfig("User2", cyst_cfg.AccessLevel.LIMITED),
                        cyst_cfg.AuthorizationConfig("User3", cyst_cfg.AccessLevel.LIMITED),
                        cyst_cfg.AuthorizationConfig("User4", cyst_cfg.AccessLevel.LIMITED),
                        cyst_cfg.AuthorizationConfig("User5", cyst_cfg.AccessLevel.LIMITED),
                        cyst_cfg.AuthorizationConfig("root", cyst_cfg.AccessLevel.ELEVATED)
                    ]
                )
            )]
        ),
        cyst_cfg.PassiveServiceConfig(
            name="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.95.4"), cyst_cfg.IPNetwork("192.168.95.0/24"))],
    shell="bash",
    id="web_server"
)

''' --------------------------------------------------------------------------------------------------------------------
Server 4:
- SSH
- Can go to router and internet

- No users were specified to be able to access the server, so I am keeping only the root
'''
other_server_1 = cyst_cfg.NodeConfig(
    active_services=[],
    passive_services=[
        cyst_cfg.PassiveServiceConfig(
            name="22/tcp, ssh",
            owner="openssh",
            version="8.1.0",
            local=False,
            access_level=cyst_cfg.AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("openssh_login_other_server_1")],
            parameters=[
                (cyst_cfg.ServiceParameter.ENABLE_SESSION, True),
                (cyst_cfg.ServiceParameter.SESSION_ACCESS_LEVEL, cyst_cfg.AccessLevel.LIMITED)
            ],
            access_schemes=[cyst_cfg.AccessSchemeConfig(
                authentication_providers=["openssh_login_other_server_1"],
                authorization_domain=cyst_cfg.AuthorizationDomainConfig(
                    type=cyst_cfg.AuthorizationDomainType.LOCAL,
                    authorizations=[
                        cyst_cfg.AuthorizationConfig("root", cyst_cfg.AccessLevel.ELEVATED)
                    ]
                )
            )]
        ),
        cyst_cfg.PassiveServiceConfig(
            name="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.95.5"), cyst_cfg.IPNetwork("192.168.95.0/24"))],
    shell="bash",
    id="other_server_1"
)

''' --------------------------------------------------------------------------------------------------------------------
Server 5:
- SSH
- Can go to router and internet

- No users were specified to be able to access the server, so I am keeping only the root
'''
other_server_2 = cyst_cfg.NodeConfig(
    active_services=[],
    passive_services=[
        cyst_cfg.PassiveServiceConfig(
            name="22/tcp, ssh",
            owner="openssh",
            version="8.1.0",
            local=False,
            access_level=cyst_cfg.AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("openssh_login_other_server_2")],
            parameters=[
                (cyst_cfg.ServiceParameter.ENABLE_SESSION, True),
                (cyst_cfg.ServiceParameter.SESSION_ACCESS_LEVEL, cyst_cfg.AccessLevel.LIMITED)
            ],
            access_schemes=[cyst_cfg.AccessSchemeConfig(
                authentication_providers=["openssh_login_other_server_2"],
                authorization_domain=cyst_cfg.AuthorizationDomainConfig(
                    type=cyst_cfg.AuthorizationDomainType.LOCAL,
                    authorizations=[
                        cyst_cfg.AuthorizationConfig("root", cyst_cfg.AccessLevel.ELEVATED)
                    ]
                )
            )]
        ),
        cyst_cfg.PassiveServiceConfig(
            name="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.95.6"), cyst_cfg.IPNetwork("192.168.95.0/24"))],
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
            name="3389/tcp, ms-wbt-server",
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
            name="powershell",
            owner="Local system",
            version="10.0.19041",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        ),
        cyst_cfg.PassiveServiceConfig(
            name="can_attack_start_here",
            owner="Local system",
            version="1",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.94.2"), cyst_cfg.IPNetwork("192.168.94.0/24"))],
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
client_2 = cyst_cfg.NodeConfig(
    active_services=[],
    passive_services=[
        cyst_cfg.PassiveServiceConfig(
            name="3389/tcp, ms-wbt-server",
            owner="Local system",
            version="10.0.19041",
            local=False,
            access_level=cyst_cfg.AccessLevel.ELEVATED,
            parameters=[
                (cyst_cfg.ServiceParameter.ENABLE_SESSION, True),
                (cyst_cfg.ServiceParameter.SESSION_ACCESS_LEVEL, cyst_cfg.AccessLevel.LIMITED)
            ],
            authentication_providers=[local_password_auth("client_2_windows_login")],
            access_schemes=[
                cyst_cfg.AccessSchemeConfig(
                    authentication_providers=["client_2_windows_login"],
                    authorization_domain=cyst_cfg.AuthorizationDomainConfig(
                        type=cyst_cfg.AuthorizationDomainType.LOCAL,
                        authorizations=[
                            cyst_cfg.AuthorizationConfig("User2", cyst_cfg.AccessLevel.LIMITED),
                            cyst_cfg.AuthorizationConfig("Administrator", cyst_cfg.AccessLevel.ELEVATED)
                        ]
                    )
                )
            ]
        ),
        cyst_cfg.PassiveServiceConfig(
            name="powershell",
            owner="Local system",
            version="10.0.19041",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        ),
        cyst_cfg.PassiveServiceConfig(
            name="can_attack_start_here",
            owner="Local system",
            version="1",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.94.3"), cyst_cfg.IPNetwork("192.168.94.0/24"))],
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
client_3 = cyst_cfg.NodeConfig(
    active_services=[],
    passive_services=[
        cyst_cfg.PassiveServiceConfig(
            name="22/tcp, ssh",
            owner="openssh",
            version="8.1.0",
            local=False,
            access_level=cyst_cfg.AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("openssh_login_client_3")],
            parameters=[
                (cyst_cfg.ServiceParameter.ENABLE_SESSION, True),
                (cyst_cfg.ServiceParameter.SESSION_ACCESS_LEVEL, cyst_cfg.AccessLevel.LIMITED)
            ],
            access_schemes=[cyst_cfg.AccessSchemeConfig(
                authentication_providers=["openssh_login_client_3"],
                authorization_domain=cyst_cfg.AuthorizationDomainConfig(
                    type=cyst_cfg.AuthorizationDomainType.LOCAL,
                    authorizations=[
                        cyst_cfg.AuthorizationConfig("User3", cyst_cfg.AccessLevel.LIMITED),
                        cyst_cfg.AuthorizationConfig("root", cyst_cfg.AccessLevel.ELEVATED)
                    ]
                )
            )]
        ),
        cyst_cfg.PassiveServiceConfig(
            name="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        ),
        cyst_cfg.PassiveServiceConfig(
            name="can_attack_start_here",
            owner="Local system",
            version="1",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.94.4"), cyst_cfg.IPNetwork("192.168.94.0/24"))],
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
client_4 = cyst_cfg.NodeConfig(
    active_services=[],
    passive_services=[
        cyst_cfg.PassiveServiceConfig(
            name="22/tcp, ssh",
            owner="openssh",
            version="8.1.0",
            local=False,
            access_level=cyst_cfg.AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("openssh_login_client_4")],
            parameters=[
                (cyst_cfg.ServiceParameter.ENABLE_SESSION, True),
                (cyst_cfg.ServiceParameter.SESSION_ACCESS_LEVEL, cyst_cfg.AccessLevel.LIMITED)
            ],
            access_schemes=[cyst_cfg.AccessSchemeConfig(
                authentication_providers=["openssh_login_client_4"],
                authorization_domain=cyst_cfg.AuthorizationDomainConfig(
                    type=cyst_cfg.AuthorizationDomainType.LOCAL,
                    authorizations=[
                        cyst_cfg.AuthorizationConfig("User4", cyst_cfg.AccessLevel.LIMITED),
                        cyst_cfg.AuthorizationConfig("root", cyst_cfg.AccessLevel.ELEVATED)
                    ]
                )
            )]
        ),
        cyst_cfg.PassiveServiceConfig(
            name="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        ),
        cyst_cfg.PassiveServiceConfig(
            name="can_attack_start_here",
            owner="Local system",
            version="1",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.94.5"), cyst_cfg.IPNetwork("192.168.94.0/24"))],
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
client_5 = cyst_cfg.NodeConfig(
    active_services=[],
    passive_services=[
        cyst_cfg.PassiveServiceConfig(
            name="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED,
            authentication_providers=[local_password_auth("local_login_client_5")],
            access_schemes=[cyst_cfg.AccessSchemeConfig(
                authentication_providers=["local_login_client_5"],
                authorization_domain=cyst_cfg.AuthorizationDomainConfig(
                    type=cyst_cfg.AuthorizationDomainType.LOCAL,
                    authorizations=[
                        cyst_cfg.AuthorizationConfig("User5", cyst_cfg.AccessLevel.LIMITED),
                        cyst_cfg.AuthorizationConfig("root", cyst_cfg.AccessLevel.ELEVATED)
                    ]
                )
            )]
        ),
        cyst_cfg.PassiveServiceConfig(
            name="can_attack_start_here",
            owner="Local system",
            version="1",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.94.6"), cyst_cfg.IPNetwork("192.168.94.0/24"))],
    shell="bash",
    id="client_5"
)

''' --------------------------------------------------------------------------------------------------------------------
Routers

- Has a defender
- SSH (Nope, the routers do not work as normal PCs. But the defender will be ready and will be possible to control it)
'''
router1 = cyst_cfg.RouterConfig(
    interfaces=[
        cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.95.1"), cyst_cfg.IPNetwork("192.168.95.0/24"), index=2),
        cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("192.168.94.1"), cyst_cfg.IPNetwork("192.168.94.0/24"), index=3),
    ],
    routing_table=[
        # Push everything not-infrastructure to the internet
        RouteConfig(cyst_cfg.IPNetwork("0.0.0.0/0"), 10)
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
                    cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.95.0/24"), cyst_cfg.IPNetwork("192.168.95.1/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                    cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.0/24"), cyst_cfg.IPNetwork("192.168.94.1/32"), "*", cyst_cfg.FirewallPolicy.ALLOW)
                ]
              ),
              cyst_cfg.FirewallChainConfig(
                  type=cyst_cfg.FirewallChainType.FORWARD,
                  policy=cyst_cfg.FirewallPolicy.DENY,
                  rules=[
                      # Client 1 can go to server 1, 2, 3
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.2/32"), cyst_cfg.IPNetwork("192.168.95.2/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.2/32"), cyst_cfg.IPNetwork("192.168.95.3/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.2/32"), cyst_cfg.IPNetwork("192.168.95.4/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      # Client 2 can go to server 1, 2, 3
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.3/32"), cyst_cfg.IPNetwork("192.168.95.2/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.3/32"), cyst_cfg.IPNetwork("192.168.95.3/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.3/32"), cyst_cfg.IPNetwork("192.168.95.4/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      # Client 3 can go to server 1, 2, 3
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.4/32"), cyst_cfg.IPNetwork("192.168.95.2/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.4/32"), cyst_cfg.IPNetwork("192.168.95.3/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.4/32"), cyst_cfg.IPNetwork("192.168.95.4/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      # Client 4 can go to server 1, 2, 3
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.5/32"), cyst_cfg.IPNetwork("192.168.95.2/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.5/32"), cyst_cfg.IPNetwork("192.168.95.3/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.5/32"), cyst_cfg.IPNetwork("192.168.95.4/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      # Client 5 can go to server 1, 2, 3
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.6/32"), cyst_cfg.IPNetwork("192.168.95.2/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.6/32"), cyst_cfg.IPNetwork("192.168.95.3/32"), "*", cyst_cfg.FirewallPolicy.ALLOW),
                      cyst_cfg.FirewallRule(cyst_cfg.IPNetwork("192.168.94.6/32"), cyst_cfg.IPNetwork("192.168.95.4/32"), "*", cyst_cfg.FirewallPolicy.ALLOW)
                  ]
              )
          ]
        )
    ],
    id="router1"
)

''' --------------------------------------------------------------------------------------------------------------------
Internet

- Represented as a router outside the scenario network 192.168.0.0
'''
internet = cyst_cfg.RouterConfig(
    interfaces=[
        cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("54.123.53.28"), cyst_cfg.IPNetwork("54.123.53.29/26"), index=0)
    ],
    routing_table=[
        RouteConfig(cyst_cfg.IPNetwork("192.168.0.0/16"), 0)
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
            name="bash",
            owner="root",
            version="5.0.0",
            local=True,
            access_level=cyst_cfg.AccessLevel.LIMITED
        ),
        cyst_cfg.PassiveServiceConfig(
            name="listener",
            owner="attacker",
            version="1.0.0",
            local=False,
            access_level=cyst_cfg.AccessLevel.ELEVATED
        )
    ],
    traffic_processors=[],
    interfaces=[cyst_cfg.InterfaceConfig(cyst_cfg.IPAddress("101.32.5.23"), cyst_cfg.IPNetwork("54.123.53.29/26"))],
    shell="bash",
    id="outside_node"
)

''' --------------------------------------------------------------------------------------------------------------------
Connections
'''
connections = [
    cyst_cfg.ConnectionConfig("smb_server", 0, "router1", 0),
    cyst_cfg.ConnectionConfig("db_server", 0, "router1", 1),
    cyst_cfg.ConnectionConfig("web_server", 0, "router1", 2),
    cyst_cfg.ConnectionConfig("other_server_1", 0, "router1", 3),
    cyst_cfg.ConnectionConfig("other_server_2", 0, "router1", 4),
    cyst_cfg.ConnectionConfig("client_1", 0, "router1", 5),
    cyst_cfg.ConnectionConfig("client_2", 0, "router1", 6),
    cyst_cfg.ConnectionConfig("client_3", 0, "router1", 7),
    cyst_cfg.ConnectionConfig("client_4", 0, "router1", 8),
    cyst_cfg.ConnectionConfig("client_5", 0, "router1", 9),
    cyst_cfg.ConnectionConfig("internet", 0, "router1", 10),
    cyst_cfg.ConnectionConfig("internet", 1, "outside_node", 0)
]

''' --------------------------------------------------------------------------------------------------------------------
Exploits
- There exists only one for windows lanman server (SMB) and enables data exfiltration. Add others as needed...
'''
exploits = [
    ExploitConfig(
        services=[
            VulnerableServiceConfig(
                service="445/tcp, microsoft-ds",
                min_version="10.0. 19041",
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
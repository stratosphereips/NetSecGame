try:
    # Attempt to import server-specific dependencies
    # disable ruff error F401 for unused imports (used for dependency checking)
    import cyst # noqa: F401
    import aiohttp # noqa: F401
    import faker # noqa: F401
    import numpy as np # noqa: F401
    import requests # noqa: F401 

    # from .coordinator import AgentServer, GameCoordinator
    # from .worlds.NetSecGame import NetSecGame
    # from .worlds.WhiteBoxNetSecGame import WhiteBoxNetSecGame

    # __all__ = [
    #     'AgentServer',
    #     'GameCoordinator',
    #     'NetSecGame',
    #     'WhiteBoxNetSecGame'
    # ]
except ImportError as e:
    raise ImportError(
        f"Failed to import 'netsecgame.game'. This module requires server dependencies.\n"
        f"Missing dependency: {e.name}\n"
        f"Please install them using: pip install 'netsecgame[server]'"
    ) from None
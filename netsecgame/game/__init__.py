try:
    # Attempt to import server-specific dependencies
    # disable ruff error F401 for unused imports (used for dependency checking)
    import cyst # noqa: F401
    import aiohttp # noqa: F401
    import faker # noqa: F401
    import numpy as np # noqa: F401
    import requests # noqa: F401 
except ImportError as e:
    # If any server-specific dependency is missing, raise an informative error
    # Surpress the context of the original ImportError
    raise ImportError(
        f"Failed to import 'netsecgame.game'. This module requires server dependencies.\n"
        f"Missing dependency: {e.name}\n"
        f"Please install them using: pip install 'netsecgame[server]'"
    ) from None
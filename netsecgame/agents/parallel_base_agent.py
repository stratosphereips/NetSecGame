# Author: Ondrej Lukas, ondrej.lukas@aic.cvut.cz
# Parallel agent class that manages connections to multiple game server instances simultaneously.
import logging
import socket
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Tuple, Dict, Any, List, Callable

from netsecgame.game_components import (
    Action, GameState, Observation, ActionType,
    GameStatus, AgentInfo, ProtocolConfig, AgentRole,
)


class ParallelBaseAgent:
    """
    Agent that manages connections to multiple NetSecGame server instances
    simultaneously, enabling parallel environment interaction.

    Unlike BaseAgent (which manages a single socket), this class maintains
    one TCP socket per environment and exposes vectorized versions of
    ``register()``, ``make_step()``, and ``request_game_reset()`` that
    operate on lists of actions/observations.

    For a concrete example of extending and using this class, 
    see ``examples/agents/random_attacker.py``.

    Args:
        game_hosts: Host address(es). A single string is broadcast to all
            ``game_ports``. A list must either have length 1 (broadcast)
            or match the length of ``game_ports``.
        game_ports: Port(s) — one per environment instance. A single int
            creates a one-environment agent.
        role: The agent role shared across all environments.
        max_workers: Maximum threads in the pool. Defaults to ``len(game_ports)``.
    """

    def __init__(
        self,
        game_hosts: str | List[str],
        game_ports: int | List[int],
        role: AgentRole,
        max_workers: Optional[int] = None,
    ) -> None:
        # ------------------------------------------------------------------
        # Normalize scalars to lists
        # ------------------------------------------------------------------
        if isinstance(game_hosts, str):
            game_hosts = [game_hosts]
        if isinstance(game_ports, int):
            game_ports = [game_ports]

        # ------------------------------------------------------------------
        # Validate & broadcast hosts
        # ------------------------------------------------------------------
        if len(game_hosts) == 1 and len(game_ports) > 1:
            game_hosts = game_hosts * len(game_ports)
        elif len(game_hosts) != len(game_ports):
            raise ValueError(
                f"game_hosts length ({len(game_hosts)}) must be 1 "
                f"(broadcast) or match game_ports length ({len(game_ports)})"
            )
        # make sure port numbers are integers
        game_ports = [int(port) for port in game_ports]
        

        self._envs: List[Tuple[str, int]] = list(zip(game_hosts, game_ports))
        self._num_envs: int = len(self._envs)
        self._single_env: bool = self._num_envs == 1
        self._role: AgentRole = role
        self._logger: logging.Logger = logging.getLogger(self.__class__.__name__)

        # ------------------------------------------------------------------
        # Open one TCP socket per environment
        # ------------------------------------------------------------------
        self._sockets: List[Optional[socket.socket]] = []
        for host, port in self._envs:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
                self._sockets.append(sock)
                self._logger.info(f"Connected to {host}:{port}")
            except socket.error as e:
                self._logger.warning(f"Failed to connect to {host}:{port}: {e}")
                self._sockets.append(None)

        # ------------------------------------------------------------------
        # Done mask & thread pool
        # ------------------------------------------------------------------
        self._done_mask: List[bool] = [s is None for s in self._sockets]
        self._executor: ThreadPoolExecutor = ThreadPoolExecutor(
            max_workers=max_workers or self._num_envs
        )
        self._logger.info(
            f"ParallelBaseAgent created with {self._num_envs} environments "
            f"({sum(self.connected)} connected)"
        )

    # ======================================================================
    # Lifecycle
    # ======================================================================

    def __del__(self) -> None:
        """Close any remaining sockets and shut down the thread pool when the
        object is garbage-collected."""
        self.terminate_connection()

    def terminate_connection(self) -> None:
        """Close all sockets and shut down the thread pool."""
        if hasattr(self, '_sockets'):
            for i, sock in enumerate(self._sockets):
                if sock is not None:
                    try:
                        sock.close()
                        self._logger.info(f"Socket for env {i} ({self._envs[i]}) closed")
                    except socket.error as e:
                        self._logger.error(
                            f"Error closing socket for env {i} ({self._envs[i]}): {e}"
                        )
                    self._sockets[i] = None
        if hasattr(self, '_executor'):
            try:
                self._executor.shutdown(wait=False)
            except Exception:
                pass

    # ======================================================================
    # Properties
    # ======================================================================

    @property
    def num_envs(self) -> int:
        """Number of environments (always equals ``len(game_ports)``)."""
        return self._num_envs

    @property
    def done_mask(self) -> "bool | List[bool]":
        """Current done mask. A single ``bool`` in single-env mode,
        otherwise a list of bools (one per env)."""
        if self._single_env:
            return self._done_mask[0]
        return list(self._done_mask)

    @property
    def all_done(self) -> bool:
        """``True`` when every episode has ended."""
        return all(self._done_mask)

    @property
    def connected(self) -> List[bool]:
        """Per-environment connection status."""
        return [s is not None for s in self._sockets]

    @property
    def role(self) -> AgentRole:
        return self._role

    @property
    def logger(self) -> logging.Logger:
        """Returns the logger instance for this agent."""
        return self._logger

    # ======================================================================
    # Private: per-environment communication
    # ======================================================================

    @staticmethod
    def _send_data(sock: socket.socket, msg: str, logger: logging.Logger) -> None:
        """Send a JSON-encoded message over *sock*."""
        logger.debug(f"Sending: {msg}")
        sock.sendall(msg.encode())

    @staticmethod
    def _receive_data(
        sock: socket.socket, logger: logging.Logger
    ) -> Tuple[GameStatus, Dict[str, Any], Optional[str]]:
        """Block until a full response is received from *sock*."""
        data = b""
        while True:
            chunk = sock.recv(ProtocolConfig.BUFFER_SIZE)
            if not chunk:
                break
            data += chunk
            if ProtocolConfig.END_OF_MESSAGE in data:
                break
        if ProtocolConfig.END_OF_MESSAGE not in data:
            raise ConnectionError("Unfinished connection.")
        data = data.replace(ProtocolConfig.END_OF_MESSAGE, b"").decode()
        logger.debug(f"Received: {data}")
        data_dict = json.loads(data)
        status = data_dict.get("status", "")
        observation = data_dict.get("observation", {})
        message = data_dict.get("message", None)
        return GameStatus.from_string(str(status)), observation, message

    def _communicate_single(
        self, env_idx: int, action: Action
    ) -> Tuple[GameStatus, Dict[str, Any], Optional[str]]:
        """Send *action* to environment *env_idx* and return the response."""
        sock = self._sockets[env_idx]
        if sock is None:
            raise ConnectionError(f"Socket for env {env_idx} is not connected.")
        if not isinstance(action, Action):
            raise ValueError("Data should be ONLY of type Action")
        self._send_data(sock, action.to_json(), self._logger)
        return self._receive_data(sock, self._logger)

    # ------------------------------------------------------------------
    # Single-env operations (run inside worker threads)
    # ------------------------------------------------------------------

    def _register_single(self, env_idx: int) -> Optional[Observation]:
        """Register on a single environment."""
        try:
            status, obs_dict, message = self._communicate_single(
                env_idx,
                Action(
                    ActionType.JoinGame,
                    parameters={
                        "agent_info": AgentInfo(
                            self.__class__.__name__, self._role.value
                        )
                    },
                ),
            )
            if status is GameStatus.CREATED:
                self._logger.info(
                    f"Env {env_idx}: registration successful! {message}"
                )
                return Observation(
                    GameState.from_dict(obs_dict["state"]),
                    obs_dict["reward"],
                    obs_dict["end"],
                    message,
                )
            else:
                self._logger.error(
                    f"Env {env_idx}: registration failed "
                    f"(status: {status}, msg: {message})"
                )
                return None
        except Exception as e:
            self._logger.error(f"Env {env_idx}: exception in register: {e}")
            return None

    def _make_step_single(
        self, env_idx: int, action: Action
    ) -> Optional[Observation]:
        """Execute a single step on one environment."""
        try:
            _, obs_dict, _ = self._communicate_single(env_idx, action)
            if obs_dict:
                return Observation(
                    GameState.from_dict(obs_dict["state"]),
                    obs_dict["reward"],
                    obs_dict["end"],
                    obs_dict["info"],
                )
            return None
        except Exception as e:
            self._logger.error(f"Env {env_idx}: exception in make_step: {e}")
            return None

    def _request_game_reset_single(
        self,
        env_idx: int,
        request_trajectory: bool,
        randomize_topology: bool,
        seed: Optional[int],
    ) -> Optional[Observation]:
        """Reset a single environment."""
        try:
            status, obs_dict, message = self._communicate_single(
                env_idx,
                Action(
                    ActionType.ResetGame,
                    parameters={
                        "request_trajectory": request_trajectory,
                        "randomize_topology": randomize_topology,
                        "seed": seed,
                    },
                ),
            )
            if status is GameStatus.RESET_DONE:
                self._logger.debug(f"Env {env_idx}: reset successful")
                return Observation(
                    GameState.from_dict(obs_dict["state"]),
                    obs_dict["reward"],
                    obs_dict["end"],
                    message,
                )
            else:
                self._logger.error(
                    f"Env {env_idx}: reset failed "
                    f"(status: {status}, msg: {message})"
                )
                return None
        except Exception as e:
            self._logger.error(
                f"Env {env_idx}: exception in request_game_reset: {e}"
            )
            return None

    # ======================================================================
    # Private: parallel dispatch helper
    # ======================================================================

    def _run_parallel(
        self,
        fn: Callable[[int, ...], Any],
        env_indices: Optional[List[int]] = None,
        *,
        args_per_env: Optional[Dict[int, tuple]] = None,
    ) -> List[Any]:
        """Submit *fn(env_idx, ...)* for each index and collect results in
        order.

        Args:
            fn: Callable whose first argument is the environment index.
            env_indices: Which envs to dispatch to. Defaults to all connected
                envs.
            args_per_env: Optional extra positional args per env index.

        Returns:
            List of results, one per ``self._num_envs``. Indices not included in *env_indices* get ``None``.
        """
        if env_indices is None:
            env_indices = [i for i in range(self._num_envs) if self._sockets[i] is not None]
        if args_per_env is None:
            args_per_env = {}

        results: List[Any] = [None] * self._num_envs

        # Fast path: skip the thread pool when there is only one env to call
        if len(env_indices) == 1:
            i = env_indices[0]
            extra = args_per_env.get(i, ())
            try:
                results[i] = fn(i, *extra)
            except Exception as e:
                self._logger.error(f"Env {i}: unhandled exception: {e}")
                results[i] = None
            return results

        future_to_idx = {}
        for i in env_indices:
            extra = args_per_env.get(i, ())
            future = self._executor.submit(fn, i, *extra)
            future_to_idx[future] = i

        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as e:
                self._logger.error(f"Env {idx}: unhandled exception: {e}")
                results[idx] = None

        return results

    # ======================================================================
    # Public API
    # ======================================================================

    def register(self) -> "Observation | None | List[Optional[Observation]]":
        """Register in all connected environments in parallel.

        Returns:
            The initial ``Observation`` (or ``None``) in single-env mode, or a list of initial observations positionally aligned with ``game_ports`` in multi-env mode.
        """
        results = self._run_parallel(self._register_single)
        # Re-initialise done mask: failed envs stay done
        self._done_mask = [r is None for r in results]
        if self._single_env:
            return results[0]
        return results

    def make_step(
        self, actions: "Action | List[Action]"
    ) -> "Observation | None | List[Optional[Observation]]":
        """Execute one step in every **active** environment in parallel.

        *Note: If you need to access the boolean done statuses across
        all environments, you can use the `self.done_mask` property.*

        Args:
            actions: In single-env mode a single ``Action``; in multi-env
                mode a list of ``Action`` objects (one per environment).
                Actions at indices where the done mask is ``True`` are
                **ignored** (no message is sent to that env).

        Returns:
            A single ``Observation | None`` in single-env mode, or a list of observations positionally aligned with ``game_ports`` in multi-env mode.

        Raises:
            ValueError: If the number of actions doesn't match ``num_envs``.
        """
        # Normalise single action to list
        if self._single_env and isinstance(actions, Action):
            actions = [actions]
        if len(actions) != self._num_envs:
            raise ValueError(
                f"Expected {self._num_envs} actions, got {len(actions)}"
            )

        # Only dispatch to envs that are still active
        active = [i for i in range(self._num_envs) if not self._done_mask[i]]
        args = {i: (actions[i],) for i in active}

        results = self._run_parallel(
            self._make_step_single, active, args_per_env=args
        )

        # Update done mask
        for i in active:
            obs = results[i]
            if obs is None:
                # Communication failure → mark as done
                self._done_mask[i] = True
            elif obs.end:
                self._done_mask[i] = True

        if self._single_env:
            return results[0]
        return results

    def request_game_reset(
        self,
        request_trajectory: bool = False,
        randomize_topology: bool = False,
        seed: Optional[int] = None,
    ) -> "Observation | None | List[Optional[Observation]]":
        """Reset all environments in parallel.

        Args:
            request_trajectory: If True, request episode trajectory from
                the server.
            randomize_topology: If True, randomize the network topology.
            seed: RNG seed. Required when ``randomize_topology`` is True.

        Returns:
            The initial ``Observation`` (or ``None``) in single-env mode, or a list of initial observations positionally aligned with ``game_ports`` in multi-env mode.
        """
        if seed is None and randomize_topology:
            raise ValueError(
                "Topology randomization without seed is not supported."
            )

        # Reset every env that still has a socket (even done ones)
        connected = [i for i in range(self._num_envs) if self._sockets[i] is not None]
        args = {
            i: (request_trajectory, randomize_topology, seed) for i in connected
        }
        results = self._run_parallel(
            self._request_game_reset_single, connected, args_per_env=args
        )

        # Clear the done mask for successfully reset envs
        self._done_mask = [results[i] is None for i in range(self._num_envs)]
        if self._single_env:
            return results[0]
        return results

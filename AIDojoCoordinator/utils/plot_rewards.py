import argparse
import os
import re
from typing import List, Tuple



def parse_rewards(path: str) -> List[float]:
    """Parse reward values from a text file.

    Expects lines ending with a numeric value, e.g.,
    "[+] Reward of last action (after reward engineering): -1"

    Returns a list of floats in the order they appear.
    Lines without a trailing number are ignored.
    """
    rewards: List[float] = []
    trailing_number = re.compile(r"(-?\d+(?:\.\d+)?)\s*$")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = trailing_number.search(line)
            if m:
                try:
                    rewards.append(float(m.group(1)))
                except ValueError:
                    # Ignore lines that cannot be parsed into a float
                    continue
    return rewards


def compute_episode_outcomes(
    rewards: List[float],
    episode_length: int = 100,
    win_reward: float = 1000.0,
    include_incomplete_final: bool = False,
) -> Tuple[List[int], List[int]]:
    """Compute episode outcomes and episode end indices.

    Rules:
    - An episode starts at the first line and continues sequentially.
    - If a reward == win_reward is encountered, the episode ends (win=1).
    - If no win is encountered within `episode_length` steps, the episode ends (win=0).
    - If the file ends with a partial episode (< episode_length, no win), it's excluded by default.
      Set `include_incomplete_final=True` to include it as a loss.

    Returns:
    - wins: list of 1/0 per episode (1=win, 0=loss)
    - episode_end_indices: global step index (0-based) where each episode ends
    """
    wins: List[int] = []
    episode_end_indices: List[int] = []

    steps_in_episode = 0

    for i, r in enumerate(rewards):
        steps_in_episode += 1
        if r == win_reward:
            wins.append(1)
            episode_end_indices.append(i)
            steps_in_episode = 0
        elif steps_in_episode >= episode_length:
            wins.append(0)
            episode_end_indices.append(i)
            steps_in_episode = 0

    # Handle incomplete final episode (optional)
    if steps_in_episode > 0 and include_incomplete_final:
        wins.append(0)
        episode_end_indices.append(len(rewards) - 1)

    return wins, episode_end_indices


def running_win_rate(wins: List[int]) -> List[float]:
    """Compute running average of wins across episodes."""
    rates: List[float] = []
    cum = 0
    for i, w in enumerate(wins, start=1):
        cum += w
        rates.append(cum / i)
    return rates


def plot_rewards_and_winrate(
    rewards: List[float],
    wins: List[int],
    win_rates: List[float],
    episode_end_indices: List[int],
    show_boundaries: bool = False,
    save_path: str | None = None,
    dpi: int = 150,
) -> None:
    """Create two scatter plots: rewards over steps, and running win-rate over episodes."""
    # Local import so non-plot helpers can be used without matplotlib installed
    # Use non-interactive backend if saving or no display is present
    import matplotlib
    if save_path is not None or not os.environ.get("DISPLAY"):
        try:
            matplotlib.use("Agg")
        except Exception:
            pass
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(14, 5), constrained_layout=True)

    # Plot 1: scatter of reward values
    ax0 = axes[0]
    ax0.scatter(range(len(rewards)), rewards, s=8, alpha=0.7)
    ax0.set_title("Rewards per Step")
    ax0.set_xlabel("Step")
    ax0.set_ylabel("Reward")

    if show_boundaries and episode_end_indices:
        for idx in episode_end_indices:
            ax0.axvline(idx, color="gray", alpha=0.15, linewidth=0.8)

    # Plot 2: running win-rate
    ax1 = axes[1]
    ax1.scatter(range(1, len(win_rates) + 1), win_rates, s=14, alpha=0.8, color="tab:green")
    ax1.set_title("Running Win-Rate (per Episode)")
    ax1.set_xlabel("Episode")
    ax1.set_ylabel("Win-Rate")
    ax1.set_ylim(-0.05, 1.05)

    if save_path:
        fig.savefig(save_path, dpi=dpi)
    else:
        plt.show()


def main():
    parser = argparse.ArgumentParser(description="Plot rewards scatter and running win-rate.")
    parser.add_argument(
        "--file",
        "-f",
        default="rewards.txt",
        help="Path to rewards log file (default: rewards.txt)",
    )
    parser.add_argument(
        "--episode-length",
        "-N",
        type=int,
        default=100,
        help="Max steps per episode if no win occurs (default: 100)",
    )
    parser.add_argument(
        "--win-reward",
        type=float,
        default=1000.0,
        help="Reward value that marks a win and ends the episode (default: 1000)",
    )
    parser.add_argument(
        "--include-incomplete",
        action="store_true",
        help="Include the final partial episode (if any) as a loss.",
    )
    parser.add_argument(
        "--show-boundaries",
        action="store_true",
        help="Overlay vertical lines at episode boundaries on the rewards plot.",
    )
    parser.add_argument(
        "--save",
        metavar="PATH",
        help="Save plots to the given file path (e.g., plots.png) instead of showing.",
    )
    parser.add_argument(
        "--dpi",
        type=int,
        default=150,
        help="DPI for saved figure (default: 150)",
    )

    args = parser.parse_args()

    rewards = parse_rewards(args.file)
    if not rewards:
        raise SystemExit(f"No rewards parsed from {args.file}. Check the file format.")

    wins, episode_ends = compute_episode_outcomes(
        rewards,
        episode_length=args.episode_length,
        win_reward=args.win_reward,
        include_incomplete_final=args.include_incomplete,
    )

    win_rates = running_win_rate(wins)

    # Console summary
    total_steps = len(rewards)
    total_episodes = len(wins)
    total_wins = sum(wins)
    final_win_rate = win_rates[-1] if win_rates else 0.0
    print(
        f"Parsed {total_steps} steps → {total_episodes} episodes, "
        f"wins={total_wins} (final win-rate={final_win_rate:.3f})."
    )

    plot_rewards_and_winrate(
        rewards,
        wins,
        win_rates,
        episode_ends,
        show_boundaries=args.show_boundaries,
        save_path=args.save,
        dpi=args.dpi,
    )


if __name__ == "__main__":
    main()

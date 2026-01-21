import argparse
import re
from pathlib import Path

import matplotlib.pyplot as plt


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compute running win rate per episode from a conceptual_q_agent.log "
            "without loading the whole file into memory."
        )
    )
    parser.add_argument(
        "--log-path",
        required=True,
        help="Path to conceptual_q_agent.log",
    )
    parser.add_argument(
        "--output",
        default="win_rate_over_episodes.png",
        help="Output PNG filename for the running win rate plot "
             "(default: win_rate_over_episodes.png).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    log_path = Path(args.log_path)

    if not log_path.is_file():
        raise SystemExit(f"Log file not found: {log_path}")

    # We only care about the raw environment reward, which is logged in the
    # 'State after action:Observation(...)' line, not the engineered reward.
    state_prefix = "[+] State after action:Observation"
    reward_pattern = re.compile(r"reward=(?P<reward>-?\d+), end=(?P<end>\w+)")

    episodes = 0
    wins = 0
    running_win_rates = []
    winrate_log_path = Path(args.output).with_suffix(".log")

    with log_path.open("r", encoding="utf-8", errors="ignore") as f, winrate_log_path.open(
        "w", encoding="utf-8"
    ) as wr_log:
        # Optional header for easier parsing later
        wr_log.write("episode,win_rate,final_reward\n")

        for line in f:
            if state_prefix not in line:
                continue

            match = reward_pattern.search(line)
            if not match:
                continue

            reward = int(match.group("reward"))
            end_flag = match.group("end") == "True"

            # We only care about terminal transitions with the special rewards.
            if not end_flag:
                continue
            if reward not in (-11, 99):
                continue

            episodes += 1
            if reward == 99:
                wins += 1

            win_rate = wins / episodes
            running_win_rates.append(win_rate)
            wr_log.write(f"{episodes},{win_rate:.6f},{reward}\n")
            print(
                f"Episode {episodes}: final reward={reward}, "
                f"running win rate={win_rate:.4f}"
            )

    if not running_win_rates:
        print("No completed episodes with reward 99 or -11 were found in the log.")
        return

    # Plot running win rate as it evolves with episodes.
    x = list(range(1, len(running_win_rates) + 1))
    plt.figure(figsize=(10, 5))
    plt.plot(x, running_win_rates, linewidth=1.0)
    plt.xlabel("Episode")
    plt.ylabel("Running win rate")
    plt.ylim(0.0, 1.0)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(args.output, dpi=150)
    print(f"Saved win-rate plot to: {args.output}")
    print(f"Saved win-rate log to: {winrate_log_path}")


if __name__ == "__main__":
    main()

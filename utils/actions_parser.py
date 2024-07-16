# Actions log file parser for the NetSecGame environment log
# The parse will go through the log file and extract
# of the actions taken per episode.
# Author: Harpo MAxx (harpomaxx@gmail.com)

import re
import csv
import argparse


def parse_actions_taken(filename):
    with open(filename, "r") as file:
        lines = file.readlines()

    all_actions = []
    current_episode_actions = []
    episode_number = 0  # To track episode numbers
    action_number = 0  # To track action numbers within an episode

    for line in lines:
        if "Agent's action" in line:
            print(episode_number, end=" ")
            print(line)
            # Extract the action type using regular expression
            match_action = re.search(r"Action <(ActionType\.[^|]+)", line)
            # Extract either target_host or target_network, if present
            match_target = re.search(
                r"'target_host': ([^,]+)|'target_network': ([^,]+)", line
            )
            match_source = re.search(r"'source_host': ([^,]+)", line)

            if match_action and (match_target or match_source):
                action_type = match_action.group(1)

                if match_source:
                    target = match_source.group(1) or match_source.group(2)
                    target = target.strip("'")
                elif match_target:
                    target = match_target.group(1) or match_target.group(2)
                    target = target.strip("'")

                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", target)
                target = match.group(1)
                action_number += 1
                current_action_data = {
                    "episode": episode_number,
                    "action_number": action_number,
                    "action_type": action_type,
                    "target": target,
                }
                current_episode_actions.append(current_action_data)
        elif "episode " in line:
            all_actions.extend(current_episode_actions)
            current_episode_actions = []
            episode_number += 1
            action_number = 0  # Reset action number for next episode

    # In case the log file doesn't end with "Episode ended", add the remaining actions
    if current_episode_actions:
        all_actions.extend(current_episode_actions)

    return all_actions


def write_actions_to_csv(actions, output_filename):
    with open(output_filename, "w", newline="") as csvfile:
        fieldnames = ["episode", "action_number", "action_type", "target"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()  # Writes the header

        for action in actions:
            writer.writerow(action)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--file_name",
        type=str,
        default="netsecenv.log",
        help="Path of the log file",
        required=True,
    )
    parser.add_argument(
        "--csv_file_name",
        type=str,
        default="actions.csv",
        help="Path of the actions file in CSV format",
        required=False,
    )
    args = parser.parse_args()

    actions_data = parse_actions_taken(args.file_name)
    write_actions_to_csv(actions_data, args.csv_file_name)

    # log_file = "netsecenv.log.bignodefence"
    # log_file = "netsecenv_gpt4_small_no_def.log"
    # csv_file = "output.csv"

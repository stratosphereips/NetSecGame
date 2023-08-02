import numpy as np
import argparse

def calculate_episode_lengths(step_seq):
    episode_lengths = []
    for i in range(1, len(step_seq)):
        if step_seq[i] == 0:
            # If the step is zero then it's a new episode
            # Take the last value as episode length
            episode_lengths.append(step_seq[i-1]+1)
    episode_lengths.append(step_seq[-1])
    return episode_lengths

def reached_limit(current_step, max_steps, invalid_steps):
    if (invalid_steps + current_step) >= max_steps + 20:
        return True
    elif current_step == max_steps:
        return True
    return False
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--file_name", type=str, default="netsecenv.log", help="Path of the file to be processed")
    parser.add_argument("--max_steps", type=int, default=100, help="The max steps for statistics calculation")
    args = parser.parse_args()


    with open(args.file_name, 'r') as f:
        data = f.readlines()

    start_str = "--- Reseting env to its initial state ---"
    win_str = "Goal reached?: True"
    step_str = "Step taken: "
    detected_str = "Action detected?: True"
    iteration_str = "Iteration: "

    # Statistics
    episode_starts = []
    win_lengths = []
    detected_lengths = []
    step_seq = []
    rewards = []
    total_detected = 0
    total_wins = 0

    # Per episode counters
    invalid = 0
    stop_until_new = False
    add_max_reward = False
    latest_step = 0

    for i, line in enumerate(data):
        # Check if the episode starts and initialize the counters
        if start_str in line:
            episode_starts.append(i)
            stop_until_new = False
            latest_step = 0
            invalid = 0
            if add_max_reward:
                rewards.append(-args.max_steps)
            add_max_reward = False


        # Check if the line contains the env step
        if step_str in line:
            latest_step = int(line.strip().split(" ")[-1])
            if not stop_until_new:
                step_seq.append(latest_step)
        
        # Check if the line contains the agent iteration
        if iteration_str in line and not stop_until_new:            
            parts = line.strip().split(" ")
            iteration = parts[5]
            if parts[7] == 'False':
                invalid += 1

        # Check if the goal is reached
        if win_str in line and latest_step < args.max_steps:
            total_wins += 1
            win_lengths.append(step_seq[-1] + 1)
            rewards.append(100-(step_seq[-1] + 1))
            add_max_reward = False
            stop_until_new = True

        # Check if the agent was detected
        if detected_str in line and not stop_until_new:
            detected_lengths.append(step_seq[-1] + 1)
            total_detected += 1
            rewards.append(-args.max_steps)
            add_max_reward = False
            stop_until_new = True

        # Check if we need to stop because of max steps or invalid steps
        if not stop_until_new:
            stop_until_new = reached_limit(latest_step+1, args.max_steps, invalid)
            if stop_until_new:
                # print("here")
                # rewards.append(-args.max_steps)
                add_max_reward = True
            
    print(f"Episodes: {len(episode_starts)}")
    print(f"Wins: {total_wins}")
    print(f"Win rate: {100*total_wins/len(episode_starts)}%")
    print(f"Detected: {total_detected}")
    print(f"Detection rate: {100*total_detected/len(episode_starts)}%")
    print(f"Average rewards: {np.mean(rewards)} +- {np.std(rewards)}")

    episode_lengths = calculate_episode_lengths(step_seq)
    print(f"Average episode length: {np.mean(episode_lengths)} +- {np.std(episode_lengths)}")
    print(f"Average win length: {np.mean(win_lengths)} +- {np.std(win_lengths)}")
    print(f"Average detected length: {np.mean(detected_lengths)} +- {np.std(detected_lengths)}")
    assert len(rewards) == len(episode_starts)
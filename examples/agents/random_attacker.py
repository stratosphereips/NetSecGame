# Author: Ondrej Lukas, ondrej.lukas@aic.cvut.cz
# This agent is an example of an attacker agent that plays the NetSecGame
# using random actions. It is intended to be used as a baseline for
# evaluating the performance of other agents.
# It can be used both with single environment, and with multiple simultaneous environments.

import logging
import argparse
import numpy as np
from os import path, makedirs
import random
from netsecgame import Action, Observation, generate_valid_actions, AgentRole
from netsecgame.agents.parallel_base_agent import ParallelBaseAgent
from netsecgame.game_components import AgentStatus

class RandomAttackerAgent(ParallelBaseAgent):
    """
    An attacker agent that selects actions randomly without learning.
    Inherits from ParallelBaseAgent.
    """

    def __init__(self, host, port, role, seed) -> None:
        """
        Initialize the RandomAttackerAgent.
        
        Args:
            host (str): Host address to connect to.
            port (int | list[int]): Port number(s) to connect to.
            role (AgentRole): The role of the agent (e.g., AgentRole.Attacker).
            seed (int): Seed for random number generation for the agent's decisions.
        """
        super().__init__(host, port, role)
        self.rng = random.Random(seed)

    def select_action(self, observation: Observation) -> Action:
        """
        Selects a random action from the set of valid actions in the current state.
        
        Args:
            observation (Observation): The current observation including the game state.
            
        Returns:
            Action: The randomly selected action.
        """
        valid_actions = sorted(generate_valid_actions(observation.state), key=lambda x: str(x))
        # randomly choose with the seeded rng
        action = self.rng.choice(valid_actions)
        return action

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", help="Host(s) where the game server is", default="127.0.0.1",
                    type=str, nargs="+", required=False)
    parser.add_argument("--port", help="Port(s) where the game server is",
                    default=[9000], type=int, nargs='+', required=False)
    parser.add_argument("--episodes", help="Sets number of episodes to play", default=100, type=int)
    parser.add_argument("--seed", help="Sets random seed for agent's decisions", default=42, type=int) 
    parser.add_argument("--logdir", help="Folder to store logs", default=path.join(path.dirname(path.abspath(__file__)), "logs"))
    args = parser.parse_args()

    if not path.exists(args.logdir):
        makedirs(args.logdir)
    logging.basicConfig(filename=path.join(args.logdir, "random_agent.log"), filemode='w', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.INFO)

    # Create agent
    agent = RandomAttackerAgent(args.host, args.port, AgentRole.Attacker, seed=args.seed)
    num_envs = agent.num_envs
    
    # Register in the game
    observations = agent.register()
    observations = agent.request_game_reset(randomize_topology=False)

    # Ensure observations is always a list for uniform handling
    if num_envs == 1:
        observations = [observations]

    # To keep statistics of each episode
    wins = 0
    detected = 0
    max_steps = 0
    num_win_steps = []
    num_detected_steps = []
    num_max_steps_steps = []
    num_detected_returns = []
    num_win_returns = []
    num_max_steps_returns = []

    # To keep statistics per env
    wins_env = [0] * num_envs
    detected_env = [0] * num_envs
    max_steps_env = [0] * num_envs
    num_win_steps_env = [[] for _ in range(num_envs)]
    num_detected_steps_env = [[] for _ in range(num_envs)]
    num_max_steps_steps_env = [[] for _ in range(num_envs)]
    num_detected_returns_env = [[] for _ in range(num_envs)]
    num_win_returns_env = [[] for _ in range(num_envs)]
    num_max_steps_returns_env = [[] for _ in range(num_envs)]

    for episode in range(1, args.episodes + 1):
        agent.logger.info(f'Starting episode {episode}')
        print(f'Starting episode {episode}')

        # Per-env tracking for this episode
        episodic_returns = [[] for _ in range(num_envs)]
        num_steps = [0] * num_envs

        # Play the game until all envs are done
        while not agent.all_done:
            # Select an action for each active env
            actions = []
            done_mask = agent.done_mask if num_envs > 1 else [agent.done_mask]
            for i in range(num_envs):
                if not done_mask[i]:
                    obs = observations[i]
                    episodic_returns[i].append(obs.reward)
                    num_steps[i] += 1
                    actions.append(agent.select_action(obs))
                else:
                    # Placeholder action for done envs (will be ignored)
                    actions.append(Action(action_type=agent.select_action(observations[0]).action_type))

            # Step all envs
            new_observations = agent.make_step(actions)
            if num_envs == 1:
                new_observations = [new_observations]

            # Update observations for active envs
            for i in range(num_envs):
                if new_observations[i] is not None:
                    observations[i] = new_observations[i]

        # Episode finished — collect stats per env
        for i in range(num_envs):
            obs = observations[i]
            agent.logger.debug(f'Env {i} final observation: {obs}')
            current_return = np.sum(episodic_returns[i])
            reward = current_return

            agent.logger.info(f"Episode {episode}, Env {i}: ended with return {current_return}.")

            if obs.info and obs.info.get('end_reason') == AgentStatus.Fail:
                detected += 1
                detected_env[i] += 1
                num_detected_steps.append(num_steps[i])
                num_detected_steps_env[i].append(num_steps[i])
                num_detected_returns.append(reward)
                num_detected_returns_env[i].append(reward)
            elif obs.info and obs.info.get('end_reason') == AgentStatus.Success:
                wins += 1
                wins_env[i] += 1
                num_win_steps.append(num_steps[i])
                num_win_steps_env[i].append(num_steps[i])
                num_win_returns.append(reward)
                num_win_returns_env[i].append(reward)
            elif obs.info and obs.info.get('end_reason') == AgentStatus.TimeoutReached:
                max_steps += 1
                max_steps_env[i] += 1
                num_max_steps_steps.append(num_steps[i])
                num_max_steps_steps_env[i].append(num_steps[i])
                num_max_steps_returns.append(reward)
                num_max_steps_returns_env[i].append(reward)

        # Reset all envs for next episode
        if episode < args.episodes:
            if episode % 10 == 0:
                observations = agent.request_game_reset(randomize_topology=True, seed=episode)
            else:
                observations = agent.request_game_reset(randomize_topology=False, seed=episode)
            if num_envs == 1:
                observations = [observations]

        # Calculate stats for logging (counts are across all envs)
        total_episodes_played = episode * num_envs
        eval_win_rate = (wins / total_episodes_played) * 100
        eval_detection_rate = (detected / total_episodes_played) * 100
        
        all_returns = num_detected_returns + num_win_returns + num_max_steps_returns
        eval_average_returns = np.mean(all_returns) if all_returns else 0
        eval_std_returns = np.std(all_returns) if all_returns else 0
        
        all_steps = num_win_steps + num_detected_steps + num_max_steps_steps
        eval_average_episode_steps = np.mean(all_steps) if all_steps else 0
        eval_std_episode_steps = np.std(all_steps) if all_steps else 0

        # Calculate stats per env for logging
        eval_win_rate_env = [(wins_env[i] / episode) * 100 for i in range(num_envs)]
        eval_detection_rate_env = [(detected_env[i] / episode) * 100 for i in range(num_envs)]
        
        eval_average_returns_env = []
        eval_std_returns_env = []
        eval_average_episode_steps_env = []
        eval_std_episode_steps_env = []
        
        for i in range(num_envs):
            all_returns_i = num_detected_returns_env[i] + num_win_returns_env[i] + num_max_steps_returns_env[i]
            eval_average_returns_env.append(np.mean(all_returns_i) if all_returns_i else 0)
            eval_std_returns_env.append(np.std(all_returns_i) if all_returns_i else 0)
            
            all_steps_i = num_win_steps_env[i] + num_detected_steps_env[i] + num_max_steps_steps_env[i]
            eval_average_episode_steps_env.append(np.mean(all_steps_i) if all_steps_i else 0)
            eval_std_episode_steps_env.append(np.std(all_steps_i) if all_steps_i else 0)
    
    # Format table text
    header = f"| {'Scope':<8} | {'Episodes':<8} | {'Wins':<6} | {'Dets':<6} | {'MaxStp':<6} | {'Win%':<7} | {'Det%':<7} | {'Avg Returns':<20} | {'Avg Steps':<20} |"
    separator = "-" * len(header)
    
    table_lines = [
        f"\nFinal results for {args.episodes} episodes x {num_envs} envs ({total_episodes_played} total):",
        separator,
        header,
        separator
    ]
    
    global_returns_str = f"{eval_average_returns:.2f} +/- {eval_std_returns:.2f}"
    global_steps_str = f"{eval_average_episode_steps:.2f} +/- {eval_std_episode_steps:.2f}"
    global_row = f"| {'Global':<8} | {total_episodes_played:<8} | {wins:<6} | {detected:<6} | {max_steps:<6} | {eval_win_rate:>6.2f}% | {eval_detection_rate:>6.2f}% | {global_returns_str:<20} | {global_steps_str:<20} |"
    table_lines.append(global_row)
    
    for i in range(num_envs):
        env_returns_str = f"{eval_average_returns_env[i]:.2f} +/- {eval_std_returns_env[i]:.2f}"
        env_steps_str = f"{eval_average_episode_steps_env[i]:.2f} +/- {eval_std_episode_steps_env[i]:.2f}"
        env_row = f"| {f'Env {i}':<8} | {args.episodes:<8} | {wins_env[i]:<6} | {detected_env[i]:<6} | {max_steps_env[i]:<6} | {eval_win_rate_env[i]:>6.2f}% | {eval_detection_rate_env[i]:>6.2f}% | {env_returns_str:<20} | {env_steps_str:<20} |"
        table_lines.append(env_row)
        
    table_lines.append(separator)
    table_text = "\n".join(table_lines)
    
    agent.logger.info(table_text)
    print(table_text)
    agent._logger.info("Terminating interaction")
    # stop gracefully
    agent.terminate_connection()

if __name__ == '__main__':
    main()
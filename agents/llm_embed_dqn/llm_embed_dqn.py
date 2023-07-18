"""
This agent uses LLm embeddings for the state and the actions
Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz
"""
import argparse
import sys
from collections import deque, namedtuple
import random
import time
import math

# This is used so the agent can see the environment and game components
from os import path
sys.path.append( path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))
from env.network_security_game import NetworkSecurityEnvironment
from env.game_components import Action, ActionType
from sentence_transformers import SentenceTransformer

import numpy as np
import tensorflow as tf

label_mapper = {
    "FindData":ActionType.FindData,
    "FindServices":ActionType.FindServices,
    "ScanNetwork":ActionType.ScanNetwork,
    "ExploitService":ActionType.ExploitService,
    "ExfiltrateData":ActionType.ExfiltrateData
}

action_list = ["ScanNetwork", "FindServices", "ExploitService", "FindData", "ExfiltrateData"]

# local_services = ['bash', 'powershell', 'remote desktop service',
# 'windows login', 'can_attack_start_here']
local_services = ['can_attack_start_here']

Transition = namedtuple('Transition', ('state', 'action', 'next_state', 'next_action', 'reward', 'memory', 'done'))


class ReplayBuffer:
    """
    Store and retrieve the episodic data
    """
    def __init__(self, capacity):
        """Initialize the buffer"""
        self.buffer = deque([], maxlen=capacity)

    def append(self, *args):
        """Save a transition"""
        self.buffer.append(Transition(*args))

    def sample(self, batch_size):
        """
        Sample based on the discounted rewards of each state
        """
        # Add 1 so that the weight sum is always positive
        # disc_rewards = [mem.disc_reward+1. for mem in self.buffer]
        # batch1 = random.choices(self.buffer, disc_rewards, k=batch_size)
        batch2 = random.sample(self.buffer, batch_size)
        # total_batch = shuffle(batch1+batch2)
        return batch2

    def __len__(self):
        """Return the size of the buffer"""
        return len(self.buffer)


class LLMEmbedAgent:
    """
    An agent for the NetSec Game environemnt that uses LLM embeddings.
    The agent is using the REINFORCE algorithm.
    """
    def __init__(self, game_env, args) -> None:
        """
        Create and initialize the agent and the transformer model.
        """
        self.env = game_env
        self.args = args
        self.embedding_size = 384

        self.transformer_model = SentenceTransformer("all-MiniLM-L12-v2").eval()
        all_actions = env.get_all_actions()
        self.action_db = {}
        for action in all_actions.values():
            self.action_db[action] = self.transformer_model.encode(str(action))
        self.q_model = self._create_model(embedding_size=self.embedding_size)
        self.q_target = self._create_model(embedding_size=self.embedding_size)
        self.optimizer = tf.keras.optimizers.Adam(learning_rate=args.lr, clipvalue=100)

        self.gamma = args.gamma
        # self.loss_fn = tf.keras.losses.MeanSquaredError()
        # self.loss_fn = nn.SmoothL1Loss()
        self.q_model.compile(self.optimizer, tf.keras.losses.MeanSquaredError())
        self.q_target.compile(self.optimizer)
        self.q_target.set_weights(self.q_model.get_weights())

        self.q_model.summary()
        run_name = f"netsecgame__LLM_embed_DQN__{env.seed}__{int(time.time())}"
        self.summary_writer = tf.summary.create_file_writer("./logs/"+ run_name)
        self.eval_episodes = args.eval_episodes
        # self.memory_len = args.memory_len
        # Parameter that defines the value of the intrinsic reward
        # self.beta = 1.0
        self.replay_buffer = ReplayBuffer(args.buffer_size)

    def _create_model(self, embedding_size=384):
        inputs = tf.keras.layers.Input(shape=(embedding_size*3,))

        layer1 = tf.keras.layers.Dense(512, activation="relu")(inputs)
        layer2 = tf.keras.layers.Dense(256, activation="relu")(layer1)
        layer3 = tf.keras.layers.Dense(32, activation="relu")(layer2)
        q_value = tf.keras.layers.Dense(1)(layer3)

        return tf.keras.Model(inputs=inputs, outputs=q_value)


    def _create_memory_prompt(self, memory_list):
        """
        Create a string that contains the past actions and their parameters.
        """
        prompt = "Memories:\n"
        if len(memory_list) > 0:
            for memory in memory_list:
                prompt += str(memory) + "\n"
        else:
            prompt = "No memories yet."
        return prompt

    def _create_embedding_from_str(self, str_):
        return self.transformer_model.encode(str_)

    def _generate_valid_actions(self, state):
        """
        Generate a list of valid actions from the current state.
        """
        valid_actions = set()
        #Network Scans
        for network in state.known_networks:
            valid_actions.add(Action(ActionType.ScanNetwork, params={"target_network": network}))
        # Service Scans
        for host in state.known_hosts:
            valid_actions.add(Action(ActionType.FindServices, params={"target_host": host}))
        # Service Exploits
        for host, service_list in state.known_services.items():
            for service in service_list:
                valid_actions.add(Action(ActionType.ExploitService,
                                         params={"target_host": host , "target_service": service}))
        # Data Scans
        for host in state.controlled_hosts:
            valid_actions.add(Action(ActionType.FindData, params={"target_host": host}))

        # Data Exfiltration
        for src_host, data_list in state.known_data.items():
            for data in data_list:
                for trg_host in state.controlled_hosts:
                    if trg_host != src_host:
                        valid_actions.add(Action(
                            ActionType.ExfiltrateData, params={"target_host": trg_host,
                                                               "source_host": src_host, 
                                                               "data": data}))
        return list(valid_actions)

    def _select_best_action_for_state(self, state, valid_actions, memories):
        """
        Go through all valid actions and select the best for this state
        """
        state_embed = self._create_embedding_from_str(str(state))
        memory_embed = self._create_embedding_from_str(self._create_memory_prompt(memories))

        action_vals = []
        for act in valid_actions:
            try:
                action_emb = self.action_db[act]
                action_vals.append(self.q_model(tf.concat([action_emb.reshape(1, -1),
                                                                   state_embed.reshape(1, -1),
                                                                   memory_embed.reshape(1, -1)],
                                                            axis=1), training=False))
            except KeyError:
                pass

        action_id = tf.argmax(action_vals).numpy().squeeze()
        action = valid_actions[action_id]

        return action

    def _optimize_models(self):
        """
        Run the training steps for a number of epochs using the replay buffer.
        """

        if len(self.replay_buffer) < self.args.batch_size:
            return
        for _ in range(self.args.num_epochs):
            transitions = self.replay_buffer.sample(self.args.batch_size)

            # Transpose the batch (see https://stackoverflow.com/a/19343/3343043 for
            # detailed explanation). This converts batch-array of Transitions
            # to Transition of batch-arrays.
            batch = Transition(*zip(*transitions))

            # Train the baseline first
            states_batch = np.array(batch.state).reshape(self.args.batch_size, self.embedding_size)
            reward_batch = np.array(batch.reward).reshape(self.args.batch_size, 1)
            action_batch = np.array(batch.action).reshape(self.args.batch_size, self.embedding_size)
            next_state_batch = np.array(batch.next_state).reshape(self.args.batch_size, self.embedding_size)
            next_action_batch = np.array(batch.next_action).reshape(self.args.batch_size, self.embedding_size)
            memory_batch = np.array(batch.memory).reshape(self.args.batch_size, self.embedding_size)
            # dones = np.array(batch.done).reshape(self.args.batch_size, 1)

            future_rewards = self.q_target(tf.concat([next_state_batch, next_action_batch, memory_batch], axis=1))
            updated_q_values = reward_batch + self.gamma * future_rewards

            # If final step set the last value to -1
            # TODO: check if this is needed
            # updated_q_values = updated_q_values * (1 - dones) - dones

            with tf.GradientTape() as tape:
                # Train the model on the states and updated Q-values
                q_values = self.q_model(tf.concat([states_batch.reshape(-1, self.embedding_size),
                                                          action_batch.reshape(-1, self.embedding_size),
                                                          memory_batch.reshape(-1, self.embedding_size)],
                                        axis=1), training=True)

                # Apply the masks to the Q-values to get the Q-value for action taken
                # q_action = tf.reduce_sum(q_values, axis=1)
                # Calculate loss between new Q-value and old Q-value
                loss = self.q_model.loss(updated_q_values, q_values)

            # Backpropagation
            grads = tape.gradient(loss, self.q_model.trainable_variables)
            self.optimizer.apply_gradients(zip(grads, self.q_model.trainable_variables))

        with self.summary_writer.as_default():
            tf.summary.scalar('train/loss',loss, step=self.q_model.optimizer.iterations)

    def train(self, num_episodes): # pylint: disable=too-many-locals,too-many-statements
        """
        Main training loop that runs for a number of episodes.
        """
        scores = deque(maxlen=128)

        # Keep track of the wins during training
        wins = 0
        epsilon = 0.9  # Epsilon greedy parameter
        epsilon_min = 0.05  # Minimum epsilon greedy parameter
        epsilon_max = 0.9  # Maximum epsilon greedy parameter
        epsilon_interval = epsilon_max - epsilon_min
        step_count = 0

        # TODO: calibrate the epsilon and the target update
        epsilon_greedy_steps = 10000
        update_target_network = 4 # steps

        running_reward = 0
        for episode in range(1, num_episodes+1):
            rewards = []
            memories = []
            int_reward = 0
            observation = self.env.reset()
            valid_actions = self._generate_valid_actions(observation.state)
            action_next = self._select_best_action_for_state(observation.state, valid_actions, memories)
            num_valid_actions=len(valid_actions)

            for _ in range(self.args.max_t):
                step_count += 1
                if epsilon > np.random.rand(1)[0]:
                    # Take random action
                    action = np.random.choice(valid_actions)
                else:
                    action = action_next

                # Decay probability of taking random action
                epsilon = epsilon_min + epsilon_interval * math.exp(-1. * step_count / epsilon_greedy_steps)

                # Take a step in the environment and get the next action and best state
                observation_next = self.env.step(action)
                valid_actions = self._generate_valid_actions(observation_next.state)
                action_next = self._select_best_action_for_state(observation_next.state, valid_actions, memories)

                if len(valid_actions) > num_valid_actions:
                    num_valid_actions = len(valid_actions)
                    int_reward = 2.0
                else:
                    int_reward = 0.0

                rewards.append(observation_next.reward+int_reward)

                self.replay_buffer.append(self._create_embedding_from_str(str(observation.state)),
                                          self._create_embedding_from_str(str(action)),
                                          self._create_embedding_from_str(str(observation_next.state)),
                                          self._create_embedding_from_str(str(action_next)),
                                          observation_next.reward,
                                          self._create_embedding_from_str(self._create_memory_prompt(memories)),
                                          observation_next.done)
                observation = observation_next
                memories.append(str(action))

                if observation_next.done:
                    # If done and the latest reward from the env is positive,
                    # we have reached the goal
                    if observation_next.reward > 0:
                        wins += 1
                    break
            win_rate = 100*(wins/episode)
            scores.append(sum(rewards))

            with self.summary_writer.as_default():
                tf.summary.scalar("train/valid_actions", len(valid_actions), episode)
                tf.summary.scalar("train/reward", np.mean(scores), episode)
                tf.summary.scalar("train/running_reward", running_reward, episode)
                tf.summary.scalar("train/num_wins", wins, episode)
                tf.summary.scalar("train/win_rate", win_rate, episode)
                tf.summary.scalar("train/epsilon", epsilon, episode)

            if episode > 1 and step_count % self.args.train_every == 0:
                self._optimize_models()

            if step_count % update_target_network == 0:
                # update the the target network with new weights
                # TODO: soft or hard update and how often?
                tau = 0.005
                target_weights = self.q_target.variables
                model_weights = self.q_model.variables
                for (a, b) in zip(target_weights, model_weights):
                    a.assign(b * tau + a * (1 - tau))
                # self.q_target.set_weights(self.q_model.get_weights())

            # Update running reward to check condition for solving
            running_reward = np.mean(scores)

            # TODO: Condition to consider the task solved
            if win_rate > 90:
                print(f"Solved at episode {episode}!")
                break

            if episode > 0 and episode % self.args.eval_every == 0:
                eval_rewards, eval_wins = self.evaluate(args.eval_episodes)
                with self.summary_writer.as_default():
                    tf.summary.scalar('test/eval_rewards', np.mean(eval_rewards), episode)
                    tf.summary.scalar('test/wins', eval_wins, episode)
                    tf.summary.scalar('test/win_rate', eval_wins/args.eval_episodes, episode)

    def evaluate(self, num_eval_episodes):
        """
        Evaluation function.
        """
        eval_returns = []
        num_wins = 0
        for _ in range(num_eval_episodes):
            observation = env.reset()
            done = False
            ret = 0
            memories = []

            valid_actions = self._generate_valid_actions(observation.state)
            while not done:
                action = self._select_best_action_for_state(observation.state, valid_actions, memories)
                memories.append(str(action))
                observation_next = self.env.step(action)

                ret += observation_next.reward
                done = observation_next.done

                # Generate the list of all the valid actions in the observed state
                valid_actions = self._generate_valid_actions(observation.state)
                observation = observation_next

            if observation_next.reward > 0:
                num_wins += 1

            eval_returns.append(ret)

        return eval_returns, num_wins

    def save_model(self, file_name):
        """
        Save the pytorch policy model.
        """
        raise NotImplementedError

    def load_model(self, file_name):
        """
        Load the model
        """
        raise NotImplementedError

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    # Task config file
    parser.add_argument("--task_config_file",
                        help="Reads the task definition from a configuration file",
                        default=path.join(path.dirname(__file__), 'netsecenv-task.yaml'),
                        action='store',
                        required=False)

    # Model arguments
    parser.add_argument("--gamma", help="Sets gamma for discounting", default=0.9, type=float)
    parser.add_argument("--lr", help="Learning rate of the NN", type=float, default=1e-3)
    # parser.add_argument("--memory_len", type=int, default=0, help="Number of memories to keep. Zero means no memory")
    parser.add_argument("--model_path", type=str, default="saved_models/q_model.h5", help="Path for saving the policy model.")

    # Training arguments
    parser.add_argument("--num_epochs", type=int, default=1, help="Number of epochs to train the networks")
    parser.add_argument("--batch_size", type=int, default=32, help="Batch size to sample from memory")
    parser.add_argument("--num_episodes", help="Sets number of training episodes", default=1000, type=int)
    parser.add_argument("--max_t", type=int, default=128, help="Max episode length")
    parser.add_argument("--train_every", type=int, default=4, help="Train every this ammount of steps.")
    parser.add_argument("--eval_every", help="During training, evaluate every this amount of episodes.", default=128, type=int)
    parser.add_argument("--eval_episodes", help="Sets evaluation length", default=100, type=int)
    parser.add_argument("--buffer_size", type=int, default=128, help="Replay buffer size")

    args = parser.parse_args()

    # Create the environment
    env = NetworkSecurityEnvironment(args.task_config_file)

    # Initializr the agent
    agent = LLMEmbedAgent(env, args)
    hparams = {
        "lr": args.lr,
        "gamma": args.gamma,
        # "mem_len": args.memory_len,
        "batch_size": args.batch_size,
        "num_episodes": args.num_episodes,
        "buffer_size": args.buffer_size,
        "train_every": args.train_every
    }

    # Train the agent using DQN
    agent.train(args.num_episodes)

    # Evaluate the agent
    final_returns, wins = agent.evaluate(args.eval_episodes)
    print(f"Evaluation finished - (mean of {len(final_returns)} runs): {np.mean(final_returns)}+-{np.std(final_returns)}")
    print(f"Total number of wins during evaluation: {wins}")
    print(f"Win rate during evaluation: {100*wins/args.eval_episodes}")
    # agent.summary_writer.add_hparams(hparams, {"hparams/wins": wins, "hparams/win_rate": wins/args.eval_episodes, "hparams/return": np.mean(final_returns)})
    # agent.summary_writer.close()
    # agent.save_model(args.model_path)

    # agent.load_model('saved_models/policy.pt')
    # final_returns, wins = agent.evaluate(args.eval_episodes)
    # print(f"Evaluation finished - (mean of {len(final_returns)} runs): {np.mean(final_returns)}+-{np.std(final_returns)}")
    # print(f"Total number of wins during evaluation: {wins}")
    # print(f"Win rate during evaluation: {100*wins/args.eval_episodes}%")

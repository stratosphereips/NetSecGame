# This agent uses LLm embeddings for the state and the actions
# Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz    
import argparse
import sys
from collections import deque

# This is used so the agent can see the environment and game components
from os import path
sys.path.append( path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))
from env.network_security_game import NetworkSecurityEnvironment
from env.game_components import Action, ActionType


import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as func
import torch.optim as optim
from torch.utils.tensorboard import SummaryWriter
from sentence_transformers import SentenceTransformer, util

label_mapper = {
    "FindData":ActionType.FindData,
    "FindServices":ActionType.FindServices,
    "ScanNetwork":ActionType.ScanNetwork,
    "ExploitService":ActionType.ExploitService,
    "ExfiltrateData":ActionType.ExfiltrateData
}

# local_services = ['bash', 'powershell', 'remote desktop service', 'windows login', 'can_attack_start_here']
local_services = ['can_attack_start_here']


class Policy(nn.Module):
    """
    This is the policy that takes as input the observation embedding
    and outputs an action embedding
    """
    def __init__(self, embedding_size=384):
        super(Policy, self).__init__()
        self.linear1 = nn.Linear(embedding_size, 512)
        self.dropout = nn.Dropout(p=0.5)
        self.linear2 = nn.Linear(512, embedding_size)
        # self.dropout2 = nn.Dropout(p=0.5)
        # self.linear3 = nn.Linear(512, embedding_size)

        self.saved_log_probs = []
        self.rewards = []

    def forward(self, x):
        x = self.linear1(x)
        x = self.dropout(x)
        x = func.relu(x)
        # x = self.linear2(x)
        # x = self.dropout2(x)
        # x = F.relu(x)
        return self.linear2(x)

class LLMEmbedAgent:
    def __init__(self, env, args) -> None:
        """
        Create and initialize the agent and the transformer model.
        """
        self.env = env
        # device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        self.policy = Policy(embedding_size=384)
        self.optimizer = optim.Adam(self.policy.parameters(), lr=args.lr)
        self.eps = np.finfo(np.float32).eps.item()

        self.transformer_model = SentenceTransformer("all-MiniLM-L12-v2").eval()
        self.max_t = args.max_t
        self.num_episodes = args.num_episodes
        self.gamma = args.gamma
        # self.loss_fn = torch.nn.MSELoss(reduction='mean')
        self.loss_fn = nn.HuberLoss()
        self.summary_writer = SummaryWriter()
        self.summary_writer.add_graph(self.policy, torch.zeros((1, 384)))

    def _create_status_from_state(self, state):
        """
        Create a status prompt using the current state.
        """
        contr_hosts = [host.ip for host in state.controlled_hosts]
        known_hosts = [host.ip for host in state.known_hosts]
        known_nets = [str(net) for net in list(state.known_networks)]

        prompt = f"Controlled hosts are {' and '.join(contr_hosts)}\n"
        # logger.info("Controlled hosts are %s", ' and '.join(contr_hosts))

        prompt += f"Known networks are {' and '.join(known_nets)}\n"
        # logger.info("Known networks are %s", ' and '.join(known_nets))
        prompt += f"Known hosts are {' and '.join(known_hosts)}\n"
        # logger.info("Known hosts are %s", ' and '.join(known_hosts))

        if len(state.known_services.keys()) == 0:
            prompt += "Known services are none\n"
            # logger.info(f"Known services: None")
        for ip_service in state.known_services:
            services = []
            if len(list(state.known_services[ip_service])) > 0:
                for serv in state.known_services[ip_service]:
                    if serv.name not in local_services:
                        services.append(serv.name)
                if len(services) > 0:
                    serv_str = ""
                    for serv in services:
                        serv_str += serv + " and "
                    prompt += f"Known services for host {ip_service} are {serv_str}\n"
                    # logger.info(f"Known services {ip_service, services}")
                else:
                    prompt += "Known services are none\n"
                    # logger.info(f"Known services: None")

        if len(state.known_data.keys()) == 0:
            prompt += "Known data are none\n"
            # logger.info(f"Known data: None")
        for ip_data in state.known_data:
            if len(state.known_data[ip_data]) > 0:

                host_data = ""
                for known_data in list(state.known_data[ip_data]):
                    host_data += f"({known_data.owner}, {known_data.id}) and "
                prompt += f"Known data for host {ip_data} are {host_data}\n"
                # logger.info(f"Known data: {ip_data, state.known_data[ip_data]}")
    
        return prompt

    def _convert_embedding_to_action(self, new_action_embedding, valid_actions):
        """
        Take an embedding, and the valid actions for the state
        and find the closest embedding using cosine similarity
        Return an Action object and the closest neighbor
        """
        all_actions_str = [str(action) for action in valid_actions]
        valid_embeddings = self.transformer_model.encode(all_actions_str)
        action_id = np.argmax(util.cos_sim(valid_embeddings, new_action_embedding), axis=0)

        return valid_actions[action_id], valid_embeddings[action_id]
    
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
                valid_actions.add(Action(ActionType.ExploitService, params={"target_host": host , "target_service": service}))
        # Data Scans
        for host in state.controlled_hosts:
            valid_actions.add(Action(ActionType.FindData, params={"target_host": host}))

        # Data Exfiltration
        for src_host, data_list in state.known_data.items():
            for data in data_list:
                for trg_host in state.controlled_hosts:
                    if trg_host != src_host:
                        valid_actions.add(Action(ActionType.ExfiltrateData, params={"target_host": trg_host, "source_host": src_host, "data": data}))
        return list(valid_actions)

    def _weight_histograms_linear(self, step, weights, layer_name):
        """
        Log the histograms of the weight of a specific layer to tensorboard
        """
        flattened_weights = weights.flatten()
        tag = f"layer_{layer_name}"
        self.summary_writer.add_histogram(tag, flattened_weights, global_step=step, bins='tensorflow')

    def _weight_histograms(self, step):
        """
        Go over each layer and if it is a linear layer send it to the
        logger function.
        """
        # Iterate over all model layers
        for layer_name in self.policy._modules.keys():
            layer = self.policy._modules[layer_name]
            # Compute weight histograms for appropriate layer
            if isinstance(layer, nn.Linear):
                weights = layer.weight
                self._weight_histograms_linear(step, weights, layer_name)

    def _training_step(self, rewards, out_embeddings, real_embeddings, episode):
        """
        The training step that calculates that discounted rewards and losses.
        It also performs the backpropagation step for the policy network.
        """
        # Calculate the discounted rewards
        policy_loss = []
        returns = deque()

        n_steps = len(rewards)
        for t in range(n_steps)[::-1]:
            disc_return_t = (returns[0] if len(returns)>0 else 0)
            returns.appendleft(self.gamma*disc_return_t + rewards[t]) 

        eps = np.finfo(np.float32).eps.item()
        returns = torch.Tensor(returns)
        returns = (returns - returns.mean()) / (returns.std() + eps)
        
        for out_emb, real_emb, disc_ret in zip(out_embeddings, real_embeddings, returns):
            rmse_loss = torch.sqrt(self.loss_fn(out_emb, torch.Tensor(real_emb).float().unsqueeze(0))) 
            policy_loss.append((-rmse_loss * disc_ret).reshape(1))

        self.optimizer.zero_grad()
        policy_loss = torch.cat(policy_loss).sum()
        self.summary_writer.add_scalar("loss", policy_loss, episode)
        policy_loss.backward()

        torch.nn.utils.clip_grad_value_(self.policy.parameters(), 100)
        self.optimizer.step()

        for tag, param in self.policy.named_parameters():
            self.summary_writer.add_histogram(f"grad_{tag}", param.grad.data.cpu().numpy(), episode)


    def train(self):
        """
        Main training loop that runs for a number of episodes.
        """
        scores = []
        for episode in range(1, self.num_episodes+1):
            out_embeddings = []
            real_embeddings = []
            rewards = []

            observation = self.env.reset()

            # Visualize the weights in tensorboard
            self._weight_histograms(episode)
            
            for _ in range(self.max_t):
                # Create the status string from the observed state
                status_str = self._create_status_from_state(observation.state)

                # Get the embedding of the string from the policy
                with torch.no_grad():
                    state_embed = self.transformer_model.encode(status_str)
                    state_embed_t = torch.from_numpy(state_embed).float().unsqueeze(0)

                # Pass the state embedding to the model and get the action
                action_emb = self.policy.forward(state_embed_t)
                out_embeddings.append(action_emb)

                # Convert the action embedding to a valid action and its embedding
                valid_actions = self._generate_valid_actions(observation.state)
                action, real_emb = self._convert_embedding_to_action(action_emb.tolist()[0], valid_actions)
                real_embeddings.append(real_emb)

                # Take the new action and get the observation from the policy
                observation = self.env.step(action)
                rewards.append(observation.reward)
                if observation.done:
                    break

            scores.append(sum(rewards))
            self.summary_writer.add_scalar("valid actions", len(valid_actions), episode)
            self.summary_writer.add_scalar("mean reward", np.mean(scores), episode)
            self._training_step(rewards, out_embeddings, real_embeddings, episode)

            if episode > 0 and episode % self.max_t == 0:
                returns = self.evaluate(50)
                print(f"Evaluation after {episode} episodes (mean of {len(returns)} runs): {np.mean(returns)}+-{np.std(returns)}")
                self.summary_writer.add_scalar('test/eval_win', np.mean(returns), step=episode)

    def evaluate(self, num_eval_episodes):
        """
        Evaluation function.
        """
        eval_returns = []
        for _ in range(num_eval_episodes):
            observation, done = env.reset(), False
            ret = 0
            while not done:
                # Create the status string from the observed state
                status_str = self._create_status_from_state(observation.state)

                # Get the embedding of the string from the policy
                state_embed = self.transformer_model.encode(status_str)
                state_embed = torch.from_numpy(state_embed).float().unsqueeze(0)

                # Pass the state embedding to the model and get the action
                action_emb = self.policy.forward(state_embed)

                # Convert the action embedding to a valid action and its embedding
                valid_actions = self._generate_valid_actions(observation.state)
                action, _ = self._convert_embedding_to_action(action_emb.tolist()[0], valid_actions)

                # Take the new action and get the observation from the policy
                observation = self.env.step(action)
                ret += observation.reward
                done = observation.done

            eval_returns.append(ret)
        print(f"Evaluation finished - (mean of {len(eval_returns)} runs): {np.mean(eval_returns)}+-{np.std(eval_returns)}")
        return eval_returns
        

    def save_model(self, file_name):
        raise NotImplementedError

    def load_model(self, file_name):
        raise NotImplementedError


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    # Task config file
    parser.add_argument("--task_config_file", help="Reads the task definition from a configuration file", default=path.join(path.dirname(__file__), 'netsecenv-task.yaml'), action='store', required=False)

    # Model arguments
    parser.add_argument("--gamma", help="Sets gamma for discounting", default=0.9, type=float)
    parser.add_argument("--batch_size", help="Batch size for NN training", type=int, default=64)
    parser.add_argument("--lr", help="Learnining rate of the NN", type=float, default=1e-2)

    # Training arguments
    parser.add_argument("--num_episodes", help="Sets number of training episodes", default=1000, type=int)
    parser.add_argument("--max_t", type=int, default=128, help="Max episode length")
    parser.add_argument("--eval_each", help="During training, evaluate every this amount of episodes.", default=128, type=int)
    # parser.add_argument("--eval_for", help="Sets evaluation length", default=250, type=int)
    parser.add_argument("--final_eval_for", help="Sets evaluation length", default=1000, type=int )

    args = parser.parse_args()

    # Create the environment
    env = NetworkSecurityEnvironment(args.task_config_file)

    # Initializr the agent
    agent = LLMEmbedAgent(env, args)

    # Train the agent using reinforce
    agent.train()

    # Evaluate the agent
    agent.evaluate(args.final_eval_for)

# This agent uses LLm embeddings for the state and the actions
# Authors:  Maria Rigaki - maria.rigaki@aic.fel.cvut.cz    
import argparse
import logging
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
import torch.nn.functional as F
import torch.optim as optim

from chromadb.utils import embedding_functions
from chromadb.config import Settings
from chromadb import Client

from sentence_transformers import SentenceTransformer

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
        self.linear1 = nn.Linear(embedding_size, 128)
        self.dropout = nn.Dropout(p=0.2)
        self.linear2 = nn.Linear(128, embedding_size)

        self.saved_log_probs = []
        self.rewards = []

    def forward(self, x):
        x = self.linear1(x)
        x = self.dropout(x)
        x = F.relu(x)
        action_embedding = self.linear2(x)
        return action_embedding

class LLMEmbedAgent:
    def __init__(self, env, args) -> None:
        """
        Create and initialize the agent.
        """
        self.env = env
        # device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        self.policy = Policy(embedding_size=384)
        self.optimizer = optim.Adam(self.policy.parameters(), lr=args.lr)
        self.eps = np.finfo(np.float32).eps.item()
        print(self.policy)

        self.db_client = Client()
        self.ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        self.collection = self.db_client.create_collection(name="actions", embedding_function=self.ef)
        self.all_actions = self.env.get_all_actions()

        self.all_actions_str = [str(action) for action in self.all_actions.values()]
        self.ids = ["a"+str(i) for i in range(len(self.all_actions))]
        self.metadata = [{"action":str(action.type), "params":str(action.parameters)} for action in self.all_actions.values()]
        self.collection.add(ids=self.ids, 
                            documents=self.all_actions_str, 
                            metadatas=self.metadata)
        
        self.transformer_model = SentenceTransformer('all-MiniLM-L6-v2')
        self.max_t = args.max_t
        self.num_episodes = args.num_episodes
        self.gamma = args.gamma
        self.loss_fn = torch.nn.MSELoss()

    # def _parse_action_string(self, action_str):
    #     """
    #     Get the action string stored as metadata
    #     and return an action to use in the environment.
    #     """
    #     params_start = action_str.find('{')
    #     params_end = action_str.find('}')

    #     action_params = eval(action_str[params_start:params_end])
    #     acttion_start = action_str.find('.')
    #     action_end = action_str.find('|')

    #     return Action(action_type=label_mapper[action_str[acttion_start:action_end]],
    #            params=action_params)

    def _create_status_from_state(self, state):
        """Create a status prompt using the current state and the sae memories."""
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


    def _convert_embedding_to_action(self, new_action_embedding):
        """
        Take an embedding, and the valid actions for the state
        and find the closest embedding using cosine similarity
        Return an Action object and the closest neighbor
        """
        result = self.collection.query(query_embeddings=new_action_embedding,
                                       n_results=1,
                                       include=["embeddings"])
        
        # where conditions can be added

        # Get the action id -> "aX"
        action_id = result["ids"][0][0]
        return self.all_actions[int(action_id[1:])], result["embeddings"][0][0]
        
    def _get_valid_actions(self):
        """
        From the current state find all valid actions and return their ids
        """
        raise NotImplementedError
    
    def _training_step(self, rewards, out_embeddings, real_embeddings):
        eps = np.finfo(np.float32).eps.item()

        # Calculate the discounted rewards
        R = 0
        policy_loss = []
        returns = deque()
        for r in rewards[::-1]:
            R = r + args.gamma * R
            returns.appendleft(R)
        returns = torch.tensor(returns)
        returns = (returns - returns.mean()) / (returns.std() + eps)
        
        for out_emb, real_emb, disc_ret in zip(out_embeddings, real_embeddings, returns):
            rmse_loss = torch.sqrt(self.loss_fn(out_emb, torch.Tensor(real_emb).float().unsqueeze(0))) 
            policy_loss.append((-rmse_loss * disc_ret).reshape(1))

        self.optimizer.zero_grad()
        policy_loss = torch.cat(policy_loss).sum()
        policy_loss.backward()
        self.optimizer.step()

    def train(self):
        scores_deque = deque(maxlen=100)
        scores = []
        for i in range(1, self.num_episodes+1):
            out_embeddings = []
            real_embeddings = []
            rewards = []

            observation = self.env.reset()
            
            for t in range(self.max_t):
                # Create the status string from the observed state
                status_str = self._create_status_from_state(observation.state)

                # Get the embedding of the string from the policy
                state_embed = self.transformer_model.encode(status_str)
                state_embed = torch.from_numpy(state_embed).float().unsqueeze(0)

                # Pass the state embedding to the model and get the action
                action_emb = self.policy.forward(state_embed)
                out_embeddings.append(action_emb)

                # Convert the action embedding to a valid action and its embedding
                action, real_emb = self._convert_embedding_to_action(action_emb.tolist()[0])
                # print(f"Action: {action}")
                real_embeddings.append(real_emb)

                # Take the new action and get the observation from the policy
                observation = self.env.step(action)
                rewards.append(observation.reward)
                if observation.done:
                    break

            scores_deque.append(sum(rewards))
            scores.append(sum(rewards))
            print(f"Scores: ", scores)
            
            self._training_step(rewards, out_embeddings, real_embeddings)

    def evaluate(self, num_eval_episodes):
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
                action, real_emb = self._convert_embedding_to_action(action_emb.tolist()[0])
                print(f"Action: {action}")

                # Take the new action and get the observation from the policy
                observation = self.env.step(action)
                ret += observation.reward
                done = observation.done

            eval_returns.append(ret)
            print(f"Evaluation finished - (mean of {len(eval_returns)} runs): {np.mean(eval_returns)}+-{np.std(eval_returns)}")

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
    parser.add_argument("--lr", help="Learnining rate of the NN", type=float, default=1e-3)

    # Training arguments
    parser.add_argument("--num_episodes", help="Sets number of training episodes", default=1000, type=int)
    parser.add_argument("--max_t", type=int, default=128, help="Max episode length")
    parser.add_argument("--eval_each", help="During training, evaluate every this amount of episodes.", default=128, type=int)
    parser.add_argument("--eval_for", help="Sets evaluation length", default=250, type=int)
    parser.add_argument("--final_eval_for", help="Sets evaluation length", default=1000, type=int )

    args = parser.parse_args()

    logger = logging.getLogger('llm_embed_agent')


    logger.info('Setting the network security environment')
    env = NetworkSecurityEnvironment(args.task_config_file)
    state = env.reset()

    # Training
    logger.info('Creating the agent')
    
    # # initialize agent
    agent = LLMEmbedAgent(env, args)
    agent.train()
    agent.evaluate(args.final_eval_for)
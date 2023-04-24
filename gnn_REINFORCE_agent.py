# Authors:  Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
#           Arti       
from network_security_game import Network_Security_Environment
#from environment import *
from game_components import *
import numpy as np
from random import choice, random, seed
import random
import argparse
from timeit import default_timer as timer
import logging
from torch.utils.tensorboard import SummaryWriter
import time
from scenarios import scenario_configuration, smaller_scenario_configuration, tiny_scenario_configuration

import tensorflow_gnn as tfgnn
import tensorflow as tf

tf.get_logger().setLevel('ERROR')

class GNN_REINFORCE_Agent:
    """
    Class implementing the REINFORCE algorithm with GNN as input layer
    """

    def __init__(self, env:Network_Security_Environment, args: argparse.Namespace):

        self.env = env
        self.args = args
        #self._transition_mapping = {k:n for n,k in enumerate(transitions.keys())}
        self._transition_mapping = env.get_all_actions()
        # for k,v in self._transition_mapping.items():
        #     print(k,v)
        # exit()


        # #Get the env state as graph
        # node_f, _, adj = env.get_current_state.observation.as_graph
        
        # #convert into TFGNN tensor
        # graph_tensor =self._create_graph_tensor(node_f, adj)

        graph_schema = tfgnn.read_schema("schema.pbtxt")
        self._example_input_spec = tfgnn.create_graph_spec_from_schema_pb(graph_schema)

        #model building blocks
        def set_initial_node_state(node_set, node_set_name):
            return tf.keras.layers.Dense(32,activation="relu")(node_set['node_type'])
    

        def dense_layer(self,units=64,l2_reg=0.1,dropout=0.25,activation='relu'):
            regularizer = tf.keras.regularizers.l2(l2_reg)
            return tf.keras.Sequential([tf.keras.layers.Dense(units, kernel_regularizer=regularizer, bias_regularizer=regularizer),tf.keras.layers.Dropout(dropout)])
        #input
        input_graph = tf.keras.layers.Input(type_spec=self._example_input_spec)
        #process node features with FC layer
        graph = tfgnn.keras.layers.MapFeatures(node_sets_fn=set_initial_node_state,)(input_graph)

        #Graph conv
        graph_updates = 4 # TODO Add to args
        for i in range(graph_updates):
            graph = tfgnn.keras.layers.GraphUpdate(
                node_sets = {
                    'nodes': tfgnn.keras.layers.NodeSetUpdate({
                        'related_to': tfgnn.keras.layers.SimpleConv(
                            message_fn = dense_layer(48), #TODO add num_units to args
                            reduce_type="sum",
                            receiver_tag=tfgnn.TARGET)},
                        tfgnn.keras.layers.NextStateFromConcat(dense_layer(64)))})(graph)  #TODO add num_units to args
        # Pool to get a single vector representing the graph 
        pooling = tfgnn.keras.layers.Pool(tfgnn.CONTEXT, "mean",node_set_name="nodes")(graph)
        # Two hidden layers (Followin the REINFORCE)
        hidden1 = tf.keras.layers.Dense(128, activation="relu", name="hidden1")(pooling)
        hidden2 = tf.keras.layers.Dense(16, activation="relu", name="hidden2")(hidden1)
        

        node_states = graph.node_sets["nodes"]

        # Output layer
        out  = tf.keras.layers.Dense(len(self._transition_mapping), activation="softmax", name="softmax_output", kernel_initializer=tf.keras.initializers.RandomUniform(seed=args.seed))(hidden2)
        
        #Build the model
        self._model = tf.keras.Model(input_graph, [out,node_states])
        self._model.compile(tf.keras.optimizers.Adam(learning_rate=args.lr))
    
    # def _adj_to_indices(self, adj):
    #     tmp = np.where(adj==1)
    #     return tmp[0].tolist(), tmp[1].tolist()
    
    def _create_graph_tensor(self, node_features, edges):
        src,trg = [x[0] for x in edges],[x[1] for x in edges]
        graph_tensor =  tfgnn.GraphTensor.from_pieces(
            node_sets = {"nodes":tfgnn.NodeSet.from_fields(
                
                sizes = [len(node_features)],
                features = {"node_type":np.array(np.eye(6)[node_features], dtype='int32')} # one-hot encoded node features TODO remove hardcoded max value
            )},
            edge_sets = {
                "related_to": tfgnn.EdgeSet.from_fields(
                sizes=[len(src)],
                features = {},
                adjacency=tfgnn.Adjacency.from_indices(
                source=("nodes", np.array(src, dtype='int32')),
                target=("nodes", np.array(trg, dtype='int32'))))
            }
        )
        return graph_tensor
    

        return tf.keras.layers.Dense(32,activation="relu")(node_set['node_type']) #TODO args
    
    def _get_discounted_rewards(self, rewards:list)->list:
        returns = np.array([self.args.gamma ** i * rewards[i] for i in range(len(rewards))])
        returns =  np.flip(np.cumsum(np.flip(returns)))
        return returns.tolist()
    
    @tf.function
    def predict(self, state_graph, training=False):
        return self._model(state_graph, training=training)
    
    @tf.function
    def _make_training_step(self, inputs, labels, weights):
        #perform training step
        with tf.GradientTape() as tape:
            logits, hidden_states = self.predict(inputs, training=True)
            cce = tf.keras.losses.SparseCategoricalCrossentropy()
            loss = cce(labels, logits, sample_weight=weights)
        grads = tape.gradient(loss, self._model.trainable_weights)
        self._model.optimizer.apply_gradients(zip(grads, self._model.trainable_weights)) 
    
    def _preprocess_inputs(self, replay_buffer):
        raise NotImplementedError
    
    def save_model(self, filename):
        raise NotImplementedError
    
    def load_model(self, filename):
        raise NotImplementedError
    
    def data_generator(self, list):
        for x in list:
            yield x

    def train(self):
        for episode in range(self.args.episodes):
            #collect data
            batch_states, batch_actions, batch_returns = [], [], []
            while len(batch_states) < args.batch_size:
                #perform episode
                states, actions, rewards = [], [], []
                state, done = env.reset().observation, False
                #print("Collecting batch")

                while not done:
                    state_node_f,_, state_edges = state.as_graph
                    state_g = self._create_graph_tensor(state_node_f, state_edges)
                    #predict action probabilities
                    probabilities, hidden_states = self.predict(state_g)
                    probabilities = tf.squeeze(probabilities)
                    # #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                    # #TEMPORARY FIX
                    # action_space = []
                    # weights = []
                    # for a in env.get_valid_actions(state):
                    #     action_space.append(a)
                    #     weights.append(probabilities[self._transition_mapping[a.transition.type]])
                    
                    # weights = weights/np.sum(weights).astype(np.float32)
                    # #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                    
                    weights = probabilities
                    action = random.choices(list(self._transition_mapping.keys()), weights=weights, k=1)[0]
                    #select action and perform it
                    next_state = self.env.step(self._transition_mapping[action])


                    #print(self._transition_mapping[action])
                    states.append(state_g)
                    actions.append(action)
                    rewards.append(next_state.reward)

                    #move to the next state
                    state = next_state.observation
                    done = next_state.done
                discounted_returns = self._get_discounted_rewards(rewards)
                batch_states += states
                batch_actions += actions
                batch_returns += discounted_returns         
            #shift batch_returns to non-negative
            batch_returns = batch_returns + np.abs(np.min(batch_returns)) + 1e-10
             
            with tf.io.TFRecordWriter("tmp_record_file") as writer:
                for graph in batch_states:
                    example = tfgnn.write_example(graph)
                    writer.write(example.SerializeToString())
            
            #Create TF dataset
            dataset = tf.data.TFRecordDataset("tmp_record_file")
            #de-serialize records
            new_dataset = dataset.map(lambda serialized: tfgnn.parse_single_example(serialized=serialized, spec=self._example_input_spec))
            # #get batch of proper size
            batch_data = new_dataset.batch(len(batch_states))
            graph_tensor_batch = next(iter(batch_data))
            
            #convert batch into scalar graph with multiple components
            scalar_graph_tensor = graph_tensor_batch.merge_batch_to_components()
            probs, hidden_states = self._model(scalar_graph_tensor)
           
            #perform training step
            self._make_training_step(scalar_graph_tensor, batch_actions, batch_returns)
            
            #evaluate
            if episode > 0 and episode % args.eval_each == 0:
                returns = []
                for _ in range(self.args.eval_for):
                    state, done = env.reset().observation, False
                    ret = 0
                    while not done:
                        state_node_f,_, state_edges = state.as_graph
                        state_g = self._create_graph_tensor(state_node_f, state_edges)
                        #predict action probabilities
                        probabilities, hidden_states = self.predict(state_g)
                        
                        probabilities = tf.squeeze(probabilities)
                        action_idx = np.argmax(probabilities)
                        action = self._transition_mapping[action_idx]

                        #select action and perform it
                        next_state = self.env.step(action)
                        ret += next_state.reward
                        state = next_state.observation
                        done = next_state.done
    
                    returns.append(ret)
                print(f"Evaluation after {episode} episodes (mean of {len(returns)} runs): {np.mean(returns)}+-{np.std(returns)}") 
            else:
                pass
                #print(f"Episode {episode} done.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    #env arguments
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=15, type=int)
    parser.add_argument("--defender", help="Is defender present", default=True, action="store_true")
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1", type=str)
    parser.add_argument("--random_start", help="Sets evaluation length", default=False, action="store_true")
    parser.add_argument("--verbosity", help="Sets verbosity of the environment", default=0, type=int)

    #model arguments
    parser.add_argument("--episodes", help="Sets number of training episodes", default=10000, type=int)
    parser.add_argument("--gamma", help="Sets gamma for discounting", default=0.9, type=float)
    parser.add_argument("--batch_size", help="Batch size for NN training", type=int, default=64)
    parser.add_argument("--lr", help="Learnining rate of the NN", type=float, default=1e-4)

    #training arguments
    parser.add_argument("--eval_each", help="During training, evaluate every this amount of episodes.", default=50, type=int)
    parser.add_argument("--eval_for", help="Sets evaluation length", default=100, type=int)

    parser.add_argument("--test", help="Do not train, only run test", default=False, action="store_true")
    parser.add_argument("--test_for", help="Sets evaluation length", default=1000, type=int)

    
    parser.add_argument("--seed", help="Sets the random seed", type=int, default=42)

    args = parser.parse_args()
    args.filename = "GNN_Reinforce_Agent_" + ",".join(("{}={}".format(key, value) for key, value in sorted(vars(args).items()) if key not in ["evaluate", "eval_each", "eval_for"])) + ".pickle"

    logging.basicConfig(filename='GNN_Reinforce_Agent.log', filemode='a', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.INFO)
    logger = logging.getLogger('GNN_Reinforce_Agent')

    # Setup tensorboard
    run_name = f"netsecgame__GNN_Reinforce__{args.seed}__{int(time.time())}"
    writer = SummaryWriter(f"logs/{run_name}")
    writer.add_text(
        "hypherparameters", 
        "|param|value|\n|-|-|\n%s" % ("\n".join([f"|{key}|{value}|" for key, value in vars(args).items()]))
    )

    #set random seed
    np.random.seed(args.seed)
    tf.random.set_seed(args.seed)
    random.seed(args.seed)
    logger.info(f'Setting the network security environment')
    env = Network_Security_Environment(random_start=args.random_start, verbosity=args.verbosity)
    if args.scenario == "scenario1":
        env.process_cyst_config(scenario_configuration.configuration_objects)
    elif args.scenario == "scenario1_small":
        env.process_cyst_config(smaller_scenario_configuration.configuration_objects)
    elif args.scenario == "scenario1_tiny":
        env.process_cyst_config(tiny_scenario_configuration.configuration_objects)
    else:
        print("unknown scenario")
        exit(1)

    # define attacker goal and initial location
    if args.random_start:
        goal = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{"213.47.23.195":"random"}
        }
        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{"213.47.23.195","192.168.2.0/24"},
            "known_services":{},
            "known_data":{}
        }
    else:
        goal = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{"213.47.23.195":{("User1", "DataFromServer1")}}
        }

        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{"213.47.23.195","192.168.2.2"},
            "known_services":{},
            "known_data":{}
        }
    
    # Training
    logger.info(f'Initializing the environment')
    state = env.initialize(win_conditons=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps)
    logger.info(f'Creating the agent')
    #initialize agent
    agent = GNN_REINFORCE_Agent(env, args)
    
    agent.train()
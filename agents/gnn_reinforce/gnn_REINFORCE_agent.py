# Authors:  Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz    
import numpy as np
import argparse
import logging
import time

from random import choice, seed, choices
from timeit import default_timer as timer

# This is used so the agent can see the environment and game components
import sys
from os import path
sys.path.append( path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

#with the path fixed, we can import now
from env.network_security_game import Network_Security_Environment
from env.scenarios import scenario_configuration, smaller_scenario_configuration, tiny_scenario_configuration
import env.game_components as components

import os
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import tensorflow_gnn as tfgnn
import tensorflow as tf
from tensorflow_gnn.models.gcn import gcn_conv
tf.get_logger().setLevel('ERROR')

class GNN_REINFORCE_Agent:
    """
    Class implementing the REINFORCE algorithm with GNN as input layer
    """

    def __init__(self, env:Network_Security_Environment, args: argparse.Namespace):
        self.env = env
        self.args = args
        self._transition_mapping = env.get_all_actions()
        graph_schema = tfgnn.read_schema("schema.pbtxt")
        self._example_input_spec = tfgnn.create_graph_spec_from_schema_pb(graph_schema)
        run_name = f"netsecgame__GNN_Reinforce__{args.seed}__{int(time.time())}"
        self._tf_writer = tf.summary.create_file_writer("./logs/"+ run_name)

        #model building blocks
        def set_initial_node_state(node_set, node_set_name):
            d1 = tf.keras.layers.Dense(128,activation="relu")(node_set['node_type'])
            return tf.keras.layers.Dense(64,activation="relu")(d1)
        
        def dense_layer(units=64,l2_reg=0.1,dropout=0.25,activation='relu'):
            regularizer = tf.keras.regularizers.l2(l2_reg)
            return tf.keras.Sequential([tf.keras.layers.Dense(units, activation=activation, kernel_regularizer=regularizer, bias_regularizer=regularizer),  tf.keras.layers.Dropout(dropout)])

        #input
        input_graph = tf.keras.layers.Input(type_spec=self._example_input_spec, name="input_actor")
        #process node features with FC layer
        graph = tfgnn.keras.layers.MapFeatures(node_sets_fn=set_initial_node_state, name="preprocessing_actor")(input_graph)
        tmp = graph


        #Graph conv
        graph_updates = 3 # TODO Add to args
        for i in range(graph_updates):
            graph = gcn_conv.GCNHomGraphUpdate(units=128, add_self_loops=True, name=f"GCN_{i+1}")(graph)

        #### ACTOR ######
        # Pool to get a single vector representing the graph
        pooling = tfgnn.keras.layers.Pool(tfgnn.CONTEXT, "sum",node_set_name="nodes", name="pooling_actor")(graph)

        # Two hidden layers (Following the REINFORCE)
        hidden1 = tf.keras.layers.Dense(128, activation="relu", name="hidden1_actor")(pooling)
        hidden2 = tf.keras.layers.Dense(64, activation="relu", name="hidden2_actor")(hidden1)

        # Output layer
        out  = tf.keras.layers.Dense(len(self._transition_mapping), activation="softmax", name="output_logits")(hidden2)

        #Build the model
        self._model = tf.keras.Model(input_graph, out, name="Actor")
        self._model.compile(tf.keras.optimizers.Adam(learning_rate=args.lr))

        #baseline
        # #input
        # input_graph = tf.keras.layers.Input(type_spec=self._example_input_spec)
        # #process node features with FC layer
        # graph = tfgnn.keras.layers.MapFeatures(node_sets_fn=set_initial_node_state,)(input_graph)

        # #Graph conv
        # graph_updates = 3 # TODO Add to args
        # for i in range(graph_updates):
        #     graph = tfgnn.keras.layers.GraphUpdate(
        #         node_sets = {
        #             'nodes': tfgnn.keras.layers.NodeSetUpdate({
        #                 'related_to': tfgnn.keras.layers.SimpleConv(
        #                     message_fn = dense_layer(units=128), #TODO add num_units to args
        #                     reduce_type="sum",
        #                     receiver_tag=tfgnn.TARGET)},
        #                 tfgnn.keras.layers.NextStateFromConcat(dense_layer(64)))}, name=f"graph_update_{i}")(graph)  #TODO add num_units to args

        #SHARE embedding from ACTOR
        # # Pool to get a single vector representing the graph
        pooling = tfgnn.keras.layers.Pool(tfgnn.CONTEXT, "sum",node_set_name="nodes")(graph)
        # Two hidden layers (Followin the REINFORCE)
        hidden2 = tf.keras.layers.Dense(64, activation="relu", name="baseline_hidden")(pooling)

        # Output layer
        out_baseline  = tf.keras.layers.Dense(1, activation=None, name="baseline_value")(hidden2)

        #Build the model
        self._baseline = tf.keras.Model(input_graph, out_baseline, name="Baseline model")
        self._baseline.compile(tf.keras.optimizers.Adam(learning_rate=args.lr), loss=tf.losses.MeanSquaredError())


        self._model.summary()
        self._baseline.summary()


    def _create_graph_tensor(self, node_features, controlled, edges):
        src,trg = [x[0] for x in edges],[x[1] for x in edges]


        node_f =  np.hstack([np.array(np.eye(6)[node_features], dtype='int32'), np.array([controlled], dtype='int32').T])
        graph_tensor =  tfgnn.GraphTensor.from_pieces(
            node_sets = {"nodes":tfgnn.NodeSet.from_fields(

                sizes = [len(node_features)],
                features = {"node_type":node_f} # one-hot encoded node features TODO remove hardcoded max value
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

    def _build_batch_graph(self, state_graphs):

        def _gen_from_list():
            for g in state_graphs:
                yield g
        ds = tf.data.Dataset.from_generator(_gen_from_list, output_signature=self._example_input_spec)
        graph_tensor_batch = next(iter(ds.batch(len(state_graphs))))
        scalar_graph_tensor = graph_tensor_batch.merge_batch_to_components()
        return scalar_graph_tensor

    def _get_discounted_rewards(self, rewards:list)->list:
        returns = np.array([self.args.gamma ** i * rewards[i] for i in range(len(rewards))])
        returns =  np.flip(np.cumsum(np.flip(returns)))
        return returns.tolist()

    @tf.function
    def predict(self, state_graph, training=True):
        return self._model(state_graph, training=training)

    #@tf.function
    def _make_training_step_actor(self, inputs, labels, weights)->None:
        #print("Updating actor model")
        #perform training step
        with tf.GradientTape() as tape:
            logits = self.predict(inputs, training=True)
            cce = tf.keras.losses.SparseCategoricalCrossentropy(from_logits=False)
            loss = cce(labels, logits, sample_weight=weights)
        grads = tape.gradient(loss, self._model.trainable_weights)
        tf.summary.experimental.set_step(self._model.optimizer.iterations)
        with self._tf_writer.as_default():
                for index, grad in enumerate(grads):
                    tf.summary.histogram("{}-grad".format(index), grad[index])
                tf.summary.scalar('train/CCE_actor',loss, step=self._model.optimizer.iterations)
                tf.summary.scalar('train/avg_weights_actor',np.mean(weights), step=self._model.optimizer.iterations)
        #grads, _ = tf.clip_by_global_norm(grads, 5.0)
        self._model.optimizer.apply_gradients(zip(grads, self._model.trainable_weights))

    def _make_training_step_baseline(self, inputs, rewards)->None:
        #perform training step
        with tf.GradientTape() as tape:
            values = self._baseline(inputs, training=True)
            loss = self._baseline.loss(values, rewards)
        grads = tape.gradient(loss, self._baseline.trainable_weights)
        with self._tf_writer.as_default():
            tf.summary.scalar('train/MSE_baseline',loss, step=self._baseline.optimizer.iterations)
        #grads, _ = tf.clip_by_global_norm(grads, 5.0)
        self._baseline.optimizer.apply_gradients(zip(grads, self._baseline.trainable_weights))

    def _preprocess_inputs(self, replay_buffer):
        raise NotImplementedError

    def save_model(self, filename):
        raise NotImplementedError

    def load_model(self, filename):
        raise NotImplementedError

    #@profile
    def train(self):
        for episode in range(self.args.episodes):
            #collect data
            batch_states, batch_actions, batch_returns = [], [], []
            while len(batch_states) < args.batch_size:
                #perform episode
                states, actions, rewards = [], [], []
                state, done = env.reset().state, False

                while not done:
                    state_node_f,controlled, state_edges,_ = state.as_graph
                    state_g = self._create_graph_tensor(state_node_f, controlled, state_edges)
                    #predict action probabilities
                    probabilities = self.predict(state_g)
                    #print(probabilities)
                    assert not np.isnan(np.sum(probabilities))
                    probabilities = tf.squeeze(tf.nn.softmax(probabilities))
                    probabilities = tf.squeeze(probabilities)


                    if np.random.random() < 0.85:
                        action = choices([x for x in range(len(self._transition_mapping))], weights=probabilities, k=1)[0]
                    else:
                        action = choice([x for x in range(len(self._transition_mapping))])
                    #select action and perform it
                    next_state = self.env.step(self._transition_mapping[action])


                    #print(self._transition_mapping[action])
                    states.append(state_g)
                    actions.append(action)
                    rewards.append(next_state.reward)

                    #move to the next state
                    state = next_state.state
                    done = next_state.done

                discounted_returns = self._get_discounted_rewards(rewards)

                batch_states += states
                batch_actions += actions
                batch_returns += discounted_returns         

            # prepare batch data
            batch_returns = np.array(batch_returns)
            scalar_graph_tensor = self._build_batch_graph(batch_states)
            
            #perform training step
            baseline = tf.squeeze(self._baseline(scalar_graph_tensor))
            assert not np.isnan(np.sum(baseline))
            self._make_training_step_baseline(scalar_graph_tensor, batch_returns)
            updated_batch_returns = batch_returns-baseline
            self._make_training_step_actor(scalar_graph_tensor, batch_actions, updated_batch_returns)
        
            #evaluate
            if episode > 0 and episode % args.eval_each == 0:
                returns = self.get_eval_retrurns(self.args.eval_for)
                print(f"Evaluation after {episode} episodes (mean of {len(returns)} runs): {np.mean(returns)}+-{np.std(returns)}")
                with self._tf_writer.as_default():
                    tf.summary.scalar('test/eval_win', np.mean(returns), step=episode)
    
    def evaluate(self):
        print(f"Starting final evaluation ({self.args.final_eval_for} episodes)")
        eval_returns = self.get_eval_retrurns(num_eval_episodes=self.args.final_eval_for)
        print(f"Evaluation finished - (mean of {len(eval_returns)} runs): {np.mean(eval_returns)}+-{np.std(eval_returns)}")
    
    def get_eval_retrurns(self, num_eval_episodes) -> list:
        eval_returns = []
        for _ in range(num_eval_episodes):
            state, done = env.reset().state, False
            ret = 0
            while not done:
                state_node_f,controlled, state_edges,_ = state.as_graph
                state_g = self._create_graph_tensor(state_node_f,controlled,state_edges)
                #predict action probabilities
                probabilities = self.predict(state_g)
                probabilities = tf.squeeze(probabilities)
                action_idx = np.argmax(probabilities)
                action = self._transition_mapping[action_idx]
                
                #select action and perform it
                next_state = self.env.step(action)
                ret += next_state.reward
                state = next_state.state
                done = next_state.done

            eval_returns.append(ret)
        return  eval_returns



if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    #env arguments
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=30, type=int)
    parser.add_argument("--defender", help="Is defender present", default=False, action="store_true")
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1", type=str)
    parser.add_argument("--random_start", help="Sets evaluation length", default=False, action="store_true")
    parser.add_argument("--verbosity", help="Sets verbosity of the environment", default=0, type=int)
    parser.add_argument("--seed", help="Sets the random seed", type=int, default=42)

    #model arguments
    parser.add_argument("--episodes", help="Sets number of training episodes", default=5000, type=int)
    parser.add_argument("--gamma", help="Sets gamma for discounting", default=0.9, type=float)
    parser.add_argument("--batch_size", help="Batch size for NN training", type=int, default=64)
    parser.add_argument("--lr", help="Learnining rate of the NN", type=float, default=1e-4)

    #training arguments
    parser.add_argument("--eval_each", help="During training, evaluate every this amount of episodes.", default=200, type=int)
    parser.add_argument("--eval_for", help="Sets evaluation length", default=100, type=int)
    parser.add_argument("--final_eval_for", help="Sets evaluation length", default=1000, type=int )
    args = parser.parse_args()
    args.filename = "GNN_Reinforce_Agent_" + ",".join(("{}={}".format(key, value) for key, value in sorted(vars(args).items()) if key not in ["evaluate", "eval_each", "eval_for"])) + ".pickle"

    logging.basicConfig(filename='GNN_Reinforce_Agent.log', filemode='w', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.INFO)
    logger = logging.getLogger('GNN_Reinforce_Agent')

    #set random seed
    np.random.seed(args.seed)
    tf.random.set_seed(args.seed)
    seed(args.seed)


    logger.info(f'Setting the network security environment')
    env = Network_Security_Environment(random_start=args.random_start, verbosity=args.verbosity)
    if args.scenario == "scenario1":
        cyst_config = scenario_configuration.configuration_objects
    elif args.scenario == "scenario1_small":
        cyst_config = smaller_scenario_configuration.configuration_objects
    elif args.scenario == "scenario1_tiny":
        cyst_config = tiny_scenario_configuration.configuration_objects
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
            "known_data":{components.IP("213.47.23.195"):"random"}        }
        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{components.IP("213.47.23.195")},
            "known_services":{},
            "known_data":{}
        }
    else:
        goal = {
            "known_networks":set(),
            "known_hosts":{},
            "controlled_hosts":{components.IP("192.168.1.2")},
            "known_services":{},
            "known_data":{components.IP("213.47.23.195"):{components.Data("User1", "DataFromServer1")}},
        }

        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{components.IP("213.47.23.195"),components.IP("192.168.2.2")},
            "known_services":{},
            "known_data":{}
        }

    # Training
    logger.info(f'Initializing the environment')
    state = env.initialize(win_conditions=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps, cyst_config=cyst_config)
    logger.info(f'Creating the agent')
    
    # #initialize agent
    agent = GNN_REINFORCE_Agent(env, args)
    agent.train()
    agent.evaluate()

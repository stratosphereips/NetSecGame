# Author:  Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
import numpy as np
import argparse
import logging
import time
import os
import sys
import tensorflow_gnn as tfgnn
import tensorflow as tf
from random import choice, choices
from tensorflow_gnn.models.gcn import gcn_conv

# This is used so the agent can see the environment and game components
from os import path

sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))

# with the path fixed, we can import now
from env.network_security_game import NetworkSecurityEnvironment
from env.game_components import Action, ActionType, GameState, IP, Network, Data

os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
tf.get_logger().setLevel("ERROR")


class GnnReinforceAgent:
    """
    Class implementing the REINFORCE algorithm with GNN as input layer
    """

    def __init__(self, env: NetworkSecurityEnvironment, args: argparse.Namespace):
        self.env = env
        self.args = args
        self._transition_mapping = env.get_all_actions()
        graph_schema = tfgnn.read_schema(
            os.path.join(path.dirname(path.abspath(__file__)), "./schema.pbtxt")
        )
        self._example_input_spec = tfgnn.create_graph_spec_from_schema_pb(graph_schema)
        run_name = f"netsecgame__GNN_Reinforce__{env.seed}__{int(time.time())}"
        self._tf_writer = tf.summary.create_file_writer("./logs/" + run_name)
        self._actor_train_acc_metric = tf.keras.metrics.SparseCategoricalAccuracy()

        # model building blocks
        def set_initial_node_state(node_set, node_set_name):
            d1 = tf.keras.layers.Dense(128, activation="relu")(node_set["node_type"])
            return tf.keras.layers.Dense(64, activation="relu")(d1)

        # input
        input_graph = tf.keras.layers.Input(
            type_spec=self._example_input_spec, name="input_actor"
        )
        input_action_mask = tf.keras.layers.Input(
            shape=(None, len(self._transition_mapping)), name="Action_mask"
        )

        # process node features with FC layer
        graph = tfgnn.keras.layers.MapFeatures(
            node_sets_fn=set_initial_node_state, name="preprocessing_actor"
        )(input_graph)

        # Graph conv
        for i in range(args.graph_updates):
            graph = gcn_conv.GCNHomGraphUpdate(
                units=128, add_self_loops=True, name=f"GCN_{i+1}"
            )(graph)

        node_emb = tfgnn.keras.layers.Readout(node_set_name="nodes")(graph)

        #### ACTOR ######
        # Pool to get a single vector representing the graph
        pooling = tfgnn.keras.layers.Pool(
            tfgnn.CONTEXT, "sum", node_set_name="nodes", name="pooling_actor"
        )(graph)

        # Two hidden layers (Following the REINFORCE)
        hidden1 = tf.keras.layers.Dense(128, activation="relu", name="hidden1_actor")(
            pooling
        )
        hidden2 = tf.keras.layers.Dense(64, activation="relu", name="hidden2_actor")(
            hidden1
        )

        # Output layer
        logits = tf.keras.layers.Dense(
            len(self._transition_mapping), activation=None, name="output_logits"
        )(hidden2)
        out = tf.keras.layers.Softmax()(logits, mask=input_action_mask)

        # Build the model
        self._model = tf.keras.Model(
            [input_graph, input_action_mask], [out, node_emb], name="Actor"
        )
        self._model.compile(tf.keras.optimizers.Adam(learning_rate=args.lr_actor))
        self._model.summary()

        #### BASEINE ######

        # SHARE embedding from ACTOR
        # # Pool to get a single vector representing the graph
        pooling = tfgnn.keras.layers.Pool(tfgnn.CONTEXT, "sum", node_set_name="nodes")(
            graph
        )
        # Two hidden layers (Following the REINFORCE)
        hidden2 = tf.keras.layers.Dense(64, activation="relu", name="baseline_hidden")(
            pooling
        )

        # Output layer
        out_baseline = tf.keras.layers.Dense(1, activation=None, name="baseline_value")(
            hidden2
        )

        # Build the model
        self._baseline = tf.keras.Model(
            input_graph, out_baseline, name="Baseline_model"
        )
        self._baseline.compile(
            tf.keras.optimizers.Adam(learning_rate=args.lr_baseline),
            loss=tf.losses.MeanSquaredError(),
        )
        self._baseline.summary()

    def _create_graph_tensor(self, node_features, controlled, edges):
        src, trg = [x[0] for x in edges], [x[1] for x in edges]

        node_f = np.hstack(
            [
                np.array(np.eye(6)[node_features], dtype="int32"),
                np.array([controlled], dtype="int32").T,
            ]
        )
        graph_tensor = tfgnn.GraphTensor.from_pieces(
            node_sets={
                "nodes": tfgnn.NodeSet.from_fields(
                    sizes=[len(node_features)],
                    features={
                        "node_type": node_f
                    },  # one-hot encoded node features TODO remove hardcoded max value
                )
            },
            edge_sets={
                "related_to": tfgnn.EdgeSet.from_fields(
                    sizes=[len(src)],
                    features={},
                    adjacency=tfgnn.Adjacency.from_indices(
                        source=("nodes", np.array(src, dtype="int32")),
                        target=("nodes", np.array(trg, dtype="int32")),
                    ),
                )
            },
        )
        return graph_tensor

    def _build_batch_graph(self, state_graphs):
        """
        Method taking a list of graphs and and producing a TFGNN batched graph
        """
        def _gen_from_list():
            for g in state_graphs:
                yield g

        ds = tf.data.Dataset.from_generator(
            _gen_from_list, output_signature=self._example_input_spec
        )
        graph_tensor_batch = next(iter(ds.batch(len(state_graphs))))
        scalar_graph_tensor = graph_tensor_batch.merge_batch_to_components()
        return scalar_graph_tensor

    def _get_discounted_rewards(self, rewards: list) -> list:
        """ Method for discounting rewards with gamma for the REINFORCE algorithm"""
        returns = np.array(
            [self.args.gamma**i * rewards[i] for i in range(len(rewards))]
        )
        returns = np.flip(np.cumsum(np.flip(returns)))
        return returns.tolist()

    def _generate_valid_actions(self, state: GameState) -> set:
        """ Method producing a set of action that can be taken in a given state"""
        
        valid_actions = set()
        # Network Scans
        for network in state.known_networks:
            # TODO ADD neighbouring networks
            valid_actions.add(
                Action(ActionType.ScanNetwork, params={"target_network": network})
            )
        # Service Scans
        for host in state.known_hosts:
            valid_actions.add(
                Action(ActionType.FindServices, params={"target_host": host})
            )
        # Service Exploits
        for host, service_list in state.known_services.items():
            for service in service_list:
                valid_actions.add(
                    Action(
                        ActionType.ExploitService,
                        params={"target_host": host, "target_service": service},
                    )
                )
        # Data Scans
        for host in state.controlled_hosts:
            valid_actions.add(Action(ActionType.FindData, params={"target_host": host}))

        # Data Exfiltration
        for src_host, data_list in state.known_data.items():
            for data in data_list:
                for trg_host in state.controlled_hosts:
                    if trg_host != src_host:
                        valid_actions.add(
                            Action(
                                ActionType.ExfiltrateData,
                                params={
                                    "target_host": trg_host,
                                    "source_host": src_host,
                                    "data": data,
                                },
                            )
                        )
        return valid_actions

    def get_valid_action_mask(self, state: GameState):
        """ Method producing mask for valid actions
          in self._transition_mapping based on a given state"""

        mask = np.zeros(len(self._transition_mapping))
        valid_actions = self._generate_valid_actions(state)
        for k, action in self._transition_mapping.items():
            is_member = action in valid_actions
            if is_member:
                mask[k] = 1
        mask = np.array(mask, dtype=bool)
        return mask

    @tf.function(experimental_relax_shapes=True)
    def predict(self, state_graph, valid_action_mask, training=True):
        return self._model([state_graph, valid_action_mask], training=training)

    # @tf.function(experimental_relax_shapes=True)
    def _make_training_step_actor(self, inputs, labels, weights, masks) -> None:
        # perform training step
        with tf.GradientTape() as tape:
            logits, node_emb = self.predict(inputs, masks, training=True)
            cce = tf.keras.losses.SparseCategoricalCrossentropy(from_logits=False)
            loss = cce(labels, logits, sample_weight=weights)
        grads = tape.gradient(loss, self._model.trainable_weights)
        self._model.optimizer.apply_gradients(zip(grads, self._model.trainable_weights))
        self._actor_train_acc_metric.update_state(labels, logits, sample_weight=weights)
        with self._tf_writer.as_default():
            tf.summary.scalar(
                "train/CCE_actor", loss, step=self._model.optimizer.iterations
            )
            tf.summary.scalar(
                "train/avg_weights_actor",
                tf.reduce_mean(weights),
                step=self._model.optimizer.iterations,
            )
            tf.summary.scalar(
                "train/mean_std_node_em",
                tf.reduce_mean(tf.math.reduce_std(node_emb, axis=0)),
                step=self._model.optimizer.iterations,
            )

    # @tf.function()
    def _make_training_step_baseline(self, inputs, rewards) -> None:
        # perform training step
        with tf.GradientTape() as tape:
            values = self._baseline(inputs, training=True)
            loss = self._baseline.loss(values, rewards)
        grads = tape.gradient(loss, self._baseline.trainable_weights)
        with self._tf_writer.as_default():
            tf.summary.scalar(
                "train/MSE_baseline", loss, step=self._baseline.optimizer.iterations
            )
        self._baseline.optimizer.apply_gradients(
            zip(grads, self._baseline.trainable_weights)
        )

    def _preprocess_inputs(self, replay_buffer):
        raise NotImplementedError

    def save_model(self, filename):
        self._model.save(filename)

    def load_model(self, filename):
        self._model = tf.keras.saving.load_model(filename)
        self._model.compile(tf.keras.optimizers.Adam(learning_rate=args.lr_actor))

    def train(self):
        self._actor_train_acc_metric.reset_state()
        for episode in range(self.args.episodes):
            # collect data
            batch_states, batch_actions, batch_returns, batch_masks = [], [], [], []
            while len(batch_states) < args.batch_size:
                # perform episode
                states, actions, rewards, masks = [], [], [], []
                state, done = env.reset().state, False

                while not done:
                    state_node_f, controlled, state_edges, _ = state.as_graph
                    state_g = self._create_graph_tensor(
                        state_node_f, controlled, state_edges
                    )

                    # valida action map
                    mask = self.get_valid_action_mask(state)

                    # predict action probabilities
                    logits, node_emb = self.predict(state_g, [mask])

                    # mask probabilities with valid actions
                    probabilities = tf.squeeze(logits)

                    action = choices(
                        [x for x in range(len(self._transition_mapping))],
                        weights=probabilities,
                        k=1,
                    )[0]
                    # select action and perform it
                    next_state = self.env.step(self._transition_mapping[action])

                    # append step data to lists
                    states.append(state_g)
                    actions.append(action)
                    rewards.append(next_state.reward)
                    masks.append(mask)

                    # move to the next state
                    state = next_state.state
                    done = next_state.done

                # episode over, add data to replay buffer
                discounted_returns = self._get_discounted_rewards(rewards)
                batch_states += states
                batch_actions += actions
                batch_returns += discounted_returns
                batch_masks += masks

            # prepare batch data
            batch_returns = np.array(batch_returns)
            batch_masks = np.array(batch_masks)

            scalar_graph_tensor = self._build_batch_graph(batch_states)

            # update returns with baseline
            baseline = tf.squeeze(self._baseline(scalar_graph_tensor))
            updated_batch_returns = batch_returns - baseline
            # perform training step
            self._make_training_step_actor(
                scalar_graph_tensor, batch_actions, updated_batch_returns, batch_masks
            )
            self._make_training_step_baseline(scalar_graph_tensor, batch_returns)

            with self._tf_writer.as_default():
                tf.summary.scalar(
                    "train/accuracy",
                    self._actor_train_acc_metric.result(),
                    step=episode,
                )
            # evaluate
            if episode > 0 and episode % args.eval_each == 0:
                returns = self.get_eval_retrurns(self.args.eval_for)
                print(
                    f"Evaluation after {episode} episodes (mean of {len(returns)} runs): {np.mean(returns)}+-{np.std(returns)}"
                )
                with self._tf_writer.as_default():
                    tf.summary.scalar("test/eval_win", np.mean(returns), step=episode)
                # self.save_model('./gnn_reinforce_actor_trained_tmp')

    def evaluate(self):
        print(f"Starting final evaluation ({self.args.final_eval_for} episodes)")
        eval_returns = self.get_eval_retrurns(
            num_eval_episodes=self.args.final_eval_for
        )
        print(
            f"Evaluation finished - (mean of {len(eval_returns)} runs): {np.mean(eval_returns)}+-{np.std(eval_returns)}"
        )

    def get_eval_retrurns(self, num_eval_episodes) -> list:
        eval_returns = []
        for _ in range(num_eval_episodes):
            state, done = env.reset().state, False
            ret = 0
            while not done:
                state_node_f, controlled, state_edges, _ = state.as_graph
                state_g = self._create_graph_tensor(
                    state_node_f, controlled, state_edges
                )
                mask = self.get_valid_action_mask(state)
                # predict action probabilities

                logits, node_emb = self.predict(state_g, [mask], training=False)

                # mask probabilities with valid actions
                probabilities = tf.squeeze(logits)
                action_idx = np.argmax(probabilities)
                action = self._transition_mapping[action_idx]

                # select action and perform it
                next_state = self.env.step(action)
                ret += next_state.reward
                state = next_state.state
                done = next_state.done

            eval_returns.append(ret)
        return eval_returns


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # task config file
    parser.add_argument(
        "--task_config_file",
        help="Reads the task definition from a configuration file",
        default=path.join(path.dirname(__file__), "netsecenv-task.yaml"),
        action="store",
        required=False,
    )

    # model arguments
    parser.add_argument(
        "--gamma", help="Sets gamma for discounting", default=0.9, type=float
    )
    parser.add_argument(
        "--graph_updates", help="Number of GCN updates", type=int, default=3
    )
    parser.add_argument(
        "--batch_size", help="Batch size for NN training", type=int, default=128
    )
    parser.add_argument(
        "--lr_actor", help="Learnining rate of the NN", type=float, default=1e-4
    )
    parser.add_argument(
        "--lr_baseline", help="Learnining rate of the NN", type=float, default=1e-4
    )

    # training arguments
    parser.add_argument(
        "--episodes", help="Sets number of training episodes", default=10000, type=int
    )
    parser.add_argument(
        "--eval_each",
        help="During training, evaluate every this amount of episodes.",
        default=250,
        type=int,
    )
    parser.add_argument(
        "--eval_for", help="Sets evaluation length", default=500, type=int
    )
    parser.add_argument(
        "--final_eval_for", help="Sets evaluation length", default=1000, type=int
    )

    args = parser.parse_args()
    args.filename = (
        "GNN_Reinforce_Agent_"
        + ",".join(
            (
                "{}={}".format(key, value)
                for key, value in sorted(vars(args).items())
                if key not in ["evaluate", "eval_each", "eval_for"]
            )
        )
        + ".pickle"
    )

    logging.basicConfig(
        filename="GNN_Reinforce_Agent_TMP.log",
        filemode="w",
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
        level=logging.INFO,
    )
    logger = logging.getLogger("GNN_Reinforce_Agent")

    logger.info("Setting the network security environment")
    env = NetworkSecurityEnvironment(args.task_config_file)
    tf.random.set_seed(env.seed)
    state = env.reset()

    # Training
    logger.info("Creating the agent")

    # #initialize agent
    agent = GnnReinforceAgent(env, args)
    agent.train()
    agent.evaluate()
    agent.evaluate()

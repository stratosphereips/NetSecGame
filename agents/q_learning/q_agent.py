# Authors:  Ondrej Lukas - ondrej.lukas@aic.fel.cvut.cz
#           Arti       
#           Sebastian Garcia. sebastian.garcia@agents.fel.cvut.cz
import sys
from os import path
sys.path.append( path.dirname(path.dirname( path.abspath(__file__) ) ))
import env.game_components as components
import numpy as np
#from random import choice, seed
import random
import pickle
import sys
import argparse
from timeit import default_timer as timer
import logging
from torch.utils.tensorboard import SummaryWriter
import time

# This is used so the agent can see the environment and game components
import sys
from os import path
sys.path.append( path.dirname(path.dirname(path.dirname( path.abspath(__file__) ) ) ))

#with the path fixed, we can import now
from env.network_security_game import Network_Security_Environment
from env.scenarios import scenario_configuration, smaller_scenario_configuration, tiny_scenario_configuration
from env.game_components import *

class QAgent:
    """
    Class implementing the Q-Learning algorithm
    """

    def __init__(self, env, alpha=0.1, gamma=0.6, epsilon=0.1):
        self.env = env
        self.alpha = alpha
        self.gamma = gamma 
        self.epsilon = epsilon
        self.q_values = {}

    def store_q_table(self,filename):
        with open(filename, "wb") as f:
            pickle.dump(self.q_values, f)
    
    def load_q_table(self,filename):
        with open(filename, "rb") as f:
            self.q_values = pickle.load(f)
    
    def get_valid_actions(self, state) -> list:
        """
        Given a state, choose the valid actions
        """
        valid_actions = set()
        #Network Scans
        for network in state.known_networks:
            # TODO ADD neighbouring networks
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
    
    def move(self, observation:Observation, testing=False) -> Action:
        state = observation.state
        actions = self.get_valid_actions(state)
        state = '1'
        logger.info(f'The valid actions in this state are: {[str(action) for action in actions]}')
        if random.uniform(0, 1) <= self.epsilon and not testing:
            action = random.choice(actions)
            if (state, action) not in self.q_values:
                self.q_values[state, action] = 0
            return action
        else: #greedy play
            #select the acion with highest q_value
            tmp = dict(((state,action), self.q_values.get((state,action), 0)) for action in actions)
            max_q_key = max(tmp, key=tmp.get)
            if max_q_key not in self.q_values:
                self.q_values[max_q_key] = 0
            return max_q_key[1]
    
    def max_action_q(self, observation:Observation) -> Action:
        state = observation.state
        actions = self.get_valid_actions(state)
        state = '1'
        tmp = dict(((state,a), self.q_values.get((state,a), 0)) for a in actions)
        return tmp[max(tmp,key=tmp.get)] #return maximum Q_value for a given state (out of available actions)
    
    def play(self, observation:Observation, testing=False) -> tuple:
        """
        Play a complete episode from beginning to end

        1. Get next action 
        2. Step and get next state
        3. Get max action of next state
        4. Update q table
        5. Store rewards
        6. loop
        """
        rewards = 0
        while not observation.done:
            # Select action
            action = self.move(observation, testing)
            # Get next state of the environment
            next_observation = self.env.step(action)           

            # Find max Q-Value for next state
            if next_observation.done:
                max_q_next = 0
            else:
                max_q_next = self.max_action_q(next_observation)

            # Update q values
            state = observation.state
            # This is broken dont use!
            state = '1'
            new_Q = self.q_values[state, action] + self.alpha*(next_observation.reward + self.gamma * max_q_next - self.q_values[state, action])
            self.q_values[state, action] = new_Q
            # This is broken dont use!
            state = observation.state

            
            rewards += next_observation.reward

            # Move to next observation
            observation = next_observation

        # If state is 'done' this should throw an error of missing variables
        return rewards, self.env.is_goal(state), self.env.detected, self.env.timestamp

    def evaluate(self, observation:Observation) -> tuple: #(cumulative_reward, goal?, detected?, num_steps)
        """
        Evaluate the agent so far for one episode

        Do without learning
        """
        return_value = 0
        while not observation.done:
            action = self.move(observation, testing=True)
            next_observation = self.env.step(action)
            return_value += next_observation.reward
            observation = next_observation

        # Has to return
        # 1. returns
        # 2. if it is a win
        # 3. if it is was detected
        # 4. amount of steps when finished
        wins = next_observation.reward > 0
        detected = self.env.detected
        steps = self.env.timestamp
        return return_value, wins, detected, steps


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--episodes", help="Sets number of training episodes", default=1000, type=int)
    parser.add_argument("--epsilon", help="Sets epsilon for exploration", default=0.2, type=float)
    parser.add_argument("--gamma", help="Sets gamma for Q learing", default=0.9, type=float)
    parser.add_argument("--alpha", help="Sets alpha for learning rate", default=0.3, type=float)
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=25, type=int)
    parser.add_argument("--defender", help="Is defender present", default=True, action=argparse.BooleanOptionalAction)
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1", type=str)
    parser.add_argument("--test", help="Do not train, only run test", default=False, action="store_true")
    parser.add_argument("--eval_each", help="During training, evaluate every this amount of episodes. Evaluation is for 100 episodes each time.", default=50, type=int)
    parser.add_argument("--eval_for", help="Sets evaluation length", default=100, type=int)
    parser.add_argument("--test_for", help="Sets evaluation length", default=1000, type=int)
    parser.add_argument("--random_start", help="Sets if starting position and goal data is randomized", default=True, action=argparse.BooleanOptionalAction)
    parser.add_argument("--verbosity", help="Sets verbosity of the environment", default=0, type=int)
    parser.add_argument("--seed", help="Sets the random seed", type=int, default=42)
    parser.add_argument("--filename", help="Load previous model file", type=str, default=False)
    args = parser.parse_args()
    args.filename = "QAgent_" + ",".join(("{}={}".format(key, value) for key, value in sorted(vars(args).items()) if key not in ["evaluate", "eval_each", "eval_for"])) + ".pickle"

    # Remove all handlers associated with the root logger object.
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    logging.basicConfig(filename='q_agent.log', filemode='a', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.INFO)
    logger = logging.getLogger('Q-agent')

    # Setup tensorboard
    run_name = f"netsecgame__qlearning__{args.seed}__{int(time.time())}"
    writer = SummaryWriter(f"agents/tensorboard-logs/logs/{run_name}")
    writer.add_text(
        "hypherparameters", 
        "|param|value|\n|-|-|\n%s" % ("\n".join([f"|{key}|{value}|" for key, value in vars(args).items()]))
    )

    random.seed(args.seed)
    np.random.seed(args.seed)

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
            "known_data":{components.IP("213.47.23.195"):"random"}
        }
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
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{components.IP("213.47.23.195"):components.Data("User1", "DataFromServer1")}
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
    observation = env.initialize(win_conditons=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps, agent_seed=args.seed, cyst_config=cyst_config)
    logger.info(f'Creating the agent')
    agent = QAgent(env, args.alpha, args.gamma, args.epsilon)
    try:
        # Load a previous qtable from a pickled file
        logger.info(f'Loading a previous Qtable')
        agent.load_q_table(args.filename)
    except FileNotFoundError:
        logger.info(f"No previous qtable file found to load, starting with an emptly zeroed qtable")
    
    # If we are not evaluating the model
    if not args.test:
        # Run for some episodes 
        logger.info(f'Starting the training')
        for i in range(1, args.episodes + 1):
            # Reset
            observation = env.reset()
            # Play complete round
            ret, win,_,_ = agent.play(observation)
            logger.info(f'Reward: {ret}, Win:{win}')
            # Every X episodes, eval
            if i % args.eval_each == 0:
                wins = 0
                detected = 0
                returns = []
                num_steps = [] 
                num_win_steps = []
                num_detected_steps = []
                for j in range(args.eval_for):
                    observation = env.reset()
                    ret, win, detection, steps = agent.evaluate(observation)
                    if win:
                        wins += 1
                        num_win_steps += [steps]
                    if detection:
                        detected += 1
                        num_detected_steps += [steps]
                    returns += [ret]
                    num_steps += [steps]

                eval_win_rate = (wins/(args.eval_for+1))*100
                eval_detection_rate = (detected/(args.eval_for+1))*100
                eval_average_returns = np.mean(returns)
                eval_std_returns = np.std(returns)
                eval_average_episode_steps = np.mean(num_steps)
                eval_std_episode_steps = np.std(num_steps)
                eval_average_win_steps = np.mean(num_win_steps)
                eval_std_win_steps = np.std(num_win_steps)
                eval_average_detected_steps = np.mean(num_detected_steps)
                eval_std_detected_steps = np.std(num_detected_steps)

                text = f'''Evaluated after {i} episodes, for {args.eval_for} episodes. 
                    Wins={wins}, 
                    Detections={detected}, 
                    winrate={eval_win_rate:.3f}%, 
                    detection_rate={eval_detection_rate:.3f}%, 
                    average_returns={eval_average_returns:.3f} +- {eval_std_returns:.3f}, 
                    average_episode_steps={eval_average_episode_steps:.3f} +- {eval_std_episode_steps:.3f}, 
                    average_win_steps={eval_average_win_steps:.3f} +- {eval_std_win_steps:.3f},
                    average_detected_steps={eval_average_detected_steps:.3f} +- {eval_std_detected_steps:.3f}
                    '''
                print(text)
                logger.info(text)
                # Store in tensorboard
                writer.add_scalar("charts/eval_avg_win_rate", eval_win_rate, i)
                writer.add_scalar("charts/eval_avg_detection_rate", eval_detection_rate, i)
                writer.add_scalar("charts/eval_avg_returns", eval_average_returns , i)
                writer.add_scalar("charts/eval_std_returns", eval_std_returns , i)
                writer.add_scalar("charts/eval_avg_episode_steps", eval_average_episode_steps , i)
                writer.add_scalar("charts/eval_std_episode_steps", eval_std_episode_steps , i)
                writer.add_scalar("charts/eval_avg_win_steps", eval_average_win_steps , i)
                writer.add_scalar("charts/eval_std_win_steps", eval_std_win_steps , i)
                writer.add_scalar("charts/eval_avg_detected_steps", eval_average_detected_steps , i)
                writer.add_scalar("charts/eval_std_detected_steps", eval_std_detected_steps , i)

        # Store the q table on disk
        agent.store_q_table(args.filename)

    # Test
    wins = 0
    detected = 0
    returns = []
    num_steps = []
    num_win_steps = []  
    num_detected_steps = []
    for i in range(args.test_for + 1):
        observation = env.reset()
        ret, win, detection, steps = agent.evaluate(observation)
        if win:
            wins += 1
            num_win_steps += [steps]
        if detection:
            detected +=1
            num_detected_steps += [steps]
        returns += [ret]
        num_steps += [steps]
  
        test_win_rate = (wins/(args.test_for+1))*100
        test_detection_rate = (detected/(args.test_for+1))*100
        test_average_returns = np.mean(returns)
        test_std_returns = np.std(returns)
        test_average_episode_steps = np.mean(num_steps)
        test_std_episode_steps = np.std(num_steps)
        test_average_win_steps = np.mean(num_win_steps)
        test_std_win_steps = np.std(num_win_steps)
        test_average_detected_steps = np.mean(num_detected_steps)
        test_std_detected_steps = np.std(num_detected_steps)


        # Print and report every 100 test episodes
        if i % 100 == 0 and i != 0:
            text = f'''Test results after {i} episodes. 
                Wins={wins}, 
                Detections={detected}, 
                winrate={test_win_rate:.3f}%, 
                detection_rate={test_detection_rate:.3f}%, 
                average_returns={test_average_returns:.3f} +- {test_std_returns:.3f}, 
                average_episode_steps={test_average_episode_steps:.3f} +- {test_std_episode_steps:.3f}, 
                average_win_steps={test_average_win_steps:.3f} +- {test_std_win_steps:.3f},
                average_detected_steps={test_average_detected_steps:.3f} +- {test_std_detected_steps:.3f}
                '''

            print(text)
            logger.info(text)

        # Store in tensorboard
        writer.add_scalar("charts/test_avg_win_rate", test_win_rate, i)
        writer.add_scalar("charts/test_avg_detection_rate", test_detection_rate, i)
        writer.add_scalar("charts/test_avg_returns", test_average_returns , i)
        writer.add_scalar("charts/test_std_returns", test_std_returns , i)
        writer.add_scalar("charts/test_avg_episode_steps", test_average_episode_steps , i)
        writer.add_scalar("charts/test_std_episode_steps", test_std_episode_steps , i)
        writer.add_scalar("charts/test_avg_win_steps", test_average_win_steps , i)
        writer.add_scalar("charts/test_std_win_steps", test_std_win_steps , i)
        writer.add_scalar("charts/test_avg_detected_steps", test_average_detected_steps , i)
        writer.add_scalar("charts/test_std_detected_steps", test_std_detected_steps , i)


    text = f'''Final test after {i} episodes 
        Wins={wins}, 
        Detections={detected}, 
        winrate={test_win_rate:.3f}%, 
        detection_rate={test_detection_rate:.3f}%, 
        average_returns={test_average_returns:.3f} +- {test_std_returns:.3f}, 
        average_episode_steps={test_average_episode_steps:.3f} +- {test_std_episode_steps:.3f}, 
        average_win_steps={test_average_win_steps:.3f} +- {test_std_win_steps:.3f},
        average_detected_steps={test_average_detected_steps:.3f} +- {test_std_detected_steps:.3f}
        '''
    print(text)
    logger.info(text)
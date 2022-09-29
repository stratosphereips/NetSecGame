from cmath import inf
from game_components import *
import random

class BasicQLearningAgent:

    def __init__(self, env) -> None:
        self._q_values = {}
        self.env = env
    @property
    def q_values(self):
        return self._q_values

    def get_q_value(self, state:GameState, action:Action):
        if (state, action) not in self._q_values.keys():
                self._q_values[(state, action)] = 0
        return self._q_values[(state, action)]

    def set_q_value(self, state:GameState, action:Action, value:float):
        self._q_values[(state, action)] = value
    
    def select_action(self, state:GameState, actions:list, epsilon=1)->Action:
        if random.random() > epsilon: #random exploration
            return random.choice(actions)
        else:
            max_q = -inf
            selected_a = None
            for a in actions:
                if self.get_q_value(state,a) > max_q:
                    max_q = self.get_q_value(state,a)
                    selected_a = a
            return selected_a
    def get_max_q_for_state(self, state:GameState, actions:list)->float:
        max_q = -inf
        for a in actions:
            if self.get_q_value(state,a) > max_q:
                max_q = self._q_values[state,a]
        return max_q
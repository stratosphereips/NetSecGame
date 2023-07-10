# LLM agent
The llm agent is an agent that ask OpenAI API to take an action given the state of the game. 

1. There are given general instructions
2. Then there are given examples
3. Then there are given the current status of the game
4. Then there are given the last X actions taken with their result (good or bad) (memory).

## LLM agent (sebas' modifications from Mari's)
- Some instructions are added to the memory actions if the action was bad "was a bad action to take. Do not repeat it.".
- Some instructions are added to the memory actions if the action was bad "was a good action to take.".
- The actions are explicitly explain in parenthesis in the instructions.
- The format of the status of the state is very explicit.
- There are the rules of which action can be done under which conditions.

## LLM agent 2
- More concise instruction prompt. No description of what are the meaning of tasks.
- No more how the status of the state will look like.
- No more rules of the actions (when to use).
- Simplified feedback on memories.
#!/bin/bash

# run all unit tests, -n *5 means distribute tests on 5 different process
# -s to see print statements as they are executed

#python3  -m pytest tests/test_actions.py -p no:warnings -vvvv -s --full-trace
python3  -m pytest tests/test_components.py -p no:warnings -vvvv -s --full-trace
python3  -m pytest tests/test_game_coordinator.py -p no:warnings -vvvv -s --full-trace
python3  -m pytest tests/test_global_defender.py -p no:warnings -vvvv -s --full-trace
#python3  -m pytest tests/test_coordinator.py -p no:warnings -vvvv -s --full-trace

# run ruff check as well
echo "Running RUFF check: in ${PWD}"
ruff check --output-format=github --select=E9,F4,F6,F7,F8,N8 --ignore=F405 --target-version=py310 --line-length=120 .


#!/bin/bash

# run all unit tests, -n *5 means distribute tests on 5 different process
# -s to see print statements as they are executed

python  -m pytest tests/test_actions.py -p no:warnings -vvvv -s --full-trace
python  -m pytest tests/test_components.py -p no:warnings -vvvv -s --full-trace
python  -m pytest tests/test_coordinator.py -p no:warnings -vvvv -s --full-trace


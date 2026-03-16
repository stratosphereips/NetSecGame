from . import (
    scenario_configuration,
    smaller_scenario_configuration,
    tiny_scenario_configuration,
    one_net,
    three_net_scenario,
    two_nets,
)

# Static Registry
SCENARIO_REGISTRY = {
    "scenario1": scenario_configuration.configuration_objects,
    "scenario1_small": smaller_scenario_configuration.configuration_objects,
    "scenario1_tiny": tiny_scenario_configuration.configuration_objects,
    "one_network": one_net.configuration_objects,
    "three_net_scenario": three_net_scenario.configuration_objects,
    "two_networks": two_nets.configuration_objects,
}
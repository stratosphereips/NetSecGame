from . import (
    scenario_configuration,
    smaller_scenario_configuration,
    tiny_scenario_configuration,
    one_net,
    three_net_scenario,
    two_nets,
    two_nets_tiny,
    two_nets_small, 
)

# Static Registry
SCENARIO_REGISTRY = {
    "scenario1": scenario_configuration.configuration_objects,
    "scenario1_small": smaller_scenario_configuration.configuration_objects,
    "scenario1_tiny": tiny_scenario_configuration.configuration_objects,
    "one_network": one_net.configuration_objects,
    "three_net_scenario": three_net_scenario.configuration_objects,
    "two_networks": two_nets.configuration_objects,
    "two_networks_tiny": two_nets_tiny.configuration_objects,
    "two_networks_small": two_nets_small.configuration_objects,
}
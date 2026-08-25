from . import (
    scenario_configuration,
    scenario_configuration_new_IPs_1,
    scenario_configuration_new_IPs_2,
    scenario_configuration_new_IPs_3,
    scenario_configuration_new_IPs_4,
    scenario_configuration_new_IPs_5,
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
    "scenario1-1": scenario_configuration_new_IPs_1.configuration_objects,
    "scenario1-2": scenario_configuration_new_IPs_2configuration_objects,
    "scenario1-3": scenario_configuration_new_IPs_3.configuration_objects,
    "scenario1-4": scenario_configuration_new_IPs_4.configuration_objects,
    "scenario1-5": scenario_configuration_new_IPs_5.configuration_objects,
    "scenario1_small": smaller_scenario_configuration.configuration_objects,
    "scenario1_tiny": tiny_scenario_configuration.configuration_objects,
    "one_network": one_net.configuration_objects,
    "three_net_scenario": three_net_scenario.configuration_objects,
    "two_networks": two_nets.configuration_objects,
    "two_networks_tiny": two_nets_tiny.configuration_objects,
    "two_networks_small": two_nets_small.configuration_objects,
}

import sys
import logging
import json
from os import path
PATH = path.dirname( path.dirname( path.dirname( path.dirname( path.abspath(__file__) ) ) ))
sys.path.append(path.dirname( path.dirname( path.dirname( path.dirname( path.abspath(__file__) ) ) )))
from NetSecGameAgents.agents import base_agent
from netsecgame.game_components import Action, ActionType, IP, Network, Service, Data


if __name__ == "__main__":

    # !!! RUN THE COORDINATOR IN SEPARATE PROCESS AS FOLLOWS !!!
    # python3 coordinator.py  --task_config=./tests/manual/three_nets/three_net_testing_conf.yaml -l DEBUG
    NSE_config = "./three_net_testing_conf.yaml"
    coordinator_conf = "../../../coordinator.conf"
    log_filename = "three_net_test.log"

    # Convert the logging level in the args to the level to use
    logging.basicConfig(
        filename=log_filename,
        filemode="w",
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level="INFO",
    )

    # load config for coordinator
    with open(coordinator_conf, "r") as jfile:
        confjson = json.load(jfile)
    
    host = confjson.get("host", None)
    port = confjson.get("port", None)

    agent = base_agent.BaseAgent(host, port, role="Attacker")
    obs1 = agent.register()
    primary_host = sorted(list(obs1.state.known_hosts))[0] # get the host in the local net
    cc_host = sorted(list(obs1.state.known_hosts))[-1]
    print(f"Starting in {primary_host}")
    
    # unsuccessful network scan 192.168.3.0/24
    obs2 = agent.make_step(Action(
        ActionType.ScanNetwork,
        params={'source_host': primary_host, 'target_network': Network("192.168.3.0",24)}))
    assert obs1.state == obs2.state

    # successful scan network scan 192.168.1.0/24
    obs3 = agent.make_step(Action(
        ActionType.ScanNetwork,
        params={'source_host': primary_host, 'target_network': Network("192.168.1.0",24)}))
    assert obs3.state != obs2.state
    assert IP("192.168.1.2") in obs3.state.known_hosts

    # service scan in IP("192.168.1.2")
    obs4 = agent.make_step(Action(
        ActionType.FindServices,
        params={'source_host': primary_host, 'target_host': IP("192.168.1.2")}))
    assert obs3.state != obs4.state
    assert len(obs4.state.known_services[IP("192.168.1.2")]) == 2

    #exploit in IP("192.168.1.2")
    obs5 = agent.make_step(Action(
        ActionType.ExploitService,
        params={'source_host': primary_host, 'target_host': IP("192.168.1.2"), "target_service":Service(name='ms-wbt-server', type='passive', version='10.0.19041', is_local=False)}))
    assert obs5.state != obs4.state
    assert IP("192.168.1.2") in obs5.state.controlled_hosts

    # successful network scan 192.168.3.0/24 from IP("192.168.1.2")
    obs6 = agent.make_step(Action(
        ActionType.ScanNetwork,
        params={'source_host': IP("192.168.1.2"), 'target_network': Network("192.168.3.0",24)}))
    assert obs6.state != obs5.state
    assert IP("192.168.3.2") in obs6.state.known_hosts

    # service scan in IP("192.168.3.2")
    obs7 = agent.make_step(Action(
        ActionType.FindServices,
        params={'source_host': IP("192.168.1.2"), 'target_host': IP("192.168.3.2")}))
    assert obs7.state != obs6.state
    assert len(obs7.state.known_services[IP("192.168.3.2")]) != 0

    # Exploit in IP("192.168.3.2")
    obs8 = agent.make_step(Action(
        ActionType.ExploitService,
        params={'source_host': IP("192.168.1.2"), 'target_host': IP("192.168.3.2"), "target_service": Service(name='active-directory', type='passive', version='10.0.19041', is_local=False)})
    )
    assert obs8.state != obs7.state
    assert IP("192.168.3.2") in obs8.state.controlled_hosts
    # Search for data in IP("192.168.3.2")
    obs9 = agent.make_step(Action(
        ActionType.FindData,
        params={"source_host":IP("192.168.3.2"), "target_host":IP("192.168.3.2")}
    ))
    assert obs9.state != obs8.state
    assert len(obs9.state.known_data[IP("192.168.3.2")]) > 0
    # exfiltrate and win
    obs10 = agent.make_step(Action(
        ActionType.ExfiltrateData,
        params={
            "source_host":IP("192.168.3.2"),
            "target_host":cc_host,
            "data": Data(owner='admin', id='passwords', size=0, type='')
        }
    ))
    assert obs10.state != obs9.state
    assert len(obs10.state.known_data[cc_host]) > 0
    assert obs10.end
    assert obs10.reward == 99
    



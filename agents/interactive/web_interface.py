import logging
import gradio as gr
from intaractive_agent import *

actions = {"ScanNetwork": ActionType.ScanNetwork,
            "FindServices": ActionType.FindServices,
            "FindData": ActionType.FindData,
            "ExploitService":ActionType.ExploitService,
            "ExfiltrateData":ActionType.ExfiltrateData
            }
STATE = None

def state_to_html(state:GameState)->str:
    nets = "<td><strong>Networks</td>"
    for n in state.known_networks:
        nets += f"<td>{n}</td>"
    nets +="</td>"
    known_hosts = "<td><strong>Known hosts</td>"
    for h in state.known_hosts:
        known_hosts += f"<td>{h}</td>"
    controlled_hosts = "<td><strong>Controlled hosts</td>"
    for h in state.controlled_hosts:
        controlled_hosts += f"<td>{h}</td>"
    services = "<td><strong>Known services</td>"
    for h, s_list in state.known_services.items():
        services += f"<td>{h}:<ul>"
        for s in s_list:
            services += f"<li>{s}</li>"
        services += "</ul>"
    services += "</td>"
    data = "<td><strong>Known data</td>"
    for h, d_list in state.known_data.items():
        data += f"<td>{h}:<ul>"
        for d in d_list:
            data += f"<li>{s}</li>"
        data += "</ul>"
    data += "</td>"
    return f"<table><tr>{nets}</tr><tr>{known_hosts}</tr><tr>{controlled_hosts}</tr><tr>{services}</tr><tr>{data}</tr></table>"


def create_website(agent):
    with gr.Blocks(theme="freddyaboulton/dracula_revamped",title="NetworkSecurityGame") as demo:

        with gr.Column():

            gr.Markdown(
                """
                # Network Security Game
                This interface is intended for interactive manual play of the game.
                """)
            with gr.Row():
                with gr.Column():
                    gr.Markdown("### Current GameState:")
                    game_state_html = gr.HTML(state_to_html(agent.env.reset().state))
                with gr.Column():
                    act_type_input = gr.Dropdown(
                        choices=actions.keys(),
                        multiselect=False, label="ActionType",
                            info="Select action type to play")

                    trg_net = gr.Textbox(label="Target network", visible=False)
                    trg_host = gr.Textbox(label="Target host", visible=False)
                    src_host = gr.Dropdown(label="Source host", visible=False, multiselect=False)
                    trg_host_drop = gr.Dropdown(label="Target host", visible=False, multiselect=False)
                    trg_service = gr.Dropdown(label="Target service", visible=False, multiselect=False)
                    trg_data = gr.Dropdown(label="Data to move", visible=False, multiselect=False)

                    def parameters_selection(action_type_str:ActionType):
                        action_type = actions[action_type_str]
                        if action_type == ActionType.ScanNetwork:
                            return {trg_net: gr.update(placeholder="Enter network to scan", visible=True), trg_host:gr.update(visible=False)}
                        elif action_type == ActionType.FindServices:
                            return {trg_host: gr.update(placeholder="Enter host to search for services", visible=True), trg_net:gr.update(visible=False)}
                        elif action_type == ActionType.FindData:
                            return {trg_host: gr.update(placeholder="Enter host to search for data", visible=True), trg_net:gr.update(visible=False)}
                        elif action_type == ActionType.ExploitService:
                            return {trg_host: gr.update(placeholder="Enter host to exploit service in", visible=True), trg_net:gr.update(visible=False)}
                        elif action_type == ActionType.ExfiltrateData:
                            return {src_host: gr.update(placeholder="Enter host to exfiltrate data from", visible=True, choices=STATE.known_data.keys()), trg_net:gr.update(visible=False), trg_host:gr.update(visible=False)}
                        else:
                            return "UNKNOWN ACTION"
                    
                    def make_trg_host_drop_visible():
                        return {trg_host_drop: gr.update(choices=STATE.controlled_hosts, visible=True)}
                    
                    def make_trg_data_visible(src_host):
                        if IP(src_host) in STATE.known_data:
                            return {trg_data: gr.update(choices=STATE.data[IP(src_host)], visible=True)}
                    
                    def make_trg_service_visible(action_type_str, trg_host):
                        if actions[action_type_str] == ActionType.ExploitService:
                            print(trg_host,STATE.known_services, IP(trg_host) in STATE.known_services, STATE)
                            if IP(trg_host) in STATE.known_services:
                                print("HEEEEEEEEEEEEEEERE")
                                return {trg_service: gr.update(choices=STATE.known_services[IP(trg_host)], visible=True)}

                    def update(action_type_str, trg_net, trg_host, src_host, trg_service, trg_data,trg_host_drop):
                        action_type = actions[action_type_str]
                        if action_type == ActionType.ScanNetwork:
                            params = {"target_network":IP(trg_net)}
                        elif action_type == ActionType.FindServices:
                            params = {"target_host":IP(trg_host)}
                        elif action_type == ActionType.FindData:
                            params = {"target_host":IP(trg_host)}
                        elif action_type == ActionType.ExploitService:
                            params = {"target_host":IP(trg_host), "target_sevice":trg_service}
                        elif action_type == ActionType.ExfiltrateData:
                            params = {"target_host":IP(trg_host_drop), "source_host":IP(src_host), "data":trg_data}       
                        action = Action(action_type, params=params)
                        new_state_obs = agent.env.step(action)
                        STATE = new_state_obs.state
                        print("new state:", STATE)



                        return {game_state_html: gr.update(value=state_to_html(new_state_obs.state))}
                                # action_type:gr.update(value=""),
                                # trg_net:gr.update(visible=False, value=""),
                                # trg_host:gr.update(visible=False, value=""),
                                # src_host:gr.update(visible=False, value=""),
                                # trg_service:gr.update(visible=False, value=""),
                                # trg_data:gr.update(visible=False),
                                # trg_host_drop:gr.update(visible=False, value="")}
                    
                    #react to action type selection
                    act_type_input.change(parameters_selection, act_type_input, outputs=[trg_net, trg_host, src_host, trg_service, trg_data, trg_host_drop])
                    trg_host.change(make_trg_service_visible, inputs=[act_type_input, trg_host], outputs=[trg_service])
                    src_host.change(make_trg_host_drop_visible, src_host, outputs=[trg_host_drop])
                    trg_host_drop.change(make_trg_data_visible,trg_host_drop,trg_data)
                    
                    #react to Action submit
                    submit_button = gr.Button(value="Submit Action")
                    submit_button.click(update, inputs=[act_type_input, trg_net, trg_host, src_host, trg_service, trg_data, trg_host_drop], outputs=[game_state_html,act_type_input, trg_net, trg_host, src_host, trg_service, trg_data, trg_host_drop])
                    
            with gr.Accordion("About this game"):
                gr.Markdown("""Lorem ipsum dolor sit amet, consectetur adipiscing elit.
                Cras posuere eu nunc ut imperdiet. Phasellus accumsan faucibus lacus eget pretium.
                Sed massa neque, commodo vel magna non, tempor mollis mi. Proin placerat quam at vestibulum lacinia.
                Nunc commodo semper aliquam. Aenean convallis felis eget turpis varius efficitur.
                Sed consectetur lorem sapien, non pharetra elit blandit ac. Aenean commodo est nisi,
                ut laoreet augue pulvinar vitae. Phasellus lobortis velit in nibh cursus, vel pretium felis finibus.
                Nulla interdum urna id massa porttitor pulvinar. Maecenas elit enim,
                scelerisque eget diam id, malesuada molestie lectus. Cras lacinia ut neque id rhoncus.
                """)


    # Use share=True to make the model public
    # Add auth if shared in public
    demo.launch(server_name="0.0.0.0", server_port=12654, show_api=False, share=False)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--max_steps", help="Sets maximum steps before timeout", default=25, type=int)
    parser.add_argument("--defender", help="Is defender present", default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument("--scenario", help="Which scenario to run in", default="scenario1_tiny", type=str)
    parser.add_argument("--verbosity", help="Sets verbosity of the environment", default=0, type=int)
    parser.add_argument("--seed", help="Sets the random seed", type=int, default=42)
    parser.add_argument("--random_start", help="Sets if starting position and goal data is randomized", default=False, action=argparse.BooleanOptionalAction)
    args = parser.parse_args()

    logging.basicConfig(filename='interactive_agent.log', filemode='w', format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.CRITICAL)
    logger = logging.getLogger('Interactive-agent')
    random.seed(args.seed)

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
            "known_data":{"213.47.23.195":"random"}
        }
        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{"213.47.23.195"},
            "known_services":{},
            "known_data":{}
        }
    else:
        goal = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":set(),
            "known_services":{},
            "known_data":{IP("213.47.23.195"):{("User1", "DataFromServer1")}}
        }

        attacker_start = {
            "known_networks":set(),
            "known_hosts":set(),
            "controlled_hosts":{"213.47.23.195","192.168.2.2"},
            "known_services":{},
            "known_data":{}
        }
    

    # Create agent
    observation = env.initialize(win_conditons=goal, defender_positions=args.defender, attacker_start_position=attacker_start, max_steps=args.max_steps, cyst_config=cyst_config)
    STATE = observation.state
    logger.info(f'Creating the agent')
    agent = InteractiveAgent(env)
    create_website(agent)
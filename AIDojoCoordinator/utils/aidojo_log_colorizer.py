#!/usr/bin/env python3
"""
A simple log processor that colorizes log entries by agent and component,
interprets JSON payloads into readable summaries,
pretty-prints key fields, and highlights actions & agents.

Usage:
    python log_processor.py path/to/logfile.log
If no file is given, reads from stdin.
"""
import sys
import re
import json
from itertools import cycle
from rich import print
from rich.console import Console
from rich.text import Text

# Force ANSI colors even when output is piped
console = Console(force_terminal=True, color_system="truecolor")

# Cycle of colors to assign to different agents
COLOR_CYCLE = ["cyan", "magenta", "green", "yellow", "blue", "red"]
agent_colors = {}
agent_names = {}  # map ip:port -> agent name
color_picker = cycle(COLOR_CYCLE)

# Regex patterns
timestamp_re = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
line_re = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<source>\S+) (?P<level>\S+)\s+(?P<msg>.*)$"
)
agent_id_re = re.compile(r"\('(?P<ip>[\d\.]+)', (?P<port>\d+)\)")
agent_reg_re = re.compile(
    r"Agent (?P<name>\S+) \(\('(?P<ip>[\d\.]+)', (?P<port>\d+)\)\)"
)
action_re = re.compile(r"ActionType\.[A-Za-z]+")


def get_agent_color(agent_id: str) -> str:
    """Assign or retrieve a consistent color for an agent."""
    if agent_id not in agent_colors:
        agent_colors[agent_id] = next(color_picker)
    return agent_colors[agent_id]


def summarize_json(ts, source_styled, level_styled, prefix: str, parsed: dict):
    """Interpret and display key fields from a JSON payload."""
    console.print(f"[bold]{ts}[/bold] ", source_styled, level_styled, f"{prefix}:")
    indent = "    "
    # Status
    status = parsed.get('status')
    if status is not None:
        console.print(Text(f"{indent}Status: {status}", style="bold green"))

    # Info and End Reason: top-level or under observation
    info = parsed.get('info', {})
    obs = parsed.get('observation', {})
    obs_info = obs.get('info', {})
    end_reason = info.get('end_reason') or obs_info.get('end_reason')
    if end_reason:
        console.print(Text(f"{indent}End Reason: {end_reason}", style="bold yellow"))

    # To agent
    to_agent = parsed.get('to_agent')
    if to_agent:
        console.print(Text(f"{indent}To Agent: {to_agent[0]}:{to_agent[1]}", style="bold cyan"))

    # Message payload (optional)
    msg_block = parsed.get('message')
    if isinstance(msg_block, dict):
        text = msg_block.get('message')
        if text:
            console.print(Text(f"{indent}Message: {text}", style="bold"))
        max_steps = msg_block.get('max_steps')
        if max_steps is not None:
            console.print(f"{indent}Max Steps: {max_steps}")
        goal = msg_block.get('goal_description')
        if goal:
            console.print(f"{indent}Goal: {goal}")
        actions = msg_block.get('actions')
        if actions:
            console.print(f"{indent}Actions: {', '.join(actions)}")
        conf = msg_block.get('configuration_hash')
        if conf:
            console.print(f"{indent}Config Hash: {conf}")

    # Observation state: networks, hosts, services, data, blocks
    state = obs.get('state', {})
    if state:
        nets = state.get('known_networks', [])
        if nets:
            items = [f"{n['ip']}/{n['mask']}" for n in nets]
            console.print(f"{indent}Known Networks: {', '.join(items)}")
        hosts = state.get('known_hosts', [])
        if hosts:
            items = [h['ip'] for h in hosts]
            console.print(f"{indent}Known Hosts: {', '.join(items)}")
        ctrl = state.get('controlled_hosts', [])
        if ctrl:
            items = [h['ip'] for h in ctrl]
            console.print(f"{indent}Controlled Hosts: {', '.join(items)}")
        services = state.get('known_services', {})
        if services:
            for host, svcs in services.items():
                names = [s['name'] for s in svcs]
                console.print(f"{indent}Services on {host}: {', '.join(names)}")
        data = state.get('known_data', {})
        if data:
            for host, entries in data.items():
                ids = [e.get('id') for e in entries]
                console.print(f"{indent}Data on {host}: {', '.join(ids)}")
                # Known blocks
        blocks = state.get('known_blocks', {})
        # Always print blocks, even if empty
        if isinstance(blocks, dict):
            ips = list(blocks.keys())
        elif isinstance(blocks, list):
            ips = [b.get('ip') for b in blocks]
        else:
            ips = []
        if ips:
            console.print(f"{indent}Blocked Hosts: {', '.join(ips)}")
        else:
            console.print(f"{indent}Blocked Hosts: None")

    # Reward & End: top-level or under observation
    reward = parsed.get('reward', obs.get('reward'))
    if reward is not None:
        console.print(Text(f"{indent}Reward: {reward}", style="bold magenta"))
    end = parsed.get('end', obs.get('end'))
    if end is not None:
        console.print(Text(f"{indent}End: {end}", style="bold red"))


def process_line(line: str):
    raw = line.rstrip("\n")
    m = line_re.match(raw)
    if not m:
        print(raw)
        return

    ts = m.group('ts')
    source = m.group('source')
    level = m.group('level')
    msg = m.group('msg').strip()

    # Capture agent registration
    reg = agent_reg_re.search(msg)
    if reg:
        aid = f"{reg.group('ip')}:{reg.group('port')}"
        agent_names[aid] = reg.group('name')

    # Style source
    if 'GameCoordinator' in source:
        source_styled = Text(source, style='bold red')
    elif 'AgentServer' in source:
        source_styled = Text(source, style='bold blue')
    else:
        source_styled = Text(source, style='bold white')

    # Style level
    level_style = 'dim white' if level == 'INFO' else 'bold red'
    level_styled = Text(level, style=level_style)

    # Highlight actions
    msg = action_re.sub(lambda m: f"[bold magenta]{m.group(0)}[/bold magenta]", msg)

    # Annotate agents
    def repl_agent(m):
        aid = f"{m.group('ip')}:{m.group('port')}"
        col = get_agent_color(aid)
        name = agent_names.get(aid)
        label = f"{name} {aid}" if name else aid
        return f"[{col}]{label}[/{col}]"
    msg_markup = agent_id_re.sub(repl_agent, msg)

    # Detect JSON and interpret
    if '{' in msg and (msg.strip().startswith('{') or ': {' in msg):
        idx = msg.find('{')
        prefix = msg[:idx].rstrip(': ')
        json_part = msg[idx:]
        try:
            parsed = json.loads(json_part)
            summarize_json(ts, source_styled, level_styled, prefix, parsed)
            return
        except json.JSONDecodeError:
            pass

    # Default print
    console.print(Text(ts, style='bold'), source_styled, level_styled, Text.from_markup(msg_markup))


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            for line in f:
                process_line(line)
    else:
        for line in sys.stdin:
            process_line(line)


if __name__ == '__main__':
    main()


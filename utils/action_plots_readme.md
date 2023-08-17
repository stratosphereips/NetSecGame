# Action Plot

This script visualizes actions taken in episodes using `ggplot2` in R.

## Dependencies

- R >=4
- ggplot2
- optparse

## Description

The script reads an input CSV file containing information about actions taken
in different episodes. It then creates a plot visualizing the sequence of
actions taken, the type of action, and the target of the action. The produced
plot is saved as a PNG file.

You can use the `action_parser.py` for reading the logs
and generating a CSV file accordingly. 

## Usage

### Parameters:

- `-f` or `--file_name`: Path to the actions CSV file.
- `-e` or `--episode_num`: The episode number to visualize. Default is `1`.
- `-d` or `--scenario_desc`: A description of the scenario. Default is `"no_desc"`.
- `-a` or `--agent_desc`: A description of the agent. Default is `"no_desc"`.

### Example:

To visualize actions taken in episode 2 from the CSV file `actions.csv`:

```bash
Rscript your_script_name.R -f actions.csv -e 2
```

This would generate a PNG file named `no_desc_figure.png` if you do not provide
a scenario description.

## Output

The script saves the generated plot as a PNG file. The name of the file is
derived from the provided scenario description (default is `"no_desc_figure.png"`).

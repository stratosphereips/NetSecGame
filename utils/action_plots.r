library(ggplot2)
library(optparse)

create_action_plot<-function(df,ep = 1, scenario_desc ="no desc", agent_desc = "no_desc"){
  filtered_df <- df[df$episode == ep, ]
  ggplot( filtered_df ,aes(x = action_number, y = action_type, group = 1)) +  # Set group to a single value for all rows
    geom_line(colour = '#333333') +
    geom_point(aes( shape = action_type , color = target, fill = target ), size = 3) +
    scale_shape_manual(values = c(21, 22, 23, 24, 25)) +
    labs(fill = 'Action Type', shape = 'Action Type') +
    theme_bw()+
    theme(
      # Adjust the size as needed
      axis.title = element_text(size = rel(0.8)),  # Reduce axis title size
      axis.text = element_text(size = rel(0.8)),   # Reduce axis text size
      plot.title = element_text(size = rel(0.8)),  # Reduce plot title size
      legend.text = element_text(size = rel(0.8)), # Reduce legend text size
      legend.title = element_text(size = rel(0.8)), # Reduce legend title size
      axis.text.x = element_text(size = rel(0.8)),
      panel.grid.major.x = element_blank(),
      panel.grid.minor.x = element_blank(),
      strip.text.y = element_text(size = 20, angle = 0),
      legend.position = "bottom"
    )+
    #xlim(seq(100))+
    ylab("Action Type")+xlab("Action Number")+
    guides(fill="none", shape = "none", color = "none")+
    labs(subtitle=agent_desc, title = paste0("Episode ", ep,"\n",scenario_desc))
}

## Main
option_list = list(
  make_option(c("-f", "--file_name"), type="character", default=NULL,
              help="Path to the actions CSV file [default = %default]", metavar="character"),
  make_option(c("-e", "--episode_num"), type="integer", default=1,
              help="Episode number [default = %default]", metavar="integer"),
  make_option(c("-d", "--scenario_desc"), type="character", default="no_desc",
              help="Scenario description [default = %default]", metavar="character"),
  make_option(c("-a", "--agent_desc"), type="character", default="no_desc",
              help="Scenario description [default = %default]", metavar="character")
)
parser <- OptionParser(option_list=option_list)
args <- parse_args(parser)

if(is.null(args$file_name)) { 
  cat("required --file_name argument not found\n")
  print_help(parser)
  quit(status=1)
}

actions_df <- read.csv(args$file_name,header =T)
figure_name <- paste0(args$scenario_desc,"_figure.png")
## Remove action type
actions_df$action_type <- gsub("ActionType.", "", actions_df$action_type)
## Convert to factor 
actions_df$action_type<-as.factor(actions_df$action_type)
## Reorder factor levels
actions_df$action_type <- factor(actions_df$action_type, levels = c("ExfiltrateData",  "FindData", "ExploitService", "FindServices", "ScanNetwork"))

action_plot <- create_action_plot(actions_df,ep = args$episode_num, scenario_desc = args$scenario_desc, agent_desc =  args$agent_desc)
#print(paste(figure_name, "created."))
ggsave(filename = figure_name ,plot = action_plot, width = 15, height = 2.5, units = 'in')
print(paste(figure_name, "created."))

library(ggplot2)
library(optparse)

create_action_plot_by_network <- function(df, ep = 1, scenario_desc = "no desc", agent_desc = "no_desc", title = FALSE){
  df$network <- sapply(df$target, function(ip) paste0(head(unlist(strsplit(ip, split = '\\.')), 3), collapse = '.'))
  filtered_df <- df[df$episode == ep, ]
  # Extract unique networks
  unique_networks <- unique(filtered_df$network)
  network_colors <- colorRampPalette(c("darkblue", "darkred", "darkgreen"))(length(unique_networks))
  names(network_colors) <- unique_networks
  
  # Function to generate shades for a given color
  get_shades <- function(color, n) {
    colorRampPalette(c('white', color))(n+2)[1:n+2]
  }
  
  # For each IP, assign a color based on its network
  # Create an empty list to hold the colors for each IP
  ip_color_list <- vector("list", length = length(unique(filtered_df$target)))
  names(ip_color_list) <- unique(filtered_df$target)
  
  # Fill the list with colors for each IP based on its network
  for (net in unique_networks) {
    ips_in_net <- unique(filtered_df$target[filtered_df$network == net])
    colors_for_ips <- get_shades(network_colors[net], length(ips_in_net))
    ip_color_list[ips_in_net] <- colors_for_ips
  }
  
  # Convert the list to a named vector
  ip_colors <- unlist(ip_color_list, use.names = TRUE)
  
  action_plot <- ggplot(filtered_df, aes(x = action_number, y = action_type, group = 1)) +  
    geom_line(colour = '#333333') +
    #geom_point(aes(shape = action_type, fill = target), color= 'black', size = 3) +
    geom_point(aes(fill = target,shape = network),color='black', size = 4) +
    scale_color_manual(values = ip_colors) +
    scale_fill_manual(values = ip_colors) +
    scale_shape_manual(values = c(21,22,23,24,25)) +
    theme_bw()+
    theme(
      axis.title = element_text(size = rel(0.8)),
      axis.text = element_text(size = rel(0.8)),
      plot.title = element_text(size = rel(0.8)),
      legend.text = element_text(size = rel(0.8)),
      legend.title = element_text(size = rel(0.8)),
      axis.text.x = element_text(size = rel(0.8)),
      panel.grid.major.x = element_blank(),
      panel.grid.minor.x = element_blank(),
      strip.text.y = element_text(size = 20, angle = 0),
      legend.position = "bottom",
      axis.line = element_blank(),
      panel.border = element_blank()
    )+
    ylab("Action Type")+xlab("Steps")+
    guides(
      fill="none", 
      shape = "none", 
      color = 'none'
    )
    if (title == TRUE) { 
      action_plot <- action_Plot +  
      labs(subtitle=agent_desc, title = paste0("Episode ", ep,"\n",scenario_desc))
    }
    return (action_plot)
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
              help="Agent description [default = %default]", metavar="character"),
  make_option(c("-t", "--add_title"), action="store_true", default=FALSE,
              help="Add a title to the plot [default = %default]")
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

action_plot <- create_action_plot_by_network(actions_df,ep = args$episode_num, scenario_desc = args$scenario_desc, agent_desc =  args$agent_desc, title = args$add_title)
#print(paste(figure_name, "created."))
ggsave(filename = figure_name ,plot = action_plot, width = 15, height = 2.5, units = 'in')
print(paste(figure_name, "created."))

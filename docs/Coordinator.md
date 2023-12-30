# Coordinator

## The format of the messages to the agents is
    {
    "to_agent": address of client, 
    "status": {
        "#players": number of players,
        "running": true or false,
        "time": time in game,
        } ,
    "message": Generic text messages (optional),
    "state": (optional) {
        "observation": observation_object,
        "ended": if the game ended or not,
        "reason": reason for ending
    }
    }
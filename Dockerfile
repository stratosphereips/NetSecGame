# Use an official Python 3.12 runtime as a parent image
FROM python:3.12.12-slim-bookworm

# Set the working directory in the container
ENV DESTINATION_DIR=/netsecgame
WORKDIR ${DESTINATION_DIR}

# Copy the source code FIRST so pip has access to pyproject.toml
COPY . ${DESTINATION_DIR}/

# The "Single Layer" Trick: Install tools, build app, purge tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    pip install --no-cache-dir --upgrade pip && \
    if [ -f pyproject.toml ]; then pip install --no-cache-dir .[server] ; fi && \
    apt-get purge -y --auto-remove build-essential && \
    rm -rf /var/lib/apt/lists/*

ARG GAME_MODULE="netsecgame.game.worlds.NetSecGame"
# Pass the build argument to an environment variable so CMD can use it
ENV ENV_GAME_MODULE=$GAME_MODULE

# Expose the port the coordinator will run on
EXPOSE 9000 

# Run the Python script when the container launches
ENTRYPOINT ["sh", "-c", "exec python3 -m ${ENV_GAME_MODULE} --task_config=netsecenv_conf.yaml --game_port=9000 --game_host=0.0.0.0 \"$@\"", "--"]

# Default command arguments (can be overridden at runtime)
CMD ["--debug_level=INFO"]
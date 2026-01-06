# Use an official Python 3.12 runtime as a parent image
FROM python:3.12.10-slim

# Set the working directory in the container
ENV DESTINATION_DIR=/aidojo


# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --upgrade pip

COPY .  ${DESTINATION_DIR}/

# Set the working directory in the container
WORKDIR  ${DESTINATION_DIR}

# Install any necessary Python dependencies
# If a requirements.txt file is in the repository
RUN if [ -f pyproject.toml ]; then pip install . ; fi

# Expose the port the coordinator will run on
EXPOSE 9000 

# Run the Python script when the container launches (with default arguments --task_config=netsecenv_conf.yaml --game_port=9000 --game_host=0.0.0.0)
ENTRYPOINT ["python3", "-m", "AIDojoCoordinator.worlds.NSEGameCoordinator", "--task_config=netsecenv_conf.yaml", "--game_port=9000", "--game_host=0.0.0.0"]

# Default command arguments (can be overridden at runtime)
CMD ["--debug_level=INFO"]

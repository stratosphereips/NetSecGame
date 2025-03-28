# Use an official Python 3.12 runtime as a parent image
FROM python:3.12-slim

# Set the working directory in the container
ENV DESTINATION_DIR=/aidojo

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN pip install --upgrade pip

# Copy project files to container
COPY . ${DESTINATION_DIR}/

# Set the working directory in the container
WORKDIR ${DESTINATION_DIR}

# Install the current project as a package (instead of using requirements.txt)
RUN pip install .

# Clone the tmp-cyst-core repository
RUN git clone https://github.com/AI-Dojo-Public/cyst-core
# Install the cloned repo as a package
RUN pip install ./cyst-core/

# Run the Python script when the container launches
CMD ["python3", "-m", "AIDojoCoordinator.worlds.NSEGameCoordinator", "--game_host=0.0.0.0" , "--task_config=/aidojo/configuration.yaml"]
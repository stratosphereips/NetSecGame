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
RUN pip install -e .

# Clone the tmp-cyst-core repository
#RUN git clone https://github.com/stratosphereips/tmp-cyst-core
COPY tmp-cyst-core/ ${DESTINATION_DIR}/tmp-cyst-core/
# Install the cloned repo as a package
RUN pip install -e ./tmp-cyst-core/

# Install the correct version of netaddr
RUN pip install netaddr==1.3.0

# Run the Python script when the container launches
CMD ["python3", "-m", "AIDojoCoordinator.worlds.NSEGameCoordinator", "--game_host=0.0.0.0", "--task_config=./AIDojoCoordinator/netsecenv_conf.yaml" ]
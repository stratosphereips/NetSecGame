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
RUN pip install --upgrade pip

COPY .  ${DESTINATION_DIR}/

# Set the working directory in the container
WORKDIR  ${DESTINATION_DIR}

# Install any necessary Python dependencies
# If a requirements.txt file is in the repository
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi

# change the server ip to 0.0.0.0
RUN sed -i 's/"host": "127.0.0.1"/"host": "0.0.0.0"/' coordinator.conf

# Run the Python script when the container launches
CMD ["python3", "coordinator.py"]

import os
import json
import pandas as pd
import tarfile
import mlflow
import argparse
import shutil
from mlflow.tracking import MlflowClient
from botocore.exceptions import NoCredentialsError

def export_run(experiment_id, run_id, export_dir="mlflow_export", mlruns_dir=None):
    """
    Export an MLflow run to a directory.
    """
    if mlruns_dir:
        print(f"Setting MLflow tracking URI to local directory: {mlruns_dir}")
        mlflow.set_tracking_uri(f"{mlruns_dir}")
    
    client = MlflowClient()
    experiment = client.get_experiment(experiment_id)
    
    if experiment is None:
        raise ValueError(f"Experiment ID {experiment_id} does not exist.")
    print(f"Found experiment: {experiment.name}")

    run = client.get_run(run_id)
    if run is None:
        raise ValueError(f"Run ID {run_id} does not exist in Experiment ID {experiment_id}.")
    print(f"Found run: {run_id}")

    os.makedirs(export_dir, exist_ok=True)
    print(f"Created export directory: {export_dir}")
    
    # Save run metadata
    run_data = {
        "experiment_id": experiment_id,
        "experiment_name": experiment.name,
        "run_id": run_id,
        "params": run.data.params,
        "metrics": run.data.metrics,
        "tags": run.data.tags
    }
    with open(os.path.join(export_dir, "run.json"), "w") as f:
        json.dump(run_data, f, indent=4)
    print("Saved run metadata")

    # Save artifacts
    artifact_dir = os.path.join(export_dir, run_id)
    os.makedirs(artifact_dir, exist_ok=True)
    print(f"Created artifact directory: {artifact_dir}")
    
    # Download artifacts
    artifacts = client.list_artifacts(run_id, f"{mlruns_dir}")
    if artifacts:
        for artifact in artifacts:
            artifact_path = os.path.join(artifact_dir, artifact.path)
            if not os.path.exists(artifact_path):
                try:
                    os.system(f"mlflow artifacts download -r {run_id} -d {artifact_dir}")
                    print(f"Downloaded artifact: {artifact.path}")
                except FileNotFoundError:
                    print(f"Artifact {artifact.path} not found, skipping.")
    else:
        print("No artifacts to export.")

    # Compress exported data
    tar_path = f"{export_dir}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(export_dir, arcname=os.path.basename(export_dir))
    print(f"Compressed exported data to: {tar_path}")
    
    return tar_path

def import_run(tar_path, remote_url):
    """
    Import an MLflow run from a tar file into a remote MLflow server.
    """
    extract_dir = tar_path.replace(".tar.gz", "")
    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(extract_dir)
    print(f"Extracted tar file to: {extract_dir}")
    
    mlflow.set_tracking_uri(remote_url)
    print(f"Setting MLflow tracking URI to remote URL: {remote_url}")
    client = MlflowClient()
    
    # Read run metadata
    with open(os.path.join(extract_dir, "run.json"), "r") as f:
        run_data = json.load(f)
    print("Read run metadata")

    experiment_name = run_data['experiment_name']
    try:
        experiment_id = client.create_experiment(experiment_name)
        print(f"Created new experiment: {experiment_name} with ID: {experiment_id}")
    except mlflow.exceptions.MlflowException:
        experiment = client.get_experiment_by_name(experiment_name)
        experiment_id = experiment.experiment_id
        print(f"Experiment {experiment_name} already exists with ID: {experiment_id}")

    # Check if the run ID already exists in the remote
    remote_runs = client.search_runs(experiment_ids=[experiment_id])
    if any(run.info.run_id == run_data['run_id'] for run in remote_runs):
        print(f"Run ID {run_data['run_id']} already exists in the remote. Skipping import.")
        return
    
    # Recreate run
    with mlflow.start_run(experiment_id=experiment_id, run_name=run_data['run_id']):
        for param, value in run_data['params'].items():
            mlflow.log_param(param, value)
        for metric, value in run_data['metrics'].items():
            mlflow.log_metric(metric, value)
        for tag, value in run_data['tags'].items():
            mlflow.set_tag(tag, value)
        print("Logged run parameters, metrics, and tags")
        
        # Upload artifacts
        artifact_path = os.path.join(extract_dir, run_data['run_id'])
        if os.path.exists(artifact_path) and os.listdir(artifact_path):
            try:
                mlflow.log_artifacts(artifact_path)
                print(f"Uploaded artifacts from: {artifact_path}")
            except NoCredentialsError:
                print("No AWS credentials found. Skipping artifact upload.")
        else:
            print("No artifacts to upload.")
    
    print(f"Run successfully imported to {remote_url} with Experiment ID {experiment_id}")

    # Delete the local export directory
    shutil.rmtree(extract_dir)
    print(f"Deleted local export directory: {extract_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export and import an MLflow run.")
    parser.add_argument("--experiment_id", type=str, required=True, help="MLflow experiment ID.")
    parser.add_argument("--run_id", type=str, required=True, help="MLflow run ID.")
    parser.add_argument("--remote_mlflow_url", type=str, required=True, help="Remote MLflow tracking server URL.")
    parser.add_argument("--mlruns_dir", type=str, required=True, help="Directory of the local mlruns.")
    args = parser.parse_args()

    print('Warning. There is no way to check if this RUN id was already uploaded. So please check by hand if you did it already.')
    tar_file = export_run(args.experiment_id, args.run_id, mlruns_dir=args.mlruns_dir)
    import_run(tar_file, args.remote_mlflow_url)
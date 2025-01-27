from setuptools import setup, find_packages

# Read the contents of your README file for the long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="AIDojoGameCoordinator",  
    version="0.1.0",  
    author="Ondrej Lukas", 
    author_email="ondrej.lukas@aic.fel.cvut.cz",  
    description="A package for coordinating AI-driven network simulation games for network security.",  
    long_description=long_description,  # Use README.md for a long description
    long_description_content_type="text/markdown",  # Content type of the long description
    url="https://github.com/your-username/AIDojoGameCoordinator",  
    packages=find_packages(),  # Automatically find all packages in your project
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.12",  # Minimum Python version
    install_requires=[
    ],
    extras_require={
        "dev": [
            "pytest",  # Add testing and development dependencies
            "flake8",
            "black",
        ]
    },
    include_package_data=True,  # Include files from MANIFEST.in
)
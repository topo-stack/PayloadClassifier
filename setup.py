from setuptools import setup, find_packages

setup(
    name="payload-classifier",
    version="2.0.0",
    author="Cybersecurity Student",
    description="Production-Ready Pure Python ML Malware Classifier Engine",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    py_modules=["bat"],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "payload-classifier=bat:cli.run",
            "bat-scan=bat:cli.run",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
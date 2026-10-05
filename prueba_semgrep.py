import subprocess

host = input("Host: ")
subprocess.call("ping " + host, shell=True)
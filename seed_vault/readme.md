

### This update is for MX Linux OS

````
sudo apt update
sudo apt install python3-full -y
sudo apt install python3 python3-pip -y
python3 --version
pip3 --version
sudo apt install -y build-essential libssl-dev zlib1g-dev libsqlite3-dev libffi-dev libbz2-dev libreadline-gplv2-dev libncursesw5-dev tk-dev -y
````
#### Best Practice: Use Virtual Environments

#### Regardless of the installation method, it is a best practice to use a virtual environment for your Python projects. This prevents conflicts between project dependencies.

#### You can create one with the venv module:
````
python3 -m venv my_project_env
source my_project_env/bin/activate
pip install cryptography
````


# USAGE commands:

````
# Encrypt (guides you end-to-end)
python seed_vault.py encrypt

# List entries
python seed_vault_v1.3.py list --vault my_vault.json

# Decrypt a specific word by index
python seed_vault_v1.3.py decrypt --vault my_vault.json --index 7

# Show all words (view-tier auto-decrypt; secured optional)
python seed_vault_v1.3.py show --vault my_vault.json
````

## Test Direct command

````
irm "https://raw.githubusercontent.com/ulyweb/python/refs/heads/main/seed_vault/v1.1_seed_vault_gui.py" | iex
````



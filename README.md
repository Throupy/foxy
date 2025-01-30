# Foxy
Foxy is a python class which will extract and decrypt firefox passwords from a firefox profile directory artefact. 

## Usage
Usage is very simple, and I might add argument parsing at some point

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

```python
foxy = Foxy("<PROFILE_DIRECTORY>")
decrypted_passwords = foxy.retrieve_passwords()
for hostname, username, password in decrypted_passwords:
    print(f"[+] {hostname} | {username} | {password}")
```

There is a profile directory called `8k3bf3zp.charles` included in the repository for your usage.

## Example output

```python
foxy = Foxy("8k3bf3zp.charles")
decrypted_passwords = foxy.retrieve_passwords()
for hostname, username, password in decrypted_passwords:
    print(f"[+] {hostname} | {username} | {password}")
```

```
[+] https://www.buckinghampalace.com | Charles | thekingofengland
```

# Tools to Manage Users

We have tools.

##### list_users.sh
```bash
./list_users.sh
```
Lists all users on the system.
*RED and GREEN users are human users. except nobody*
RED = inactive user
GREEN = active user
WHITE = system user

##### purge_user.sh
```bash
./purge_user.sh <UID> <lock password or delete user [L/D]>
```

##### manage_users.py
```bash
python3 manage_users.py
```
Currently incomplete. 
• Runs list_users.sh and extracts it as a list of tuples where a tuple is (UID, username, status=INACTIVE,ACTIVE,SYSTEM)
• Prints it out (currently)
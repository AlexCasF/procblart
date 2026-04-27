# SSH Agent Setup

Proc Blart can collect remote Windows process data over SSH:

```powershell
procblart run --remote-ssh <USER>@<TARGET_IP>
```

Password login works, but the live monitor reconnects regularly, so password prompts become noisy. SSH key auth with `ssh-agent` lets the normal Windows SSH client authenticate without Proc Blart storing or handling your password.

## Host Machine

Run these on the machine where Proc Blart runs:

```powershell
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\procblart_ed25519
Start-Service ssh-agent
Set-Service ssh-agent -StartupType Automatic
ssh-add $env:USERPROFILE\.ssh\procblart_ed25519
Get-Content $env:USERPROFILE\.ssh\procblart_ed25519.pub
```

Copy the public key line printed by the last command.

## Target Windows Machine

Log in as the remote user, for example `<USER>`, then run:

```powershell
mkdir $env:USERPROFILE\.ssh -Force
notepad $env:USERPROFILE\.ssh\authorized_keys
```

Paste the public key line into `authorized_keys`, save, and close Notepad.

## Test

From the host machine:

```powershell
ssh -i $env:USERPROFILE\.ssh\procblart_ed25519 <USER>@<TARGET_IP>
```

If SSH opens a remote shell without asking for the Windows account password, Proc Blart can use the same path:

```powershell
procblart run --remote-ssh <USER>@<TARGET_IP>
```

## Optional SSH Alias

On the host, add this to:

```text
C:\Users\<LOCAL_USER>\.ssh\config
```

Example:

```sshconfig
Host procblart-vm
    HostName <TARGET_IP>
    User <USER>
    IdentityFile ~/.ssh/procblart_ed25519
```

Then run:

```powershell
procblart run --remote-ssh procblart-vm
```


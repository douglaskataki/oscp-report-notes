# Enumeration

## Some tips:
In order to execute some powershell scripts:
```
powershell -ep bypass
```

About users (script for getting users)


## Manual
Enumerate Local Accounts on the machine:
```
net user /domain
```

Checking admin account:
```
net user admin /domain
```

Enumerate roups:
```
net group /domain
```

Get information about Sales Department
```
net group "Sales Department" /domain
```

### Operating System

### Permissions and Logged on Users

### Enumeration Through Service Principal Names

### Enumerating Object Permissions

### Enumerating Domain Shares

## Automatic

### BloodHound

#### Analyzing Data

#### Raw Queries

# Attacking

## Password Attacks

## AS-REP Roasting

## Kerberoasting

## Silver Tickets

## Domain Controller Synchronization

# Lateral Movement

## Wmic and WinRM

## PsExec

## Pass the Hash

## Overpass the Hash

## Pass the Ticket

## DCOM

# Persistance

## Golden Ticket

## Shadow Ticket

# PAM_student_card
Using RC-S380 to pass PAM authentication with student ID card.

The tool is intended to be run with pam_exec.so.
I understand that pam_exec.so executes the specified file and processes it as authentication success if the return value is 0, otherwise as authentication failure. Sorry if I'm wrong.

## Requirement
We are using nfcpy, which officially supports the device for use with the RC-S380.
The following tools must be installed so that they can be called from root.
- nfcpy >= 1.8.0

## Usage
You must create a list of permissions.
Create a file named `/etc/security/PAM_student_card.csv` and create a permission list in the following format `hash,student_number,user,salt`.
Salt and hash values can be created by running `get_salt_and_hash.py`.

Here is an example of a permission list.
```
59aecf9ed93a9c6c9b2433fff04a0e146339ff5406df2d4335c18e026df46e56,AAA123BBB,sampleuser,bf0b3aa252b347615193dae6cef197d60559bb9964c09c10b17cac6342fdd5da
```

## Example
If `/etc/pam.d/sshd` is configured as follows, it can authenticate with NFC tags and perform password authentication, etc. in case of failure.
```
#%PAM-1.0

auth      sufficient pam_exec.so quiet stdout /home/user/work/nfcc/read_nfc.py
auth      include   system-remote-login
account   include   system-remote-login
password  include   system-remote-login
session   include   system-remote-login
```

## Verification
There are three values to be verified.
We look at the card's idm (SHA256 with salt), StudentNumber, and PAM_USER, which is set as an environment variable when pam_exec.so is run.
If all values in each line of `/etc/security/PAM_student_number.csv` all match, the verification is considered successful.

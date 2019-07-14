# jLoot - JIRA Secure Attachment Looter #

jLoot is a tool that can be used to enumerate attachments to JIRA tickets.

When files are attached to issues in JIRA, they are given a sequential number and stored.
While there are access controls on most installations, if a JIRA was meant to be public,
or if it was misconfigured by the organization, the files are easily iterable.

jLoot simplifies the iteration process by checking if a file exists at a given ID number,
and downloading it.

jLoot comes with a basic set of yara rules to check incoming files for sensitive words.
If a rule matches, it will appear highlighted in red next to the file name. You can use
the `-y` flag to specify your own yara rules, or edit jLoot.yar

If a file matches a yara rule, it has the word "CHECK_" appended to the beginning of the
filename for easy recall of sensitive files.

## Command Line Options ##

The following command line options are supported:

```
 -u baseURL     The base url of the JIRA instance
 -s start_id    The starting attachment ID (attachments start at 10000)
 -l limit       The limit for file downloads
 -o out_dir     The output directory (default is loot/)
 -y yara_rules  Specify custom yara rules
```

## Setup ##

If you don't have yara installed, you can use [this guide](https://yara.readthedocs.io/en/v3.10.0/gettingstarted.html) to install it. Install yara
for python using `python3 -m pip install yara-python`

If you get an error about yara not being able to find libyara, run these commands:
```
sudo sh -c 'echo "/usr/local/lib" >> /etc/ld.so.conf'
sudo ldconfig
```

## Shouts ##

Big shoutout to hermit for finding the initial dorks that led to this tool. Shoutout to 
ThugCrowd and all the Safari Zone Game Wardens.

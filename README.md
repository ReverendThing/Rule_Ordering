# Rule_Ordering
Attempt to create a super efficient and effective Hashcat Rule
By Rev_Thing

Basics: This script takes a list of usernames and ntlm password hashes (in the format USER:HASH) and a dictionary and runs Hashcat using all.rule - a rule file that basically contains all of the standard Hashcat rules, as well as d3adhob0.rule and NSAv1.rule and NSAv2.rule - sorted and filtered to remove duplicates.

It runs Hashcat with the --keep-guessing option, which means that one password hash may be recovered using multiple combinations of word+rule
For example Password1 could be recovered by adding the number 1 to the end of the word Password, or by capitalising the first letter of password1.

Combined with the --debug-mode=4 this means that we are given an output that contains exactly how many times each individual rule would be useful if it was the only rule running across a password dump with a given dictionary.

We use "keep guessing" because the rule that happens to crack a password first may not actually be the rule that would perform best if each rule got a fresh crack at the password dump.

The aim of this script is to create a .rule that contains every useful individual rule from a .rule file in order based on performance. By giving each individual line of a .rule file a fresh crack at a password dump, it is possible to count rules that fire in the debug output and pick out the top individual line.

Taking this a step further this script then removes the top line from all.rule and places it at the top of a new .rule file. It runs this new .rule file with the dictionary over the password dump and this time removes passwords cracked using the top rule and the given dictionary.

It then starts the process again, minus the top rule and its cracked passwords.

By repeating this process we end up with a .rule file that contains each individual line of .rule that fires - in order - based on performance - and each line is the best line after every line that has gone before it.

The process takes quite a while for the first run (depending on the size of the dictionary and hash dump) but speeds up each time it repeats as far less rules will be involved in the second run, and so on as we have weeded out only ones that actually fire.

Additionally, using this method we do get rid of rules that would have been useful, but not after the rules that have gone before - for this particular combination - and this may be removing rules that would be useful given other combinations, but we have to start somewhere!

Next Aims:
It would be great to be able to combine the outputs across multiple hash dumps/dictionaries, however, there are some problems, such as if a new dictionary contains a word we have already quantified, it may now get skewed, over-representation as it is appearing more times, but actually, has already been counted.

Additionally, a rule that would work best on one domain's password complexity, may not be the best for a different domain's password complexity rules.

The goal is that over time, this process of continual improvement should still lead to a decent .rule that should be efficient with high-performance, and some of the issues inherent in this method should be overcome by numerous runs sifting out anomalies.

I need to add command line options so it does not all have to be hardcoded into the script

I would like to port it to c#

My variable names are terrible


Dependencies:
Pandas, Numpy

Folder Structure and additional info:
It is currently hardcoded to run hashcat64.exe and creates a RuleOrdering folder to store files as it works on them
It is currently hardcoded to run on a file called hashes in a Hashes folder within the Hashcat folder
It is currently hardcoded to use a dictionary called words.txt in a Dictionaries folder within the hashcat folder
It is currently hardcoded to use all.rule (provided here) that should be in the rules folder

It also outputs a few additional files, such as a finished dictionary of all words used with the rule - this could be developed to help also produce an efficient dictionary.

Rev_Thing.log contains a run down of the individual rule lines as well as the count of how many times each rule hit after the one before it

At the moment it cuts out when it gets to a load of rules that only fire once at most - these are output to a separate .rule file, so you can still include these if you wish.

*It may take overnight or longer to do your first run if it is a big dictionary/hashdump*

*You can interact with Hashcat as it runs/pause it by hitting space in the command prompt as this script runs*

*This is a pretty dirty script that may not use the most efficient ways of chopping up outputs and parsing them*

*At the moment it uses the --username option of hashcat as it is expecting the hash dump you use to have usernames and passwords - remove this option from every hashcat command if you just want to give it loads of hashes*

*There is some problem with the final run as it doesn't seem able to safely stop - but you will have a rule file and dic file etc by that point - may just have lost the final single line*

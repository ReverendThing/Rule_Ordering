#Rule orderer
#V0.9
#Rev_Thing

#yhddhso++++++/++++++++/:::--:-:://+/+/:///////+++o
#syhdhyso+++////////////:::-----:://::::-:////:::/+
#hhhdyysoo+////////////:::::-------::::::/+//::-:/+
#hhhhsoooo+/////////+osss+oyh/:::-..--:/++++++///++
#hyyysooo+////+++++yhmmmNNNmmNmdo:--:::::/++++++oos
#ysssyssoo+///+++ohNNNMMMMmdmNmmmy/:::----:/+++osss
#hyyyyyso++//+oosshmNMMMMMNNNNNNddo:-::---:::/+oosy
#mddysoo++++oo+oshmmNhhmMMMNdshNNdo-------.--:++oyh
#mdhyso+//++oooosdNNNosdmdmmo/:NNd+----:----:/++sdd
#mddyso+//////++ohmmmshhdhmmh/:dhds:--:::///++osyhh
#mdyoosoo++//:///odddsyddyshh+-smm+-:-:/++ooosssyys
#mdyosyyyso+/////+sNMysdhs+dh/oMdo----:/+osoossoooo
#dhysysysso++//+osymNdydhysys+hNdyo/:--://+os++++//
#yysysosooosyhdmddmmmmyhyhh+++mmdmNNddhyo/-::///:::
#yyyssoohdmmNmmmdmNNNNNmdmmydNNNNdNMNdNNmdhs::::///
#ssso++ommNNmNNNmNMMNMMNm/+NNmmNNNNNMNdMNmmd////+os
#so+///dNNNNmMNmMNMNMMMNNmmNNNNmNNMNNNdMNmmmh//+oyd
#o+/+/omNNNNmMNMMMNNMMmhhssymNMMNNNNNNmNNNNNms++oss
#o+++odmNNMMmNNMMMMNMms+/ss/omMNNMNMMNmNMNNmmh+/+oo
#+++smmhmNNNNNMMMMMMNyss+sso+odNMMNMMNNMMNNNhNs/++o
#++omddmNNMMNNMNMMMmyhdhyhs++:`:smMMMNMMMMMNddmy++o
#++hddmmNMMMMNNmddhhhddmmhhso+:-.-/yNmMMMMNmmmdms+o
#sddhddmmmdmNNNmdddmNNNNMMNNNNmmhs/:ydmmNNNmmmmdhoo
#hmdhmdNmmNmNNmMNmNMMMNNMMMMNMMMMmdsdMNdhhmmNdhdmds
#mNmmNNNNNNNdmmNNMMMMMMmMMMMmNNMMMNmNMMMmmmmmhmdmmh
#dmNmMMNMMNNNNNNNMMMMMMNMMMMmdMMMNmmNmNNNNNmMhdNmmy
#smNMMNMMMNmMMMMMMMMMMMNMMMMNMNNMNNNNNNNMMMMNNdNmho
#+odNdyyso++mMMNMMMMMMMNMMMMNNNNMNNNmNMdmMNMMMNNmy+
#///////////sMMNMMNMMMNNMMMMNNdNMNNmdmm+/oydmmmmso+
#o++++//////omNNMNNMMNmNMMMMNmNNNNNmmNd/:::/+ooosss
#ssooo+/////+mNNNmNNNNmMMMNNNdNNNNNdmNy/---/+ossyhh
#ysssoo+++///ymNNmNNNmmNmdmmmddmmNmdmNo///+osyyyddh
#ssssoo+++//+omNmdmmddmmhoosyhhddmmddd++++osyyshddh
#ssosoo++++//+ddddddhhdsssssysyyyhdhhy/+oosyssyhdhy
#sooo+++++++//yhhhhyhhhso+ooosyyyyyhs+/++osyyyhyyos


#This script is currently hard-coded to run all.rule across words.txt for "hashes" hashdump and then process from there.

#Outputs to RuleOrdering/Rev_Thing.log giving each rule and its frequency when added - so freq after everything above it has run.

#It also currently appends to RuleOrdering/all_rules_all_jobs.rule - this is done on the first run and so shows frequency each rule would have got on its own
#Allowing at least some sort of frequency to be deduced across multiple jobs.

#Possibly haven't nailed down error of it stopping :s if rules crack nothing after previous top rule is run
#Also, seems to only add to rules_ordered.rule after new top rule has been found? Should maybe just be added as soon as top_rule has been run.
#Might mean the final rule is lost?

#Also, it deletes certain files at certain points - could probably do with checking it wouldn't mess everything up if I start it on a new job rather than appending!
#Also, could maybe even add possibility to pause / resume as it will save in state?
#Also - weirdly top rule in pandas said something like 112 occurences - then when ran on its own it gave 356 passwords?! - maybe cos first rule also removes none rule cracked hashes

#Also - could probably just add --recovery-file or whatever it is option to hashcat command so that can recover itself if messed up? Though might need separate script that starts
#from a recovery file and continues.

#It does seem to allow for interaction with running hashcat if you just hit space in command prompt as it is running! So can pause that way - though doesn't always survive
#hibernating machine.


import subprocess, sys, os, csv
import pandas as pd
import numpy as np
import collections

#Global Variables
cwd=os.path.dirname(os.path.abspath(__file__))
path=cwd+'\\RuleOrdering\\'
rules_processing_still_has_lines = int(1)

def replace_last(s, old, new, occurence):
	li = s.rsplit(old, occurence)
	return new.join(li)

#Functions
def firstRun():
	#Run my desired hashcat command
	#MUST USE --KEEP-GUESSING
	process=subprocess.Popen('hashcat64.exe -a 0 -m 1000 --username --force --keep-guessing -w 4 Hashes/hashes Dictionaries/words.txt -r rules/all.rule --potfile-path RuleOrdering/hashcat_run1.potfile --debug-mode=4 --debug-file=RuleOrdering/hashcat_run1.log', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

	#display the standard output from the hashcat command in the command prompt
	while True:
		nextline = process.stdout.readline()
		if nextline == b'' and process.poll() is not None:
			break
		sys.stdout.write(nextline.decode(sys.stdout.encoding))
		sys.stdout.flush()
	
	
	#Strip passwords cracked without using any rule from the log.
	remove_lines = [':::', ':::']
	with open(path+'hashcat_run1.log') as infile, open(path+'hashcat_run1-processing.log', 'w') as newfile:
		for line in infile:
			if not any (remove in line for remove in remove_lines):
				newfile.write(line)
	infile.close()
	newfile.close()
	
	
	#Write back over the original log
	with open(path+'hashcat_run1-processing.log') as f, open(path+'hashcat_run1.log', 'w') as f1:
		for linesss in f:
			f1.write(linesss)
	
	f.close()
	f1.close()

		
	#Change first and last ':' for '£' as some rules contain :
	file_replacing=open(path+"file_replacing.rule", 'a')
	with open("RuleOrdering\hashcat_run1.log", "r") as myfile:
		for line in myfile:
			d = collections.defaultdict(int)
			for c in line:
				d[c] += 1
			if d[':'] > 2:
				line=replace_last(line, ':', '£', 1)
				line=line.replace(':', '£', 1)
				file_replacing.writelines(line)
			else:
				line=line.replace(':', '£')
				file_replacing.writelines(line)
	
	file_replacing.close()
	myfile.close()
	

	
	
	#Write back over the original log
	with open(path+'file_replacing.rule') as f_replacing, open(path+'hashcat_run1.log', 'w') as fi_replacing:
		for liness in f_replacing:
			fi_replacing.writelines(liness)
	
	f_replacing.close()
	fi_replacing.close()
	
	
	#Read the log file into panda using £ as a delimeter - have to use QUOTE_NONE otherwise will read any " in file as code.
	rules = pd.read_csv(path+'hashcat_run1.log', sep='£', engine='python', quoting=csv.QUOTE_NONE, names=['baseword', 'rule', 'cracked_password'])
	
	
	#Add count to the rule column
	rules['count'] = rules.groupby('rule')['rule'].transform(pd.Series.value_counts)

	#Save all rules to an all_rules file - this contains every rule that hit, with the complete hash dump, from all the rules, and does not remove duplicate appearances.
	#This file can then be added to by all subsequent jobs allowing you to sort by frequency across jobs.
	#You could also separately compare positions in different job's rules_processed.rule file - ie this rule is often in the top 5 etc - by looking at the rule_ordered.rule at the end.
	rules['rule'].to_csv(path+'all_rules_all_jobs_processing.rule', index=False, sep='£')
	#Write it to an all_rules_all_jobs.rule file so that these can later be taken from multiple jobs and merged and sorted by frequency.
	#If I made it append, could be rudimentary beginning of running on multiple hash dumps in one script and collating 
	with open(path+'all_rules_all_jobs_processing.rule') as f_all_rules, open(path+'all_rules_all_jobs.rule', 'w') as fi_all_rules:
		for linessss in f_all_rules:
			fi_all_rules.writelines(linessss)
	
	f_all_rules.close()
	fi_all_rules.close()
	
			
	

	#Sort rules by count in descending order and drop duplicates based on the word in the rule column
	rules = (rules.sort_values('count', ascending=False))
	rules = rules.drop_duplicates(subset='rule')

	#At this point we have the rules arranged in descending order from most frequently occuring in the output.

	#Save the results to an output file, without including the row numbering
	#This is now all the rules that fired - in order according to frequency
	rules['rule'].to_csv(path+'rules_in_order_processing.rule', index=False, sep='£')
	
	#Also write out the rules in descending order with their counts so we can log the top one
	header = ["rule", "count"]
	rules.to_csv(path+'rules_in_order_to_log.rule', columns = header, header = False, index=False)
		
	#Now I want to just run the top rule - removing hashes as they are cracked (happnes in the top_rule function)
	#So take the top line and write it to top_rule.rule:
	with open(path+'rules_in_order_processing.rule', 'r') as topfile:
		first_line = topfile.readline()
		#Save the top rule to its own rule file
		top_rule = open(path+'top_rule.rule', 'w')
		top_rule.write(first_line)
		top_rule.close()
	
	topfile.close()
	
	rules = None
	
	
	#I want to also output only the basewords that fire each time so that the dictionary will continually also shrink - this dictionary does not need to contain duplicates, so for ease, I will
	#read it into a separate database.
	#Read in the log
	basewords_processing = pd.read_csv(path+'hashcat_run1.log', sep='£', engine='python', quoting=csv.QUOTE_NONE, names=['baseword', 'rule', 'cracked_password'])
	
	#Add count and remove duplicates
	basewords_processing['count'] = basewords_processing.groupby('baseword')['baseword'].transform(pd.Series.value_counts)
	basewords_processing = (basewords_processing.sort_values('count', ascending=False))
	basewords_processing = basewords_processing.drop_duplicates(subset='baseword')
	
	#Read this list out to a basewords_processing.dic file
	basewords_processing['baseword'].to_csv(path+'allbasewords_processing.dic', index=False)
	
	#And as this is the first run, create the rules_processing.rule containing all except the top rule
	with open(path+'rules_in_order_processing.rule', 'r') as all_rules_file:
		data = all_rules_file.read().splitlines(True)
	with open(path+'rules_processing.rule', 'w') as all_rules_out:
		all_rules_out.writelines(data[1:])
	
	all_rules_file.close()
	all_rules_out.close()
	data = None
		
	#Now log the top rule and its count to Rev_Thing.log	
	#Read out the top rule and its count to first_line2 for the log:
	with open(path+'rules_in_order_to_log.rule', 'r') as topfile2:
		first_line2 = topfile2.readline()
	#Save the top rule and it's count to an evergrowing logfile
	with open(path+'Rev_Thing.log', 'a') as fi_log:
		fi_log.writelines(first_line2)
		
		topfile2.close()
		fi_log.close()
	
	#Remove processing files
	os.remove(path+'hashcat_run1-processing.log')
	os.remove(path+'all_rules_all_jobs_processing.rule')
	os.remove(path+'rules_in_order_processing.rule')
	os.remove(path+'rules_in_order_to_log.rule')
	return;

def check_rules_processing():
	#I think this may not work on 0 - so may not do exactly what I need it to do
	rules_processing_still_has_lines = 0
	with open(path+'rules_processing.rule') as check_file:
		for i, l in enumerate(check_file):
			pass
	rules_processing_still_has_lines = i+1
	
	check_file.close()
	return;


def topRuleRun():
	#Blast potfile and debug file from first run, we don't need anything else from it, and on subsequent runs, this function will have extracted what we need by now.
	os.remove(path+'hashcat_run1.log')
	

	#Run top rule using remove so we can then see what is genuinely the second best rule to run
	#WE DO NOT USE --KEEP-GUESSING (though I am keeping the log names the same for ease/it doesn't matter what they're called
	process2=subprocess.Popen('hashcat64.exe -a 0 -m 1000 --username --force -w 4 Hashes/hashes RuleOrdering/allbasewords_processing.dic -r RuleOrdering/top_rule.rule --potfile-path RuleOrdering/hashcat_run1_toprule_run.potfile --debug-mode=4 --debug-file=RuleOrdering/hashcat_run1.log', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	
	
	#display the standard output from the hashcat command in the command prompt
	while True:
		nextline2 = process2.stdout.readline()
		if nextline2 == b'' and process2.poll() is not None:
			break
		sys.stdout.write(nextline2.decode(sys.stdout.encoding))
		sys.stdout.flush()
	
	#Copy the potfile so that keep-guessing will not guess at hashes cracked by the top rules
	with open(path+'hashcat_run1_toprule_run.potfile') as potfile1:
		linespot = potfile1.readlines()
		with open(path+'hashcat_run1.potfile', 'w') as potfile2:
			potfile2.writelines(linespot)
	
	#Strip passwords cracked without using any rule from the log.
	remove_lines = [':::', ':::']
	with open(path+'hashcat_run1.log') as infile3, open(path+'hashcat_run1-processing.log', 'w') as newfile3:
		for line3 in infile3:
			if not any (remove in line3 for remove in remove_lines):
				newfile3.write(line3)
	
	newfile3.close()
	infile3.close()
	


	#Write back over the original log
	with open(path+'hashcat_run1-processing.log') as f_3:
		lines_3 = f_3.readlines()
		with open(path+'hashcat_run1.log', 'w') as f1_3:
			f1_3.writelines(lines_3)
	
	f_3.close()
	f1_3.close()
	lines_3 = None
	

		
	#Change first and last ':' for '£' as some rules contain :
	file_for_me=open(path+"file_for_me.rule","a")
	with open(path+"hashcat_run1.log", "r") as myfile_for_me:
		for line in myfile_for_me:
			d_for_me = collections.defaultdict(int)
			for c in line:
				d_for_me[c] += 1
			if d_for_me[':'] > 2:
				line=replace_last(line, ':', '£', 1)
				line=line.replace(':', '£', 1)
				file_for_me.writelines(line)
			else:
				line=line.replace(':', '£')
				file_for_me.writelines(line)
				
	file_for_me.close()
	myfile_for_me.close()
	
			

	
	#Write back over the original log
	with open(path+'file_for_me.rule') as f_replacing:
		lines_replacing = f_replacing.readlines()
		with open(path+'hashcat_run1.log', 'w') as fi_replacing:
			fi_replacing.writelines(lines_replacing)
			
	f_replacing.close()
	fi_replacing.close()
	lines_replacing = None
	
	
	#Append actual basewords fired by this top rule to a rolling basewords.dic - this will contain only basewords for each individual rule so any duplication
	#is genuine repetition of that baseword being useful and will only be based on the top rules as they are run.
	#Create new database based on just this run
	#I believe this variable is local so should be reset each time the function is called.
	basewords = pd.read_csv('RuleOrdering\hashcat_run1.log', sep='£', engine='python', quoting=csv.QUOTE_NONE, names=['baseword', 'rule', 'cracked_password'])
	#Append basewords each time, as this can then be used for frequency.
	basewords['baseword'].to_csv(path+'all_basewords_processing.dic', index=False)
	#Also write out all rules as they are hit - as we are just running the top rule at this points, this will just be duplicates of the top rule - but as this file is added to,
	#it will become a genuine list of how often each rule fires, after everything above it has fired - and as such, can be used to combine multiple jobs.
	basewords['rule'].to_csv(path+'all_rules_processing.rule', index=False)
	
	#Append lines from all_basewords_processing.dic to all_basewords.dic
	with open(path+'all_basewords_processing.dic') as f_2_2:
		lines_2_2 = f_2_2.readlines()
		with open(path+'all_basewords.dic', 'a') as fi_2_2:
			fi_2_2.writelines(lines_2_2)
			
			
	basewords = None
	f_2_2.close()
	fi_2_2.close()
	lines_2_2 = None
	
	#Also write out every rule from this run - that will only be repeats of the single top rule, but this means we now will have a file containing actual frequency of each
	#individual rule for this run - including how often it hit AFTER everything that has gone before.
	#Should allow for greater accuracy across jobs as it will then lead to a frequency ordered list of how well rules performed against each other and in their positions?
	#Maybe wrong, but maybe try multiple different methods to do this - this allows this one, and can still do others.
	with open(path+'all_rules_processing.rule') as f2:
		lines2 = f2.readlines()
		with open(path+'all_toprules_hits.rule', 'a') as fi2:
			fi2.writelines(lines2)
			
	f2.close()
	fi2.close()
	lines = None
	
	#Clean up crap
	os.remove(path+'all_basewords_processing.dic')
	os.remove(path+'all_rules_processing.rule')
	os.remove(path+"file_for_me.rule")
	os.remove(path+"hashcat_run1-processing.log")
	
	
	#Append the top rule to the rules_ordered.rule - this is the file that contains all our top rules in order.
	#If this is the first time topRun is ran, it will create this file.
	rules_ordered = open(path+'rules_ordered.rule', 'a')
	with open(path+'top_rule.rule', 'r') as top_rule_file:
		rules_ordered.write(top_rule_file.readline())
		
	rules_ordered.close()
	top_rule_file.close()
	
	
	#Remove top_rule as this will next be created with the new top rule.
	os.remove(path+'top_rule.rule')
	
	#This checks if there are still more rules to process.
	check_rules_processing()
	if (rules_processing_still_has_lines >= int(1)):
		findTopRule()
	return;
	
	
def findTopRule():
	os.remove('RuleOrdering/hashcat_run1.log')

	#Run my desired hashcat command
	#Now we are running using rules_processing.rule which contains every rule except for the ones we have already extracted.
	#We do not want to remove as this is just to find the next top rule.
	#WE MUST USE --KEEP-GUESSING again to find the next genuine top rule
	process3=subprocess.Popen('hashcat64.exe -a 0 -m 1000 --username --keep-guessing --force -w 4 Hashes/hashes RuleOrdering/allbasewords_processing.dic -r RuleOrdering/rules_processing.rule --potfile-path RuleOrdering/hashcat_run1.potfile --debug-mode=4 --debug-file=RuleOrdering/hashcat_run1.log', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	#display the standard output from the hashcat command in the command prompt
	while True:
		nextline = process3.stdout.readline()
		if nextline == b'' and process3.poll() is not None:
			break
		sys.stdout.write(nextline.decode(sys.stdout.encoding))
		sys.stdout.flush()
		

	#Strip passwords cracked without using any rule from the log.
	remove_lines = [':::', ':::']
	with open('RuleOrdering\hashcat_run1.log') as infile4, open('RuleOrdering\hashcat_run1-processing.log', 'w') as newfile4:
		for line4 in infile4:
			if not any (remove in line4 for remove in remove_lines):
				newfile4.write(line4)
				
	infile4.close()
	newfile4.close()
	

	#Write back over the original log
	with open('RuleOrdering\hashcat_run1-processing.log') as f_4:
		lines_4 = f_4.readlines()
		with open('RuleOrdering\hashcat_run1.log', 'w') as f1_4:
			f1_4.writelines(lines_4)
	
	f_4.close()
	f1_4.close()
	lines_4 = None
		
	
	#Change first and last ':' for '£' as some rules contain :
	file_for_me_4=open(path+"file_for_me_4.rule","a")
	with open(path+"hashcat_run1.log", "r") as myfile_for_me_4:
		for line in myfile_for_me_4:
			d_for_me_4 = collections.defaultdict(int)
			for c in line:
				d_for_me_4[c] += 1
			if d_for_me_4[':'] > 2:
				line=replace_last(line, ':', '£', 1)
				line=line.replace(':', '£', 1)
				file_for_me_4.writelines(line)
			else:
				line=line.replace(':', '£')
				file_for_me_4.writelines(line)
				
	file_for_me_4.close()
	myfile_for_me_4.close()
	
	
	#Write back over the original log
	with open(path+'file_for_me_4.rule') as f_replacing_4:
		lines_replacing = f_replacing_4.readlines()
		with open(path+'hashcat_run1.log', 'w') as fi_replacing_4:
			fi_replacing_4.writelines(lines_replacing)
			
	f_replacing_4.close()
	fi_replacing_4.close()
	lines_replacing = None
	

		
	#Read the log file into panda using £ as a delimeter - have to use QUOTE_NONE otherwise will read any " in file as code.
	rules_find = pd.read_csv(path+'hashcat_run1.log', sep='£', engine='python', quoting=csv.QUOTE_NONE, names=['baseword', 'rule', 'cracked_password'])
	#Add count to the rule column
	rules_find['count'] = rules_find.groupby('rule')['rule'].transform(pd.Series.value_counts)

	#Sort rules by count in descending order and drop duplicates based on the word in the rule column
	rules_find = (rules_find.sort_values('count', ascending=False))
	rules_find = rules_find.drop_duplicates(subset='rule')
	
	#Check if the most frequent rule only has a count of 1 - if so, write remaining rules to a file and stop.
	#I can then run these remaining "1 hitter" rules and even still remove ones that don't fire after each other etc - but for now, remove for speed.
	#rules_processing_still_has_lines for bailing on my while loop isn't working, so again, this probably wouldn't work, but this is where it should be stopped!
	top_rule_count = rules_find['count'].iloc[0]
	if (top_rule_count == 1):
		rules_find['rule'].to_csv(path+'remaining_1_or_less.rule', index=False)
		rules_processing_still_has_lines = 0
		return
	
	#At this point we have the rules arranged in descending order from most frequently occuring in the output.

	#Save the results to an output file, without including the row numbering
	#This is now all the rules that fired - in order according to frequency
	rules_find['rule'].to_csv(path+'rules_in_order_processing.rule', index=False, sep='£')
	#Write out the rules in descending order with their counts so we can log the top one
	header = ["rule", "count"]
	rules_find.to_csv(path+'rules_in_order_to_log.rule', columns = header, header = False, index=False)
	
	rules_find = None

	#Now I want to just run the top rule - removing hashes as they are cracked (happens in the top_rule function)
	#So take the top line and write it to top_rule.rule:
	with open(path+'rules_in_order_processing.rule', 'r') as topfile_4:
		first_line = topfile_4.readline()
		#Save the top rule to its own rule file
		top_rule_4 = open(path+'top_rule.rule', 'w')
		top_rule_4.write(first_line)
		top_rule_4.close()
		
	topfile_4.close()
	
	#Now log the top rule and its count to Rev_Thing.log	
	#Read out the top rule and its count to first_line2 for the log:
	with open(path+'rules_in_order_to_log.rule', 'r') as topfile2_4:
		first_line_4 = topfile2_4.readline()
	#Save the top rule and it's count to an evergrowing logfile
	with open(path+'Rev_Thing.log', 'a') as fi_log_4:
		fi_log_4.writelines(first_line_4)
	
	topfile2_4.close()
	fi_log_4.close()
	

	#Delete existing rules_processing and allbasewords_processing to be sure - may be unnecessary
	os.remove(path+'rules_processing.rule')
	os.remove(path+'allbasewords_processing.dic')

	#And remove it from the other rule file
	with open(path+'rules_in_order_processing.rule', 'r') as all_rules_file_4:
		data = all_rules_file_4.read().splitlines(True)
	with open(path+'rules_processing.rule', 'w') as all_rules_out_4:
		all_rules_out_4.writelines(data[1:])
	
	all_rules_file_4.close()
	data = None
	all_rules_out_4.close()
	
	#I want to also output only the basewords that fire each time so that the dictionary will continually also shrink - this dictionary does not need to contain duplicates, so for ease, I will
	#read it into a separate database.
	#Read in the log
	basewords_processing_find = pd.read_csv(path+'hashcat_run1.log', sep='£', engine='python', quoting=csv.QUOTE_NONE, names=['baseword', 'rule', 'cracked_password'])
	
	#Add count and remove duplicates
	basewords_processing_find['count'] = basewords_processing_find.groupby('baseword')['baseword'].transform(pd.Series.value_counts)
	basewords_processing_find = (basewords_processing_find.sort_values('count', ascending=False))
	basewords_processing_find = basewords_processing_find.drop_duplicates(subset='baseword')
	
	#Read this list out to a basewords_processing.dic file
	basewords_processing_find['baseword'].to_csv(path+'allbasewords_processing.dic', index=False)
	
	basewords_processing_find = None
	
	#Clean up crap
	os.remove(path+'rules_in_order_processing.rule')
	os.remove(path+'rules_in_order_to_log.rule')
	os.remove(path+"hashcat_run1-processing.log")
	os.remove(path+"file_for_me_4.rule")


	#At this point - original top rule has been saved to rules_ordered.rule, remaining rules have all run with keep-guessing, a new top rule has been found, this is now top_rule.rule
	#The remaining rules (minus the top two now) are saved again as rules_prcoessing.rule
	
	os.remove('RuleOrdering/hashcat_run1.potfile')
	return;



#Main Program
#Check for RuleOrdering folder and create if necessary
if not os.path.exists(path):
	os.makedirs(path)

#Run firstRun
firstRun()
#Remove crap that for some reason thinks it's still open in firstRun itself.
os.remove(path+'file_replacing.rule')


#After firstRun you have run all rules against the dictionary - you have then taken only the rules that fired and ordered them by frequency.
#You have also extracted the top rule to its own .rule file - top_rule.rule
#You have removed this from the other ruleset which is now called rules_processing.rule
#You have all_rules_all_jobs.rule which contains every rule fired on the first run- so duplicates if used on multiple passwords.
#You have started creating Rev_Thing.log which is logging each top rule as it is extracted with its count
#You have not touched the original hash file
#You have also not extracted used basewords.

#While rules_processing.rule has lines in it, continue calling topRuleRun()
while (rules_processing_still_has_lines >= int(1)):
	topRuleRun()



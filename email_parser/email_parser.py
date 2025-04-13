import re
import os
import sys
import pickle
import math
import json
import random

import time

import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import words

import numpy as np

import gzip

#
# Precompiled patterns for performance
#
time_pattern = re.compile("Date: (?P<data>[A-Z][a-z]+\, \d{1,2} [A-Z][a-z]+ \d{4} \d{2}\:\d{2}\:\d{2} \-\d{4} \([A-Z]{3}\))")
subject_pattern = re.compile("Subject: (?P<data>.*)")
sender_pattern = re.compile("From: (?P<data>.*)")
recipient_pattern = re.compile("To: (?P<data>.*)")
cc_pattern = re.compile("cc: (?P<data>.*)")
bcc_pattern = re.compile("bcc: (?P<data>.*)")
msg_start_pattern = re.compile("\n\n", re.MULTILINE)
msg_end_pattern = re.compile("\n+.*\n\d+/\d+/\d+ \d+:\d+ [AP]M", re.MULTILINE)


'''
# Function to extract enron email main body
'''
feeds = []

def parse_email(pathname):
    with open(pathname) as TextFile:
        text = TextFile.read().replace("\r", "")
        try:
            time = time_pattern.search(text).group("data").replace("\n", "")
            subject = subject_pattern.search(text).group("data").replace("\n", "")

            sender = sender_pattern.search(text).group("data").replace("\n", "")

            recipient = recipient_pattern.search(text).group("data").split(", ")
            cc = cc_pattern.search(text).group("data").split(", ")
            bcc = bcc_pattern.search(text).group("data").split(", ")
            msg_start_iter = msg_start_pattern.search(text).end()
            try:
                msg_end_iter = msg_end_pattern.search(text).start()
                message = text[msg_start_iter:msg_end_iter]
            except AttributeError: # not a reply
                message = text[msg_start_iter:]
            message = re.sub("[\n\r]", " ", message)
            message = re.sub("  +", " ", message)
        except AttributeError:
            logging.error("Failed to parse %s" % pathname) 
            return None
            
        return message



'''
# Function to extract keyword frequencies from the emails
# You only need to use this if you want to get the frequency of the keywords
'''
def get_keyword_frequency(path):
    frequencies = {}
    total = 0

    for folder in os.listdir(path):
        if os.path.isfile(os.path.join(path, folder)):
            continue

        for sub_folder in os.listdir(os.path.join(path, folder)):
            if os.path.isfile(os.path.join(path, folder, sub_folder)):
                continue

            for filename in os.listdir(os.path.join(path, folder, sub_folder)):
                if os.path.isfile(os.path.join(path, folder, sub_folder, filename)):
                    main_body = parse_email(os.path.join(path, folder, sub_folder, filename))
                    total += 1

                    keywords = word_tokenize(main_body)
                    keywords = set([w.lower() for w in keywords])

                    for keyword in keywords:
                        if keyword not in frequencies:
                            frequencies[keyword] = 0
                        frequencies[keyword] += 1


    return frequencies, total
    
    


'''
# Function to extract the keywords from the emails and dump the keywords and the email body into a new file
'''
def build_inverted_index(path_input, include_keywords, N_files):
    inverted_index_target = {}
    for keyword in include_keywords:
        inverted_index_target[keyword] = []

    file_ctr = 0

    
    for folder in os.listdir(path_input):
        if os.path.isfile(os.path.join(path_input, folder)):
            continue


        for sub_folder in os.listdir(os.path.join(path_input, folder)):
            if os.path.isfile(os.path.join(path_input, folder, sub_folder)):
                continue

            for filename in os.listdir(os.path.join(path_input, folder, sub_folder)):
                
                if os.path.isfile(os.path.join(path_input, folder, sub_folder, filename)):
                    file_input = open(os.path.join(path_input, folder, sub_folder, filename), 'r')
                    full_text = file_input.read()
                    file_input.close()

                    
                    main_body = parse_email(os.path.join(path_input, folder, sub_folder, filename))

                    keywords = word_tokenize(main_body)
                    keywords = set([w.lower() for w in keywords if w.lower() in include_keywords and len(w) <= 16])

                    for keyword in keywords:
                        inverted_index_target[keyword] += [file_ctr]

                    file_ctr += 1

                    if file_ctr % (N_docs//20) == 0:
                        print(f"Progress: {file_ctr}/{N_docs} documents processed.")

                    if file_ctr >= N_files:
                        return inverted_index_target




def dump_inverted_index(inverted_index, path_output):
    file_output = open(path_output + f'inveted_index_{N_docs}.txt', 'w')

    for keyword in include_keywords:
        if len(inverted_index[keyword]) > 0:
            file_output.write(keyword + ',' + ','.join(map(str, inverted_index[keyword])) + '\n')

    file_output.close()
                    
    

nltk.download('punkt_tab')
nltk.download('punkt')
nltk.download('words')


N_docs = 5000

file_input = open('./include_keywords.txt', 'r', encoding='windows-1252')
text = file_input.read()
file_input.close()
include_keywords = set(text.split(','))


path_input = '../emails_raw/maildir/'
path_output = '../input/'

time_start = time.time()
inverted_index_target = build_inverted_index(path_input, include_keywords, N_docs)

dump_inverted_index(inverted_index_target, path_output)
time_end = time.time()
print('Time taken: %.2f seconds' % (time_end - time_start))

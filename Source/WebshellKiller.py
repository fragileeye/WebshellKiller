#coding: utf-8
import yara
import sys
import json
import logging
import os
import re
import random
    
class WebshellKiller:
    '''
    Usage & Info
    
    Usage: 
    1> firstly, load the yar file, in this file, you should indicate the features in yara rules
    for matching webshell.

    2> secondly, following the code:
    Killer = WebshellKiller(yara_file, log_file)
    Killer.detect(file_path) or Killer.detect_directory(directory_path)
    
    Info:
    1> the idea which inspires me comes from 'PMF'(https://github.com/nbs-system/php-malware-finder), thanks.
    
    2> very much thanks to the strong tool 'yara'(https://github.com/VirusTotal/yara) and you can refer doc
    (https://yara.readthedocs.io/en/latest/index.html)
    
    3> the precision of the code function, especially depends on the yara rules you've made from 
    samples and the sample definition in yar file is just for consultant. 
    
    4> same as notice: the piece code is just for rigorous testing, IF YOU have any trouble with 
    the error judgement, please stay away from changing the code(just print the result) and calling
    the `kill` method.
    '''
    
    def __init__(self, yara_file, log_file):
        self._load_logger(log_file)
        self._load_rules(yara_file)
            
    def _load_rules(self, yara_file):
        try:
            self.rules = yara.compile(yara_file)
            self.load_done = True
        except yara.Error as e:
            self.load_done = False
            self.cmdx_logger.warning('[*] {0}'.format(e))
    
    def _load_logger(self, log_file):
        self.file_logger = self._load_logger_(log_file)
        self.cmdx_logger = self._load_logger_('console')
        
    def _load_logger_(self, name='console'):
        logname = os.path.basename(name) + str(random.randint(0, 9527))
        xlogger = logging.getLogger(logname)
        xformat = logging.Formatter('%(asctime)s - %(message)s')
        if name == 'console': 
            handler = logging.StreamHandler() 
        else:
            handler = logging.FileHandler(name)
        handler.setLevel(logging.INFO)
        handler.setFormatter(xformat)
        xlogger.setLevel(logging.INFO)
        xlogger.addHandler(handler)
        return xlogger   
        
    def match_filter(self, data):
        if data.get('matches'):
            match_tags = data.get('tags', None)
            match_type = data['rule'] if not match_tags else match_tags[0]
            nasty_keys, match_keys = set(), list()
            for x in data['strings']:
                if x[-1] not in nasty_keys: 
                    nasty_keys.add(x[-1])
                    match_keys.append(x)  
            message = '[_Trigger] > {0} with keys:{1}'.format(match_type, match_keys)
            self.file_logger.warning(message) #Log the triggered features 
        return yara.CALLBACK_CONTINUE  
    
    def data_filter(self, data):
        valid_regex = re.escape('\\u(\\d){4}').encode()
        if re.search(valid_regex, data):
            return data.decode('unicode_escape').encode()
        else:
            return data
    
    def detect_file(self, fp, fpath):
        detect_message = None
        matched_list = self.rules.match(data=self.data_filter(fp.read()),
                callback=self.match_filter, which_callbacks=yara.CALLBACK_MATCHES)            
        if len(matched_list) > 0: 
            detect_message = '[Webshell] > {0}'.format(fpath)
            self.file_logger.warning(detect_message + '\r\n')
            self.cmdx_logger.warning(detect_message)
        else : 
            detect_message = 'NormalPage > {0}'.format(fpath)
            self.cmdx_logger.info(detect_message)
        return detect_message
    
    def detect(self, fpath):
        try:
            if not self.load_done: return None
            with open(fpath, 'rb') as fp: return self.detect_file(fp, fpath)
        except:
            return None
        
    def detect_directory(self, dpath, recursive=False):
        if not recursive:
            for fname in os.listdir(dpath):
                fpath = os.path.join(dpath, fname)
                if os.path.isfile(fpath): 
                    self.detect(fpath)
        else:
            for root, dirs, files in os.walk(dpath):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    self.detect(fpath)
        
    #warning: please do not kill file casually, be a gentle killer. 
    def kill(self, fpath):
        os.remove(fpath)

if __name__ == '__main__':
    killer = WebshellKiller(r'../Config/JavaWebshellKiller.yar', r'../Log/Webshell.log')
    killer.detect_directory(r'../Samples/jsp', recursive=True)
    #killer.detect(r'../Samples/php/w2_dama_140.php')
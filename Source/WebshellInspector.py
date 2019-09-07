#coding: utf-8
import simhash
import re
import os
import json
import sys
import logging
import random

#webshell samples (path) for featuring and training.
CONFIG_SAMPLES  = 'samples'
CONFIG_FEATURES = 'features'

class WebshellInspector:    
    '''
    thanks for the great guys supporting such things:
    1> the elegant algorithim(http://www.wwwconference.org/www2007/papers/paper215.pdf) and 
    beautiful code(https://leons.im/posts/a-python-implementation-of-simhash-algorithm/)
    
    2> the good idea for using simhash to detect webshell, especially with signatures that 
    couldn't be easilly encoding.(http://www.cnki.com.cn/Article/CJFDTotal-TXJS201803029.htm)
    
    3> the authors collecting so many samples and sharing freely.
    (https://github.com/tennc/webshell, https://github.com/ysrc/webshell-sample, https://github.com/xl7dev/WebShell)
    '''
    
    '''
    Usage：some tips for easily using this piece code.
    1> firstly, define a json file which has formats as the JAVA_NASTY_SIG, in this file, you should indicate
    the directory which includes the samples for extract the simhash values, and the signatures for training.
    
    2> secondly, following the code:
    JInspector = JavaWebshellInspector(config_file, log_file)
    JInspector.detect(file_path) or JInspector.detect_directory(directory_path)
    '''
    
    def __init__(self, config_file, log_file):
        self.black_list = set()
        self._load_logger(log_file)
        self._load_config(config_file)
        self._load_samples()
    
    def _load_logger(self, log_file):
        self.file_logger = self._load_logger_(log_file)
        self.cmdx_logger = self._load_logger_('console')
        
    def _load_logger_(self, name):
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
    
    def _load_config(self, config_file):
        with open(config_file, 'rb') as fp:
            try:
                configs = json.load(fp)
                self.samples = configs[CONFIG_SAMPLES]
                self.features = configs[CONFIG_FEATURES]
                self.valid_regex = b'|'.join([re.escape(x).encode() for x in self.features])
                self._init_done = True
            except FileNotFoundError:
                abs_config_file = os.path.abspath(config_file)
                self.cmdx_logger.info('File {0} not found!'.format(abs_config_file))
            except json.JSONDecodeError as e:
                self._init_done = False
                self.cmdx_logger.info('Invalid config file: {0}... $'.format(e))
            
    def _load_samples(self):
        if not self._init_done: return
        for sample_dir in self.samples:
            self._load_sample_directory(sample_dir)
        self.detector = simhash.SimhashIndex(list(self.black_list), k=3)
    
    def _load_sample_directory(self, sample_dir):
        for root, dirs, files in os.walk(sample_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                self._load_sample_with_features(fpath)
    
    def _load_features_from_file(self, fp):
        file_data = self.data_filter(fp.read())
        return [x.decode() for x in re.findall(self.valid_regex, file_data, re.I)]
    
    def _load_sample_with_features(self, fpath):
        with open(fpath, 'rb') as fp:
            hash_set = self._load_features_from_file(fp)
            hash_result = simhash.Simhash(hash_set)
            self.black_list.add((fpath, hash_result))        
    
    def data_filter(self, data):
        valid_regex = re.escape('\\u(\\d){4}').encode()
        if re.search(valid_regex, data):
            return data.decode('unicode_escape').encode()
        else:
            return data
    
    def _detect_internal(self, fpath):
        with open(fpath, 'rb') as fp:
            detect_result = dict()
            hash_set = self._load_features_from_file(fp)
            hash_result = simhash.Simhash(hash_set)
            matched_samples = self.detector.get_near_dups(hash_result)
            if len(matched_samples) > 0:
                detect_messgae = '[Webshell] > {0} with matches: {1}'.format(fpath, matched_samples)
                self.cmdx_logger.warning(detect_messgae)
                self.file_logger.warning(detect_messgae + '\r\n')
                detect_result[fpath] = True
            else:
                detect_messgae = 'NormalPage > {0}.'.format(fpath)
                self.cmdx_logger.info(detect_messgae) 
                detect_result[fpath] = False
            return detect_result   #A dict which key means file path and value is a bool value.

    def detect_file(self, fpath):
        if not self._init_done: 
            return None
        try:
            fpath = os.path.abspath(fpath)
            return self._detect_internal(fpath)
        except:
            return None
        
    def detect_directory(self, dpath, recursive=False):
        if not self._init_done: 
            return None
        detect_results = dict()
        if not recursive:
            for fname in os.listdir(dpath):
                fpath = os.path.join(dpath, fname)
                if os.path.isfile(fpath):
                    detect_result = self.detect_file(fpath)
                    if detect_result:
                        detect_results.update(detect_result)
        else:
            for root, dirs, files in os.walk(dpath):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    detect_result = self.detect_file(fpath)
                    if detect_result:
                        detect_results.update(detect_result)
        return detect_results
    
    def detect(self, path, recursive=False):
        if os.path.isdir(path):
            return self.detect_directory(path, recursive)
        else:
            return self.detect_file(path)
        
if __name__ == '__main__':
    inspector = WebshellInspector(r'../Config/JavaWebshellInspector.json', r'../Log/Webshell.log')
    #inspector.detect(r'../Samples/jsp', recursive=True)
    inspector.detect(r'../Samples/jsp/w1_caidao_3.jsp')

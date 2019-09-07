#coding: utf-8
from WebshellKiller import WebshellKiller
from WebshellInspector import WebshellInspector
import os
import re
    
class WebshellDetector:
    def __init__(self, config_directory, logger_directory):
        self.config_directory = config_directory
        self.logger_directory = logger_directory
        self._init_detectors()
    
    def _init_killer(self, magic_head):
        config_fpath = os.path.join(self.config_directory, 
                                    "{0}WebshellKiller.yar".format(magic_head))   
        logger_fpath = os.path.join(self.logger_directory, "Webshell.log")
        return WebshellKiller(config_fpath, logger_fpath)

    def _init_inspector(self, magic_head):
        config_fpath = os.path.join(self.config_directory, 
                                    "{0}WebshellInspector.json".format(magic_head))
        logger_fpath = os.path.join(self.logger_directory, "Webshell.log")
        return WebshellInspector(config_fpath, logger_fpath)

    def _init_detectors(self):
        self.valid_regex = re.compile('JSP(X)?|AS(P|H)X|PHP(\\d)?', re.I)
        self.detectors = {
            1: {
                'J': self._init_killer('Java'),
                'A': self._init_killer('Aspx'),
                'P': self._init_killer('Php')
            },
            0: {
                'J': self._init_inspector('Java'),
                'A': self._init_inspector('Aspx'),
                'P': self._init_inspector('Php')
            }
        }
           
    def _detect_file(self, fpath):
        fname = os.path.basename(fpath)
        match_type = re.search(self.valid_regex, fname)
        if match_type: 
            index = (match_type[0][0]).upper()
            detector = self.detector_team[index]
            return detector.detect(fpath)
        return None
                
    def _detect_directory(self, dpath, recursive=False):
        detect_results = dict()
        if not recursive:
            for fname in os.listdir(dpath):
                fpath = os.path.join(dpath, fname)
                if os.path.isfile(fpath): 
                    detect_result = self._detect_file(fpath)
                    if detect_result:
                        detect_results.update(detect_result)
        else:
            for root, dirs, files in os.walk(dpath):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    detect_result = self._detect_file(fpath)
                    if detect_result: 
                        detect_results.update(detect_result)
        return detect_results
        
    def detect(self, path, level=1, recursive=False):
        if level:
            self.detector_team = self.detectors[1]
        else:
            self.detector_team = self.detectors[0]

        if os.path.isdir(path):
            return self._detect_directory(path, recursive)
        else:
            return self._detect_file(path)    

if __name__ == '__main__':
    detector = WebshellDetector(r'../Config', r'../Log')
    #detector.detect(r'../Samples/php/w2_dama_140.php', level=0)
    detector.detect(r'../Samples/jsp', level=1)
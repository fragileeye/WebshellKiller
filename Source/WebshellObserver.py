#coding: utf-8
import abc
import math
import os
import re
import zlib

class BaseCalculator(metaclass=abc.ABCMeta):
    def __init__(self):
        self.valid_regex = re.compile('\.ASPX|\.JSPX?|\.PHP\d?', re.I)
        self.result_dict = {}
        self.sorted_list = list()
    
    def _reset(self):
        if self.result_dict:
            self.result_dict.clear()
        if self.sorted_list:
            self.sorted_list.clear()
    
    def valid_file(self, fpath):
        if not os.path.isfile(fpath):
            return False
        if re.search(self.valid_regex, fpath):
            return True
        return False
    
    @abc.abstractclassmethod
    def calc_from_data(self, data):
        pass
    
    def calc_from_file(self, fpath):
        with open(fpath, 'rb') as fp:
            calc_result = self.calc_from_data(fp.read())
            calc_result = round(calc_result, 3)
            return calc_result
        
    def _calc_from_alldir(self, dpath):
        for root, dirs, files in os.walk(dpath):
            for fname in files:
                fpath = os.path.join(root, fname)
                if not self.valid_file(fpath):
                    continue
                calc_result = self.calc_from_file(fpath)
                calc_result = round(calc_result, 3)
                self.result_dict[fpath] = calc_result
                
    def _calc_from_curdir(self, dpath):
        for fname in os.listdir(dpath):
            fpath = os.path.join(dpath, fname)
            if os.path.isfile(fpath):
                if not self.valid_file(fpath):
                    continue                
                calc_result = self.calc_from_file(fpath)
                calc_result = round(calc_result, 3)
                self.result_dict[fpath] = calc_result                
                
    def calc_from_directory(self, dpath, recursive=False, reverse=True):
        self._reset()
        if not os.path.isdir(dpath):
            return self.result_dict
        if recursive:
            self._calc_from_alldir(dpath)
        else:
            self._calc_from_curdir(dpath)
        self.sorted_list = sorted(self.result_dict.items(), 
                                  key=lambda x: x[1], reverse=reverse)
        return self.result_dict
        
    def show_message(self):
        title = self.__class__.__name__
        print('[Rank list "{0}"]'.format(title))
        if not self.sorted_list or not len(self.sorted_list): 
            return 
        for f, v in self.sorted_list:
            print(' {0:>7.4f}\t{1}'.format(v, f))
    
class LanguageIC(BaseCalculator): #No reverse
    def __init__(self):
        super().__init__()
    
    def calc_from_data(self, data):
        if not data or not len(data):
            return 0        
        sum_, char_counts, char_count_dict = 0, 0, dict()
        for x in range(256):
            char = bytes(chr(x), 'utf-8')
            if char not in char_count_dict: char_count_dict[char] = 0
            char_count_dict[char] += data.count(char)
            char_counts += data.count(char)
        for value in char_count_dict.values():
            if value > 0: sum_ += value * (value - 1)
        text_ic = sum_ / ((char_counts - 1) * char_counts)
        return text_ic 
    
class TextEntropy(BaseCalculator):
    def __init__(self):
        super().__init__()
        self.strip_pattern = re.compile(b'(/\*[^/]*/)|(//[^\n]*)|(\s+)')
    
    def calc_from_data(self, data):
        if not data or not len(data):
            return 0
        text_entropy  = 0
        stripped_data = re.sub(self.strip_pattern, b'', data)
        stripped_size = len(stripped_data)
        for x in range(256):
            char = bytes(chr(x), 'utf-8')
            prob = stripped_data.count(char) / stripped_size
            if prob > 0: text_entropy += -prob * math.log(prob, 2)
        return text_entropy

class LongestWord(BaseCalculator):
    def __init__(self):
        super().__init__()
        self.split_pattern = re.compile(b'[= \t\'"]')
        
    def calc_from_data(self, data):
        if not data or not len(data):
            return 0
        words_list = re.split(self.split_pattern, data)
        return max([len(x) for x in words_list])
    
class Compression(BaseCalculator): 
    def __init__(self):
        super().__init__()
    
    def calc_from_data(self, data):
        if not data or not len(data):
            return 0
        compressed_data  = zlib.compress(data)
        compressed_ratio = len(compressed_data) / len(data)
        return compressed_ratio
    
if __name__ == '__main__':
    exp_directory = r"D:\Python代码\webshell检测\代码\Flask\samples\jsp"
    ic = LanguageIC()
    ic.calc_from_directory(exp_directory, reverse=False)
    ic.show_message()
    #e = TextEntropy()
    #e.calc_from_directory(exp_directory)
    #e.show_message()
    #l = LongestWord()
    #l.calc_from_directory(exp_directory)
    #l.show_message()
    #c = Compression()
    #c.calc_from_directory(exp_directory)
    #c.show_message()
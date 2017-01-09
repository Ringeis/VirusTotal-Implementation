'''
@author: jringeis
'''

import contextlib
from configobj import ConfigObj
import fnmatch
import glob
import json
import optparse
import os
import postfile
import re
import shutil
import threading
import time
import traceback
import urllib
import urllib2
import zipfile
import requests

REQ_LIM = 4

class Driver_virus_test(object):
    
    def __init__(self, key, antivirus):
        self.api_key = key
        self.host = "www.virustotal.com"
        self.num_of_reqs = 0
        self.antivirus_dict = antivirus.values()
        self.req_lock = threading.Lock()
        
    def check_lim(self):
        """check_lim: verifies that the maximum number of requests has not been reached"""
        with self.req_lock:
            self.num_of_reqs+=1
            if self.num_of_reqs >= REQ_LIM:
                time.sleep(60)
                self.num_of_reqs-=1   
    
    def parse_report(self, report, driver):
        """parse_report: pretty printing of output in both the terminal/cmdline and text file
                report - dictionary containing results of the completed scan
                driver - name of file that scan has been enacted upon"""
        analysis = open("vt_analysis-%s.txt" % (driver[:-4]), 'w')
        print("- Opening \'%s\' to write . . . " % (analysis.name))
        time.sleep(3) #readability
        for key in report:
            if ((str(report[key]["detected"]) == 'True') and (key in self.antivirus_dict)):
                analysis.write("%s - virus detected: %s " % (key, report[key]["detected"]))
                print("\tVirus flag hit by \'%s\'" % (key))
                analysis.write("-- result: \'%s\'\n\n" % (report[key]["result"]))
        analysis.close()
        if (os.path.getsize(os.path.abspath(analysis.name)) > 0):
            print("- Scan report for \'%s\' written to \'%s\'.\n" % (driver, analysis.name))
        else:
            print("- Scan report for \'%s\' contains no flags." % (driver))
            print("- Removing empty report file \'%s\'.\n" % (analysis.name))
            os.remove(os.path.abspath(analysis.name))
    
    def scan_file(self, driver):
        """scan_file: makes request for scan; returns response
                driver - name of file to be scanned for potential virus"""
        if os.stat(driver).st_size >= 33554432L:
            params = {'apikey': self.api_key}
            # obtaining the upload URL
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/scan/upload_url', params=params)
            json_response = response.json()
            upload_url = json_response['upload_url']
            # submitting the file to the upload URL
            files = {'file': (driver, open(driver, 'rb'))}
            self.check_lim()
            response = requests.post(upload_url, files=files)
            request = response.json()
            print("- Scan request sent for %s.\n" % (os.path.basename(driver)))
            report = Request_handler(request, self, driver)
            if report:
                report.refresh()
            
            return report
        else:
            selector = "https://www.virustotal.com/vtapi/v2/file/scan"
            fields = {"apikey": self.api_key,}.items()
            content = open(driver, "rb").read()
            files = [("file", driver, content)]
        
            self.check_lim()
            request = postfile.post.post_multipart(self.host, selector, fields, files)
            print("- Scan request sent for %s.\n" % (os.path.basename(driver)))
            report = Request_handler(request, self, driver)
            if report:
                report.refresh()
            
            return report
       
    def request_report(self, resource, driver):
        """request_report: makes request for completed scan report; returns response
                resource - the scan_id of the pending request; a md5/sha1/sha256 hash, 
                driver - name of file that scan has been enacted upon"""
        selector = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {"resource": resource,
                      "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        
        self.check_lim()
        req = urllib2.Request(selector, data)  
        request = urllib2.urlopen(req).read()
        print("- Report request sent for %s.\n" % (os.path.basename(driver)))
        report = Request_handler(request, self, driver)
        
        return report

class Request_handler(object):
    
    def __init__(self, request, parent, driver):
        if isinstance(request, str):
            self.report = json.loads(request)
        else:
            self.report = request
        self.parent = parent
        self.refresh(self.report)
        self.driver = driver
        
    def refresh(self, response = None):
        """refresh: updates the status of the pending request
                response - result of report query""" 
        if response is not None:
            response = response
            self.report = response
        else:
            response = self.parent.request_report(self.report["scan_id"], self.driver)
            self.report = response.report
    
    @property
    def status(self):
        """status: gets and returns status of report query updated by refresh"""
        return {-2: "pending",1: "ok",0: "ko",}.get(self.report["response_code"])

    def wait(self):
        """wait: scanning files takes time"""
        self.refresh()
        while self.status != "ok":
            print("\t%s - Report '%s'\n" % (os.path.basename(self.driver), self.status))
            time.sleep(60) #4 requests per/min to virus total 
            self.refresh()

def unzip(mount_path):
    #removed
    #this method unpacked drivers and executibles from a mounted staging area

def parse_command_options():
    parser = optparse.OptionParser(usage = """%prog <RESOURCE(S)>
    RESOURSE - <Customer> <Release> <Build>
        Customer: [Default_Kits|Customer_Kits|etc.]
        Release: xx.x
        Build: <xx.x.xx>""")
    args = parser.parse_args()
    if len(args[1]) < 3:
        parser.print_usage()
        return -1
    
    return args[1]

def main():
    """Main function run from virustotal.sh; accepts 1-4 files to scan for potential threats"""
    arguments = parse_command_options()
    config = ConfigObj('virus_total.cfg')
    mount_path = "network system containing files for scanning"
    if os.path.ismount("/mountDir"):
        os.system("umount /mountDir")
    elif not os.path.isdir("/mountDir"):
        os.makedirs("/mountedDir")
    os.system("mount -t nfs 'network system containing files for scanning' /mountDir")
    if not str(arguments[0]) == "Customer_Kits":
        resource_path = os.path.join(mount_path, "%s/R%s/%s/Windows/" %(str(arguments[0]), str(arguments[1]), str(arguments[2])))
        file_list = config['FileList']
    else:
        resource_path = os.path.join(mount_path, "%s/R%s/%s/" %(str(arguments[0]), str(arguments[1]), str(arguments[2])))
        file_list = config['CustomerKit']
        unzip(resource_path)
        resource_path = "./Customer_Kits"
    antivirus = config['AntivirusList']
    key = config['api_key']
    start_msg = "Beginning scan for possible malicious flags on:"
    drivers = []
    for component in file_list.keys():
        for driver in glob.glob(os.path.join(resource_path, file_list[component])):
            drivers.append(driver)
            start_msg+=" \'%s\'," % (os.path.basename(driver))
    print "%s\n\n" % (start_msg)
    virus_test = Driver_virus_test(key, antivirus)
    
    def run_virus_test(driver):   
        try:
            print("Virus Total Scan of \'%s\' initiated . . .\n" % (os.path.basename(driver)))
            report = virus_test.scan_file(driver)
            report.wait()
            print("- Scan complete for %s." % (os.path.basename(driver)))
            time.sleep(1) #readability of output to CLI
            print("- Report for %s received." % (os.path.basename(driver)))
            virus_test.num_of_reqs-=1
            virus_test.parse_report(report.report["scans"], os.path.basename(driver))
        except:
            traceback.print_exc()
            print("ERROR: Something went wrong for %s!" % (os.path.basename(driver)))
            print("Likely reached request limit. Run again when current scan is complete.\n")
    
    threads = []
    for driver in drivers:
        thread = threading.Thread(target = run_virus_test, args = (driver, ))
        threads.append(thread)
        thread.daemon = True
        thread.start()    
        
    for thread in threads:
        while thread.is_alive():
            try:
                thread.join(0.1)

            except KeyboardInterrupt:
                print("Thread interrupted!")
                return
        
        
if __name__ == '__main__':
    main()
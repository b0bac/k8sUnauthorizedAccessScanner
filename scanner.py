########################################################################################################################
#                              Kubernetes Unauthorized Access Vulnerability Scanner                                    #
#                                               Author:  b0b@c                                                         #
########################################################################################################################

# import files, modules, packages
import sys
import time
import datetime
import urllib3
import requests
import threading
from optparse import OptionParser
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


BANNER = """
########################################################################################################################
#                              Kubernetes Unauthorized Access Vulnerability Scanner                                    #
#                                               Author:  b0b@c                                                         #
########################################################################################################################
"""


# define result logger
def write_log(content) -> None:
    timestamp: str = str(datetime.datetime.fromtimestamp(time.time()))
    with open("./running.log", 'a') as file_writer:
        content: str = str(content).replace("\n", "")
        message: str = "[%s] %s\n" % (timestamp, content)
        try:
            file_writer.write(message)
        except Exception as error:
            err_message: str = "[-][%s]Write log error!" % timestamp
            file_writer.write(err_message)

def k8s_apiserver_unauthorized_access_vulnerability_verify(target: str) -> None:
    """Judge the text of the response packet to see if target is vulnerable with apiserver!"""
    try:
        response: requests.Response = requests.get(target, verify=False, timeout=5)
        if response.status_code == 200 and response.text.find("api") > 0 and response.text.find("k8s") > 0:
            print("[+] [%s] has k8s apiserver unauthorized access vulnerability!" % str(target))
    except Exception as error:
        write_log(error)


def k8s_kubelet_unauthorized_access_vulnerability_verify(target: str) -> None:
    """Judge the text of the response packet to see if target is vulnerable with kubelet!"""
    target: str = target + "/pods" if target[-1] != "/" else target + "pods"
    try:
        response: requests.Response = requests.get(target, verify=False, timeout=5)
        if response.status_code == 200 and response.text.find("apiVersion") >= 0:
            print("[+] [%s] has k8s kubelet unauthorized access vulnerability!" % target)
    except Exception as error:
        write_log(error)


def k8s_etcd_unauthorized_access_vulnerability_verify(target: str) -> None:
    """Judge the text of the response packet to see if target is vulnerable with etcd!"""
    target: str = target + "/v2/keys" if target[-1] != "/" else target + "v2/keys"
    try:
        response: requests.Response = requests.get(target, verify=False, timeout=5)
        if response.status_code == 200 and response.text.find("dir: true") >= 0:
            print("[+] [%s] has k8s etcd unauthorized access vulnerability!" % target)
    except Exception as error:
        write_log(error)


def k8s_dashboard_unauthorized_access_vulnerability_verify(target: str) -> None:
    """Just support to show the content length of response packet!"""
    try:
        response: requests.Response = requests.get(target, verify=False, timeout=5)
        count: str = str(response.headers.get("Content-Length"))
        if response.status_code == 200 and int(count) > 500:
            print("[*] [%s] The response content length is %s , please judge it by manual!" % (target, count))
    except Exception as error:
        write_log(error)


def k8s_public_cluster_info_unauthorized_access_vulnerability_verify(target: str) -> None:
    """Judge the text of the response packet to see if target is vulnerable with cluster info!"""
    if target[-1] != "/":
        target = target + "/api/v1/namespaces/kube-public/configmaps/cluster-info"
    else:
        target = target + "api/v1/namespaces/kube-public/configmaps/cluster-info"
    try:
        response: requests.Response = requests.get(target, verify=False, timeout=5)
        if response.status_code == 200 and response.text.find("certificate-authority-data") >= 0:
            print("[+] [%s] has k8s cluster info unauthorized access vulnerability!" % target)
    except Exception as error:
        write_log(error)


def docker_registry_unauthorized_access_vulnerability_verify(target: str) -> None:
    """Judge the text of the response packet to see if target is vulnerable with docker registry!"""
    target: str = target + "/v2/_catalog" if target[-1] != "/" else target + "v2/_catalog"
    try:
        response: requests.Response = requests.get(target, verify=False, timeout=5)
        if response.status_code == 200 and response.text.find("repositories") > 0 :
            print("[+] [%s] has docker registry unauthorized access vulnerability!" % str(target))
    except Exception as error:
        write_log(error)


def docker_remote_unauthorized_access_vulnerability_verify(target: str) -> None:
    """Judge the text of the response packet to see if target is vulnerable with docker remote!"""
    target: str = target + "/version" if target[-1] != "/" else target + "version"
    try:
        response: requests.Response = requests.get(target, verify=False, timeout=5)
        if response.status_code == 200 and response.text.find("Platform") > 0 :
            print("[+] [%s] has docker registry unauthorized access vulnerability!" % str(target))
    except Exception as error:
        write_log(error)


# define k8s sacnner creater
class K8sScannerCreater(object):
    """Define this class to handle input target, threading pool and so on ... """
    def __init__(self, function, target: str, target_file: str = None, thread_count: int = 10):
        self.target_list: list = []
        self.function_name = function
        self.thread_count: int = thread_count
        self.thread_size: int = 0
        self.thread_list: list = []
        # start to handle target file
        if target_file is not None:
            try:
                with open(target_file, 'r') as file_reader:
                    for line in file_reader:
                        line = line.split("\n")[0].split("\r")[0]
                        self.target_list.append(line)
            except Exception as error:
                print("[-] Get targets information error!")
                write_log(error)
        # start to handle target
        elif target is not None:
            self.target_list.append(target)
        print("[+] Get targets finished!")
        self.target_count: int = len(self.target_list)

    def verify(self) -> None:
        """Running verify functions with multi-thread!"""
        if len(self.target_list) <= 0:
            print("[-] No targets to scan!")
            return
        print("[+] Start scanning! Totally %s targets!" % str(len(self.target_list)))
        for target in self.target_list:
            if self.thread_size < self.thread_count:
                thread = threading.Thread(target=self.function_name, args=(target,))
                self.thread_list.append(thread)
                self.thread_size += 1
                self.target_count -= 1
            if self.thread_size == self.thread_count or self.thread_szie == len(self.target_list) or self.target_count == 0:
                for thread in self.thread_list:
                    thread.start()
                for thread in self.thread_list:
                    thread.join()
                self.thread_list = []
                self.thread_size = 0


# define main class
class K8sScanner:
    """Define main class to handle input parameter!"""
    def __init__(self, target: str, target_file: str, scan_vulnerability: str, count: int = 10):
        self.scanner = None
        # start to choose functions
        if scan_vulnerability == "apiserver":
            self.scanner = K8sScannerCreater(k8s_apiserver_unauthorized_access_vulnerability_verify, target, target_file, count)
        elif scan_vulnerability == "kubelet":
            self.scanner = K8sScannerCreater(k8s_kubelet_unauthorized_access_vulnerability_verify, target, target_file, count)
        elif scan_vulnerability == "etcd":
            self.scanner = K8sScannerCreater(k8s_etcd_unauthorized_access_vulnerability_verify, target, target_file, count)
        elif scan_vulnerability == "dashboard":
            self.scanner = K8sScannerCreater(k8s_dashboard_unauthorized_access_vulnerability_verify, target, target_file, count)
        elif scan_vulnerability == "cluster":
            self.scanner = K8sScannerCreater(k8s_public_cluster_info_unauthorized_access_vulnerability_verify, target, target_file, count)
        elif scan_vulnerability == "registry":
            self.scanner = K8sScannerCreater(docker_registry_unauthorized_access_vulnerability_verify, target, target_file, count)
        elif scan_vulnerability == "remote":
            self.scanner = K8sScannerCreater(docker_remote_unauthorized_access_vulnerability_verify, target, target_file, count)

        else:
            pass

    def run(self):
        """Running function!"""
        if self.scanner is not None:
            self.scanner.verify()


if __name__ == "__main__":
    print(BANNER)
    parser = OptionParser("")
    parser.add_option("-t", dest="target", help="target to scan")
    parser.add_option("-f", dest="targetfile", help="target file to scan")
    parser.add_option("-v", dest="scanvulnerability", help="vulnerability to scan? [apiserver | kubelet | etcd | dashboard | cluster | remote | registry]")
    parser.add_option("-c", dest="threadcount", help="count of thread?[10,15,20,25,30,35,40,45,50]")
    (options, args) = parser.parse_args()
    if options.scanvulnerability not in ["apiserver", "kubelet", "etcd", "dashboard", "remote", "registry", "cluster"]:
        print("[-] Got unknown vulnerability name! Please choose from 'apiserver', 'kubelet', 'etcd', 'dashboard', 'registry', 'remote'!")
        sys.exit(0)
    print("[+] Start to check %s!" % str(options.scanvulnerability) )
    options.threadcount = int(options.threadcount)
    if options.threadcount not in [10, 15, 20, 25, 30, 35, 40, 45, 50]:
        options.threadcount = 10
    print("[+] Configure maximum thread count to %s!" % str(options.threadcount))
    k8sscanner = K8sScanner(options.target, options.targetfile, options.scanvulnerability, options.threadcount)
    k8sscanner.run()
    print("[+] Scanning finished! ByeBye!")

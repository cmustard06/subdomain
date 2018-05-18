#!/usr/bin/env python
# -*- coding: utf-8 -*-

import optparse
import sched
import time
import dns.resolver
import json
import multiprocessing
from datetime import datetime
from string import digits, ascii_lowercase
from random import sample

schedule = sched.scheduler(time.time, time.sleep)
bingo = multiprocessing.Queue()


class DomainsBrute:
    def __init__(self, target_domain, subdomain_dict):
        """
        初始化类和成员变量
        :param target_domain:  目标域名host
        :param subdomain_dict: 子域名爆破字典
        :param domain_id: 域名在数据库中所对应的IP
        :param domain_name: 域名的名字，如百度
        """
        self.target_domain = target_domain  
        self.subdomain_dict = subdomain_dict  
        self.domain_list = [] 
        self.result = {}  
        self.random_subdomain = ''.join(sample(digits + ascii_lowercase, 10)) + '.' + self.target_domain

    # check wildcard DNS record
    def resolver_check(self):
        """
        对随机生成一个域名并进行处理，如果这个随机的域名存在就返回解析的结果
        :return: [] or False
        """
        try:
            ha_resolver_domain(self.random_subdomain)  # 对这个随机生成的DNS域名解析
            if ha_resolver_domain(self.random_subdomain)[self.random_subdomain]:  # 如果解析成功就返回解析的地址
                return ha_resolver_domain(self.random_subdomain)[self.random_subdomain]
            else:
                return False
        except Exception as e:
            return False

    def handle_domain(self):
        """
        组成新的二级或者三级域名
        :return: <type 'list'>: [u'123.baidu.com', u'2323.baidu.com', u'sds.baidu.com']
        """
        for sub_domain in self.subdomain_dict:
            self.domain_list.append(
                sub_domain.strip() + '.' + self.target_domain)  # <type 'list'>: [u'123.baidu.com', u'2323.baidu.com', u'sds.baidu.com']

    # handle wildcard DNS record
    def handle_result(self):
        """
        获取处理的结果，如果该二级或者三级域名存在，则存入数据库，
        :return:
        """
        result_wildcard = {}
        for result in self.result:  # <type 'list'>: [{u'123.baidu.com': ['61.135.169.121', '61.135.169.125']}, {}, {}, {}, {}]
            # 这里为了处理空字典
            if result:
                if self.resolver_check():
                    for domain in result.keys():
                        for record in result[domain]:
                            if record not in self.resolver_check():
                                result_wildcard[domain] = result[domain]
                                self.printinfo(result_wildcard)
                                result_wildcard = {}
                else:
                    self.printinfo(result)

    def printinfo(self, result):
        global bingo
        print(u"成功查找，结果为：{}".format(result))
        bingo.put(json.dumps(result))

    def run_multi(self):
        """
        多进程解析域名
        :return:
        """
        self.handle_domain()
        scanner_pool = multiprocessing.Pool(processes=200)
        self.result = scanner_pool.map(ha_resolver_domain, self.domain_list)
        scanner_pool.close()
        scanner_pool.join()
        self.handle_result()


def ha_resolver_domain(domain):
    """
    解析域名，返回解析结果
    :param domain:
    :return: {'baidu.com': ['220.181.57.216', '123.125.115.110']}
    """
    _result = {}
    record_a = []
    record_cname = []
    try:
        respond = dns.resolver.query(domain.strip())
        for record in respond.response.answer:
            for i in record.items:
                if i.rdtype == dns.rdatatype.from_text('A'):
                    # 判断该解析的IP是否为A记录
                    record_a.append(str(i))
                    _result[domain] = record_a
                    # 判断是否为Cname记录
                elif i.rdtype == dns.rdatatype.from_text('CNAME'):
                    record_cname.append(str(i))
                    _result[domain] = record_cname
    except Exception as e:
        pass
    # del record_a
    # del record_cname
    return _result  # {'baidu.com': ['220.181.57.216', '123.125.115.110']}


def start_brute(domain_list, subdomain_list, isThird=False):
    """

    :param domain_list:
    :param subdomain_list:
    :param isThird:
    :return:
    """

    start_date = datetime.now()
    for target in domain_list:
        start = DomainsBrute(target, subdomain_list)
        start.run_multi()
    # 是否开启三级域名扫描
    if isThird:
        while not bingo.empty():
            result = bingo.get()
            result = json.loads(result)
            next_subdomain = result.keys()[0]  # u'123.baidu.com'
            start = DomainsBrute(next_subdomain, subdomain_list)
            start.run_multi()
    scan_time = datetime.now() - start_date
    print("++++++++++ Scan Done! ++++++++++ time consuming {}s".format(scan_time.total_seconds()))


def main():
    domains = []
    helps = """Usage: subdomain_2.py [options]

Options:
  -h, --help            show this help message and exit
  -f DOMAINDICT, --dict=DOMAINDICT
                        subdomian dict path
  -d DOMAIN, --domain=DOMAIN
                        single target domain
  --domain-list=DOMAIN_LIST
                        Multiple target domain list
  --enable              scan third-level domain names

    """
    parser = optparse.OptionParser()
    parser.add_option("-f", "--dict", dest="domainDict", help="subdomian dict path")
    parser.add_option("-d", "--domain", dest="domain", help="single target domain")
    parser.add_option("--domain-list", dest="domain_list", help="Multiple target domain list")
    parser.add_option("--enable", dest="enable", action="store_true", default=False,
                      help="scan third-level domain names")
    options, args = parser.parse_args()
    domainDict = options.domainDict
    domain = options.domain
    domain_list = options.domain_list
    enable = options.enable
    if not domain and not domain_list:
        print("No target specofied!!!")
        print(helps)
        exit(1)

    if not domainDict:
        print("No file path specified!!!")
        print(helps)
        exit(1)
    if domain_list:
        domains = [x.strip() for x in domain_list.split(",")]
    else:
        domains.append(domain.strip())
    with open(domainDict, "r") as f:
        subdomain_list = [x.strip("\n") for x in f.readlines()]

    print("Start scanning......")
    start_brute(domains, subdomain_list, enable)


if __name__ == '__main__':
    main()

from BGPtopology import BGPtopology
from Rgraph import *
from create_Rgraph_from_Topo import *
import pytricia
# import pickle
import time
import random
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sys



class Simulation():

    def __init__(self):
        
        print('Loading topology...')
        self.topo = BGPtopology()
        AS_relationship_dataset = './BGPdata/20160901.as-rel2.txt' # an AS topology with the format provided by the CAIDA AS-relationships dataset http://www.caida.org/data/as-relationships/
        self.topo.load_topology_from_csv(AS_relationship_dataset)

        self.attackers = list()
        self.victims   = list()

        self.attackers.extend([7315, 45899, 22085, 4230, 4812, 2816, 58517, 4809, 
        27699, 56723, 9121, 33717, 17715, 18403, 4766, 9760, 3825, 9768, 24086, 7552])

        # victims used for non-anycast experiments
        self.victims.extend([37410, 45620, 20940, 44521])

        #victim used for anycast
        # self.victims.extend([20940])

        # list with original mirai IP addresses
        self.mirai_ip_dataset = list()

        self.all_nodes_ASNs = self.topo.get_all_nodes_ASNs()

        # Filter ASes that do not exist in Topology
        for x in self.attackers:
            if not self.topo.get_node(x):
                self.attackers.remove(x)
        for x in self.victims:
            if not self.topo.get_node(x):
                self.victims.remove(x)

        # data structure used for plotting that keeps information regarding the results of the analysis 
        self.results = {"anycast": 0, "bogon": 0, "cones": 0, 
        "no_bbx_length": list(), 
        "anycast_paths_ratio": list(), "bogon_paths_ratio": list(), "cones_paths_ratio": list(),
        "anycast_paths_length": list(), "bogon_paths_length": list(), "cones_paths_length": list(),
        }

        # Import prefixes and announce what's necesary to Topology
        self.import_prefixes()

        # Initialize methods and techniques
        self.init_blackboxes()

    # Import prefixes from prefix2as dataset corresponding to as_paths towards the victims
    def import_prefixes(self):
        print('Importing prefixes...')    

        pf2as = open("./BGPdata/routeviews-rv2-20160901-1800.pfx2as", "r")

        victims_to_import = list()
        for x in self.victims:
            victims_to_import.append(x)

        all_nodes = list()
        for x in self.all_nodes_ASNs:
            all_nodes.append(x)
        
        for line in pf2as:
            try:
                AS_set = str(line.split()[2])
                prefix = str(line.split()[0]) + "/" + str(line.split()[1])
                for AS in AS_set.split("_"):
                    self.topo.get_node(int(AS)).prefix_trie.insert(prefix, prefix)
                    if int(AS) in victims_to_import:
                        self.topo.add_prefix(int(AS), prefix)
                        victims_to_import.remove(int(AS))
            except:
                pass
        pf2as.close()
        
        try:
            mirai_ip_dataset = open("./mirai_ip_data/2016-09-01", "r")
            for line in mirai_ip_dataset:
                self.mirai_ip_dataset.append(line.rstrip("\n"))
        except Exception as e:
            print ("Couldn't open mirai_ip_data ")
            print (e)

    # init the different methods and techniques 
    def init_blackboxes(self):
        self.init_acl()
        self.init_spoofer()
        self.init_catchment()

    # init ACL's that correspond to bogon addresses
    def init_acl(self):
        self.bogonList = pytricia.PyTricia()
        
        # create the bogonList
        try:
            f = open("./BGPdata/fullbogons-ipv4.txt", "r")
            for line in f:
                if "#" in line:
                    continue
                prefix = line.rstrip("\n")
                self.bogonList.insert(prefix, prefix)

        except Exception as e:
            print ("Couldn't open fullbogons-ipv4.txt")
            print (e)
    
    # init Customer Cones 
    def init_spoofer(self):
        
        # open ppdc file
        ppdc_ases_dataset = './BGPdata/20160901.ppdc-ases.txt' # an AS topology with the format provided by the CAIDA AS-relationships dataset http://www.caida.org/data/as-relationships/
        
        # spoofer = ['ASX' : list( AS1, AS2, AS3)]
        # ASX's cone contains AS1, AS2, AS3
        self.spoofer = dict()
        try:
            with open(ppdc_ases_dataset, 'r') as ppdc_ases:
                for cone in ppdc_ases:
                    if cone[0] is not "#":
                        ases = cone.split()
                        AS_number = int(ases[0])
                        self.spoofer[ases[0]] = list()
                        for x in ases[1:]:
                            self.spoofer[ases[0]].append(x)

        except Exception as e:
            print ("Couldn't open ppdc-ases.txt")
            print (e)

    # init anycast inference method
    def init_catchment(self):
        
        shortest_path_preference = True # boolean. I.e., to use (True) or not (False) Algorithm 5 from [1]

        prefix = "204.188.136.0/21"
        self.anycasters = list()
        self.anycasters.extend([20940, 1273])

        for AS in self.anycasters:
            self.topo.add_prefix(AS, prefix)
        
        print('Creating Rgraph...') 
        self.Graph = create_Rgraph_from_Topo(self.topo, prefix, shortest_path_preference=shortest_path_preference)
        
        print('Probabilistic coloring...')
        self.Graph.set_probabilistic_coloring(self.anycasters)  # i.e., Algorithms 2 and 3 from [1]
        

    def analysis(self):
        self.num_of_attacks = 10000
        counter = self.num_of_attacks

        while (counter > 0):

            # used for different victims
            victim = self.victims.pop(random.randint(0,2))
            
            # used for anycast
            # victim = self.victims.pop()
         
            self.victims.append(victim)
           
            self.attack(self.attackers, victim)
            counter -= 1


    def attack(self, attackers, victim):
        # print ("Attacker = {0}, Victim = {1}, as_path = {2}".format(attacker, victim, self.topo.get_node(attacker).paths))

        # generate traffic from IP distribution
        traffic = self.generate_attack_traffic()

        # get IP address from traffic distribution
        source_ip = self.generate_ip(traffic)

        # get IP address  from mirai IP dataset
        # source_ip = random.choice(self.mirai_ip_dataset)

        for attacker in attackers:
            
            # as_path from attacker to victim
            path = self.get_reachability(attacker, victim)

            # Log the length of as_path
            path_length = len(path)
            
            # flag that indicates which blackbox stopped the attack
            flag = 0
            
            # var that iterates through AS_path in order to check on cones
            temp_attacker = attacker

            # print ("Attacker = {0}, victim = {1}, path = {2}".format(attacker, victim, path))
            for AS in path:
                defended = True
                path_length -= 1
                
                # attacker would never route there because of certain anycast inferrence
                if victim in self.anycasters:
                    # print ("attacker = " + str(attacker))
                    # print ("self.Graph.get_color(attacker)" + str(self.Graph.get_color(attacker)))
                    if victim not in self.Graph.get_color(attacker):
                        flag = 2
                        break
                
                # IP is bogon
                if source_ip in self.bogonList:
                    flag = 1
                    break

                # # based on as_path, check if exists in customer cone of transit AS
                elif str(temp_attacker) in self.spoofer[str(AS)]:
                    flag = 3
                    break
        
                else:
                    defended = False
                temp_attacker = AS

            if (defended):
                self.calculate_metrics(flag, path_length, len(path))


    # return as_path from attacker to victim
    def get_reachability(self, attacker, victim):

        paths = self.topo.get_node(attacker).paths
        for prefix, path in paths.items():
            if path[-1] == victim:
                return path


    # generate an ip from traffic distribution
    def generate_ip(self, traffic):

        source_ip = str(random.choice(traffic))
        temp = random.randint(1,3)
        for i in range(3):
            source_ip = source_ip + "."
            for x in range(temp):
                source_ip = source_ip + str(random.randint(0,9))
        return source_ip

    # generate attack traffic distribution
    def generate_attack_traffic(self):
        
        traffic = list()
        for i in range(1,4):
            for x in range(1,64):
                traffic.append(x)
            for x in range(127,175):
                traffic.append(x)
            for x in range(90,126):
                traffic.append(x)
        return traffic



    # calculate metrics 
    def calculate_metrics(self, flag, path_length, original_path_length):
        
        self.results["no_bbx_length"].append(original_path_length)

        if flag == 1:
            self.results["bogon"] += 1
            self.results["bogon_paths_ratio"].append(path_length/float(original_path_length))
            self.results["bogon_paths_length"].append(path_length)

            # fill the rest of the values with NaN
            self.results["anycast_paths_ratio"].append(np.nan)
            self.results["anycast_paths_length"].append(np.nan)
            self.results["cones_paths_ratio"].append(np.nan)
            self.results["cones_paths_length"].append(np.nan)

            
        elif flag == 2:
            self.results["anycast"] += 1
            self.results["anycast_paths_ratio"].append(path_length/float(original_path_length))
            self.results["anycast_paths_length"].append(path_length)

            # fill the rest of the values with NaN
            self.results["bogon_paths_ratio"].append(np.nan)
            self.results["bogon_paths_length"].append(np.nan)
            self.results["cones_paths_ratio"].append(np.nan)
            self.results["cones_paths_length"].append(np.nan)


        elif flag == 3:
            self.results["cones"] += 1
            self.results["cones_paths_ratio"].append(path_length/float(original_path_length))
            self.results["cones_paths_length"].append(path_length)
           
            # fill the rest of the values with NaN
            self.results["bogon_paths_ratio"].append(np.nan)
            self.results["bogon_paths_length"].append(np.nan)
            self.results["anycast_paths_ratio"].append(np.nan)
            self.results["anycast_paths_length"].append(np.nan)


    def plot(self):
        self.plot_succ_attacks()
        self.plot_succ_attacks_anycast()
        self.plot_ratio_of_path_lengths()
        self.plot_histograms()
    
    def plot_succ_attacks(self):

        blackboxes = ["bogon", "cones"]
        number_of_attacks = [self.results["bogon"], self.results["cones"]]
        print ("number of bogon ")
        print (self.results['bogon'])
        y_pos = np.arange(len(number_of_attacks))
        plt.title("Attacks Defended out of " + str(self.num_of_attacks * len(self.attackers)))
        plt.xlabel("Methods")
        plt.ylabel("# of attacks")

        plt.bar(y_pos, number_of_attacks)
        plt.xticks(y_pos, blackboxes)
        plt.show()

    def plot_succ_attacks_anycast(self):

        blackboxes = ["bogon", "anycast", "cones"]
        number_of_attacks = [self.results["bogon"], self.results["anycast"], self.results["cones"]]
        y_pos = np.arange(len(number_of_attacks))
        plt.title("Attacks Defended out of " + str(self.num_of_attacks * len(self.attackers)))
        plt.xlabel("Methods")
        plt.ylabel("# of attacks")

        plt.bar(y_pos, number_of_attacks)
        plt.xticks(y_pos, blackboxes)
        plt.show()
    
    def plot_ratio_of_path_lengths(self):

        # Plot Paths Length including anycast
        data_length_anycast = {"Original" : self.results["no_bbx_length"],
                "Bogon" : self.results["bogon_paths_length"],
                "Cones" : self.results["cones_paths_length"],
                "Anycast" : self.results["anycast_paths_length"]
        }

        # Boxplot
        medianprops = dict(linestyle='-', linewidth=2, color='blue')
        df2 = pd.DataFrame(data_length_anycast)
        boxplot2 = df2.boxplot(medianprops=medianprops)
        plt.title("Paths Length")
        plt.xlabel("Methods")
        plt.ylabel("Number of Hops") 
        plt.yticks(np.arange(0,5,1))
        plt.show(boxplot2)


    def plot_histograms(self):

        x = self.results['bogon_paths_length']
        plt.title("Bogon")
        plt.xlabel("Path Length")
        plt.ylabel("Count")  
        plt.hist(x, bins=3, range=(1,3))
        plt.show()

        y = self.results['cones_paths_length']
        plt.title("Cones")
        plt.xlabel("Path Length")
        plt.ylabel("Count")  
        plt.hist(y, cumulative=True, label='CDF', histtype= 'bar', alpha=0.8, color='k')
        plt.show()



# Init Simulation 
simulation = Simulation()

# run the analysis
simulation.analysis()

# plot
simulation.plot()


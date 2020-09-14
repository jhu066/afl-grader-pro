#!/home/cju/pypy3.6-v7.3.1-linux64/bin/pypy3

import concurrent.futures
import urllib.request
import subprocess
import time
import queue as Q
import os
import glob 
import itertools
import shutil
import _thread
import threading
from functools import total_ordering
#$from depq import DEPQ
import time

#FIFO='/tmp/wp'
pq = Q.PriorityQueue()
#pq = DEPQ()
out_pq = Q.PriorityQueue()
#out_pq = DEPQ()
outindex = itertools.count()
path_index = 0
edge_index = 0
#fifo = open(FIFO,'w')
padding = "A"*512;

class CETask(object):
    def __init__(self,category,idx,score,path):
        self.category = category  #AFL=0 #EQ=1 #PQ=2
        self.idx = idx
        self.score = score
        self.path = path
    def __lt__(self,other):
        if (self.category < other.category):  # AFL > EQ > PQ
            return True
        elif (self.category > other.category):
            return False
        elif (self.category == 0 and self.idx < other.idx): # AFL ordered by name
            return True
        elif (self.score > other.score): # other orders by score
            return True
    def __str__(self):
        return "category: "+str(self.category) + " idx: " + str(self.idx) + " score: " + str(self.score) + " " + self.path

# Retrieve a single page and report the URL and contents
@total_ordering
class OutTask(object):
	def __init__(self,category,idx,score,out_idx):
		self.category = category  #AFL=0 #EQ=1 #PQ=2
		self.idx = idx
		self.score = score
		self.out_idx = out_idx
	def __lt__(self,other):
		if (self.category ==0 and other.category!=0):  # AFL > EQ > PQ
			return True
		elif (self.category == 0 and self.idx < other.idx): # AFL ordered by name
			return True
		elif (self.score > other.score): # other orders by score
            		return True
	def __eq__(self,other):
		return (self.category == other.category) and (self.id==other.id)
	def __str__(self):
		return "category: "+str(self.category) + " idx: " + str(self.idx);


def process_task(taskitem,process_id):
	task = taskitem.path
	index = next(outindex)
	category = taskitem.category
	idx = taskitem.idx
	score = taskitem.score
	print ("@"+str(process_id)+" processing "+task + " score "+str(score))
	output_dir = os.getcwd()+'/'+'size_src/kirenenko-out-'+str(index)+'/queue'
	if not os.path.exists(output_dir):
		os.makedirs(output_dir)
	program_path = os.getcwd() + '/size_pp '
	ceCmd = 'TAINT_OPTIONS="taint_file=' + task
	ceCmd = ceCmd + ' output_dir=' + output_dir + '" '
	ceCmd = ceCmd + ' timeout 1s '+program_path + task
	#print(ceCmd)
	try:
		output = subprocess.call([ceCmd], shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
	except subprocess.CalledProcessError:
		print ("something goes wrong, but continue")
	#print("push to out pq")
	#out_pq.put(OutTask(category,idx,score,index))
	#if (out_pq.qsize()>16):
	#	while not out_pq.empty():
			#outitem = out_pq.first()
#			fifo.write(str(out_pq.get().out_idx)+","+padding+"\n")
#			fifo.flush()
			#out_pq.popfirst()

def try_insert(task, priority):
	pq.insert(task,priority)
	#if not pq.is_empty() and pq.size()>20000:
		## add if we are better
#		if priority > pq.low():
#			pq.poplast()
#			pq.insert(task,priority)
#			print("replacing with insert "+task.path)
#	else:
#		pq.insert(task,priority)
	print("insert "+task.path)


def syncAfl(afl_index):
	dest_dir = os.getcwd()+"/size_dst/fuzzer1/queue/"
	count = 0
	while (True):
		has_new=False
		cur="id:"+str(afl_index+count).zfill(6)
		for item in glob.glob(dest_dir+cur+"*"):
			has_new=True
			count=count+1
			task = CETask(0,afl_index+count,0.0,item)
				#tpq.insert(task,100000-(afl_index+count))
			#try_insert(task,100000-(afl_index+count))
			pq.put(task)
			#process_task(task)
		if not has_new:
			break
	return count

def syncEdge(edge_file_position):
	edge_rare_path = os.getcwd()+"/size_dst/MQfilter/edge_rare"
	edge_queue_path = os.getcwd() + '/size_dst/MQfilter/queue/' 
	edge_crash_path = os.getcwd() + '/size_dst/MQfilter/crashes/' 
#scan edge queue
	count=0
	if (os.path.exists(edge_rare_path)):
			edge_rare_file = open(edge_rare_path,"r")
			edge_rare_file.seek(edge_file_position)
			for line in edge_rare_file.readlines():
					lineitems = line.split(',')
					if (len(lineitems)!=3):
							continue 
					path = ''
					if (lineitems[2] == 'eq\n'):
							path = edge_queue_path + lineitems[1]
					elif (lineitems[2] == 'ec\n'):
							path = edge_creash_path + lineitems[1]
					print(path)
					task = CETask(1,0,float(lineitems[0]),path)
					#print(path)
					#tpq.insert(task,float(lineitems[0]))
					#try_insert(task,float(lineitems[0]))
					pq.put(task)
					count=count+1
			edge_file_position=edge_rare_file.tell()
			edge_rare_file.close()	
	return edge_file_position

def syncPath(path_file_position):
	#scan path queue
	path_rare_path = os.getcwd()+"/size_dst/MQfilter/path_rare"
	path_queue_path = os.getcwd() + '/size_dst/MQfilter-path/_queue/' 
	path_crash_path = os.getcwd() + '/size_dst/MQfilter-path/_crashes/' 
	count=0
	if (os.path.exists(path_rare_path)):
			has_new_line=False
			path_rare_file = open(path_rare_path,"r")
			path_rare_file.seek(path_file_position)
			for line in path_rare_file.readlines():
					lineitems = line.split(',')
					if (len(lineitems)!=3):
							continue 
					path = ''
					if (lineitems[2] == 'pq\n'):
							path = path_queue_path + lineitems[1]
					elif (lineitems[2] == 'pc\n'):
							path = path_crash_path + lineitems[1]
					task = CETask(2,0,float(lineitems[0]),path)
					pq.put(task)
					#ktry_insert(task,float(lineitems[0]))
					has_new_line=True
					count=count+1
					#print(path)
			path_file_position=path_rare_file.tell()
			path_rare_file.close()	
	return path_file_position


	
def process(process_id):
	while True:
		if not pq.empty():
			print("PQ items total "+str(pq.qsize()))
			process_task(pq.get(),process_id)
			


def main():
	executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)

	#executor.submit(writer,1)
	executor.submit(process,1)
	#_thread.start_new_thread( process, () )
	#x = threading.Thread(target=process, args=(1,))
	#x.start()
	#y = threading.Thread(target=writer, args=(1,))
	#y.start()
	afl_index = 0
	edge_file_position = 0
	path_file_position = 0
	while True:
		afl_index += syncAfl(afl_index)
		#if (inc!=0):
			#afl_index = afl_index + inc
			#print("afl_index updated to "+str(afl_index))
		edge_file_position = syncEdge(edge_file_position)
		path_file_position = syncPath(path_file_position)
		#time.sleep(1)  
		#print("tpq size is "+str(tpq.size()))
		#while (pq.is_empty() or ((not tpq.is_empty()) and tpq.high() > pq.low())):
		#	pq.insert(tpq.first(),tpq.high())
		#	tpq.popfirst()
		#if (edge_file_position!=last_e or path_file_position!=last_p):
			#last_e = edge_file_position
			#last_p = path_file_position
			#print("edge path position updated to "+str(edge_file_position)+","+str(path_file_position))
	#_thread.start_new_thread( graderScan, () )
	print("start rolling")

	while True:
		pass	
		
		
if __name__ == "__main__":
	main()


import os
import angr
import subprocess
import random
import string
import signal
import logging

class Fuzzer:
	def __init__(self, binary, run_format, max_len=10000, cur_len=5, inc_fac=4):
		self.binary = binary
		self.max_len = max_len
		self.cur_len = cur_len
		self.inc_fac = inc_fac
		self.run_format = run_format
		self.return_code = 0
		self.crashed = False
		self.crash_input = None
		self.logger = logging.getLogger("Fuzzer")
	
	def fuzz(self):
		letters = string.printable
		rand_inp = [random.choice(letters) for i in range(self.cur_len)]
		fuzzy_input = "".join(rand_inp)+"\n"

		bin_process = None
		run_format = [0]*len(self.run_format)

		if "stdin" in self.run_format:
			bin_process = subprocess.run([self.binary], input=fuzzy_input.encode(), capture_output = True)
		else:
			for i in range(len(self.run_format)):
				if self.run_format[i] == "@":
					run_format[i] = fuzzy_input
				else:
					run_format[i] = self.run_format[i]
			bin_process = subprocess.run(run_format, capture_output=True)

		self.return_code = bin_process.returncode
		if self.return_code == -signal.SIGSEGV:
			self.logger.setLevel(logging.INFO)
			self.logger.info("Binary received SIGSEGV (Crashed)")
			self.crashed = True
			self.crash_input = fuzzy_input
		self.cur_len += self.inc_fac

	def run_fuzzer(self):
		self.logger.setLevel(logging.INFO)
		self.logger.info("Fuzzing the binary :"+self.binary)
		
		while self.max_len > self.cur_len and not self.crashed :
			self.fuzz()
		return self.crash_input
	
	def get_crash_input(self):
		return self.crash_input

	def is_crashed(self):
		return self.crashed

	def set_inc_fact(self, fact):
		self.inc_fac = fact

	def set_max_len(self, mlen):
		self.max_len = mlen

if __name__ == '__main__':
	f = Fuzzer("../examples/vuln", ["../examples/vuln", "@"])
	print(len(f.run_fuzzer()))


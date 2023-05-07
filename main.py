import argparse
import json
import logging

from arbiterx.ArbiterX import ArbiterX

logging.basicConfig()
logging.root.setLevel(logging.INFO)

log = logging.getLogger(__name__)

def is_valid_file(filename):
	try:
		file = open(filename, 'r')
		return True
	except Exception as e:
   		log.error("Error:", e)
   		exit(1)

def main():
	parser = argparse.ArgumentParser()

	parser.add_argument("-f", "--file", help="File to exploit")
	parser.add_argument("-t", "--template", help="Template file path")

	args = parser.parse_args()

	binary = args.file
	template = args.template
		
	if not is_valid_file(binary) or not is_valid_file(template):
		exit(1)

	arbx = ArbiterX(binary, template)
	arbx.resolve_sources()
	arbx.resolve_sinks()

	if not arbx.check_reachability():
		print("given source and sink are not reachable..", "Sources :", arbx.get_sources(), "Sinks :", arbx.get_sinks())
		exit(0)
	else:
		arbx.fuzz_binary()
		arbx.analyze_crash()
		arbx.generate_exploit("payload.exp")


if __name__ == '__main__':
	main()

# ArbiterX : Automated Exploit Generation Tool Based on Arbiter Source and Sink Model
An automated exploit generation tool based on arbiters source and sink model.

Block DIagram of the Tool:

![framework(1)](https://user-images.githubusercontent.com/30689856/236703541-6d043c1b-ab3b-4932-9cfe-6687bca45b70.png)

## Usage:
``` 
git clone https://github.com/maheshgm/arbiterX 
cd arbiterX/
python main.py -f vuln.elf -t template.json

```
## Format of the Template:

```
{
  run_format : ["binary_name", <stdin or @ for command line arguments>],
  sources: [<list of sources functions use main as default>],
  sinks : [<list of target functions to check reachability>],
  exec : "function to call using the vulnerability",
}
```
Look at the example template for better understanding.

## What it can do currently:
ArbiterX can find and generate an exploit for buffer overflows. The exploit generated will execute the target function present in the binary. With minor modification to the code can get a shell also (return to libc Attack).

## Example:

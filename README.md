# u2parser
Unified2 Log (Snort) Parser

Author: Diego Fernandez

This tool is a class which allow reads unified2 logs, parse it, and returns the records as list of dictionaries.

## Installation

```bash
pip install u2parser
```

## Usage

```python
import u2parser

u2 = u2parser.u2(path_to_file)

for record in u2.parse():
	print record
```


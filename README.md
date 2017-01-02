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
from u2parser.u2parser import u2

u2 = u2(path_to_log, sid_file = '/etc/snort/sid-msg.map')

for record in u2.parse():
	print record
```


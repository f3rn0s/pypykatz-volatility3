# pypykatz-volatility3
Updated pypykatz plugin for volatility3 framework.

`vol_pypykatz` dumps the full output.
`vol_shortkatz` dumps just NT and LM hashes.

```bash
$ vol -p "$(pwd)/pypykatz-volatility3" -f memory.vmem vol_pypykatz
$ vol -p "$(pwd)/pypykatz-volatility3" -f memory.vmem vol_shortkatz
```

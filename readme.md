# SpaceJA3

Builds a vtable in osquery for ja3/s handshakes on the system.
Looks like this:

<img width="998" alt="table output" src="https://github.com/zmackie/spaceja3/assets/5925347/5004d250-cfc4-4d22-b462-9d3f60b720a3">



# runnning

```shell
sudo osqueryi --nodisable_extensions
osquery> select value from osquery_flags where name = 'extensions_socket';

# seperate terminal window
sudo ./spaceja3 --socket /home/name/.osquery/shell.em (--debug)

```

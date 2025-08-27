## Verifiable Index: CT

This is a demo of pulling the contents of a tile-based CT log into a [Verifiable Index](../../README.md).

[tlog-tiles]: https://c2sp.org/tlog-tiles
[Tessera]: https://github.com/transparency-dev/tessera

The CT Input Log is processed, with each entry being indexed on all common names defined in the cert. 
This allows the owner of a domain to look up all certs for their domain, in a way that is fully verified.

## Running

The Input Log is expected to be available at a URL provided by the `--static_ct_log_url` flag.
The Verifiable Index and Output Log are constructed locally, persisted to local disk (in the `--storage_dir` directory), and hosted via a web server.

```shell
export INPUT_LOG=https://tuscolo2025h2.skylight.geomys.org/
export INPUT_LOG_PK=  TODO(mhutchinson): how to do this

OUTPUT_LOG_PRIVATE_KEY=PRIVATE+KEY+example.com/outputlog+07392c46+ATPJ4crkyUbPeaRffN/4NUof3KV0pQznVIPGOQm3SDEJ go run ./vindex/cmd/ct --storage_dir ~/vindex-ct/
```

Running the above will run a web server hosting the following URLs:
 - `/vindex/lookup` - the provisional [vindex lookup API](./api/api.go)
 - `/outputlog/` - the [tlog-tiles][] base URL for the output log

To inspect the log, you can use the woodpecker tool (using the corresponding public key to the private key used above):

```shell
# To inspect the Output Log
go run github.com/mhutchinson/woodpecker@main --custom_log_type=tiles --custom_log_url=http://localhost:8088/outputlog/ --custom_log_vkey=example.com/outputlog+07392c46+AWyS8y8ZsRmQnTr6Fr2knaa8+t6CPYFh5Ho3wJEr14B8
```

Use left/right cursor to browse, and `q` to quit.

A domain indexed by the verifiable map can be looked up using the following command:

```shell
go run ./vindex/cmd/client --vindex_base_url http://localhost:8088/vindex/ --in_log_base_url http://localhost:8088/inputlog/ --out_log_pub_key=example.com/outputlog+07392c46+AWyS8y8ZsRmQnTr6Fr2knaa8+t6CPYFh5Ho3wJEr14B8 --in_log_pub_key=example.com/inputlog+bd6268fb+AWdGkrHKBm+pOubTrcBTV8JMDLFlF1Y8WUH1nrtLNXDr --lookup=foo
```

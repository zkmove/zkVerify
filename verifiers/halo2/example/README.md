Below script is used to run the example Move package, to generate the trace.

Make sure you have a customized version of the Move CLI installed:

```shell
cargo install --git https://github.com/zkmove/aptos-core move-cli --branch witnessing
```
Build and publish the example package. Then generate the witness while executing the example. By default, the witness will be generated in a directory called `witnesses`.
```shell
move build --skip-fetch-latest-git-deps
move sandbox publish --skip-fetch-latest-git-deps --ignore-breaking-changes
move sandbox run --skip-fetch-latest-git-deps --witness storage/0x0000000000000000000000000000000000000000000000000000000000000001/modules/fibonacci.mv test_fibonacci --args 10u64
```
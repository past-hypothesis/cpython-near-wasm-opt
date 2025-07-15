CPython-NEAR WASM optimizer tool

Allows packaging arbitray Python modules together with the contract source files into a self-contained WASM file ready for
running on the NEAR blockchain.

Inputs:
  python.wasm -- pre-compiled CPython-NEAR WASM
  python-stdlib.zip -- pre-compiled CPython-NEAR stdlib .pyc files
  lib/ -- directory with contract source files and arbitrary Python modules to package into the WASM file
  
Optimizations:
  Optimizer runs the supplied contract with default arguments (or ones specified via @near.optimizer_inputs() decorator) and traces
  which Python modules and WASM functions get loaded/called during the runtime, removing unreferenced ones according to the 
  optimization settings specified via -Ox, --module-tracing=1/0, --function-tracing=off/safe/aggressive cmdline arguments.
  
  --function-tracing=safe (-O2 and lower) tries to only remove WASM functions which belong to non-referenced builtin Python modules, 
  which is safer than --function-tracing=aggressive (-O3 and higher), which removes all unreferenced WASM functions except those pinned 
  via DEFAULT_PINNED_FUNCTIONS or --pinned-functions=<name1>,<name2>,...
  
  Optimized out WASM functions are replaced with a panic handler, which will, in case such a function has still been called during 
  the contract runtime, print a message including the missing function name, which then can be added to the pinned function name list
  to ensure it is retained.
  
  Additionally, LZ4 compression can be applied to WASM data initializer, which allows up to 500KiB WASM size reduction while consuming
  ~20Tgas for decompression.
  
  Typical WASM sizes after optimization with json module included (-O4/3/2): 530/560/1363KiB.
  

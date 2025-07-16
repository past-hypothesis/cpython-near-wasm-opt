"""CPython-NEAR WASM optimizer tool

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
  
  Typical WASM sizes after optimization with json module included (-O4/3/2): 530/560/1363KiB
"""

from pathlib import Path
import argparse
from .core import optimize_wasm_file, BINARY_PATH, LIB_PATH

def resolve_defaults(args):
    # defaults by optimization level: [module_tracing, function_tracing, compression, debug_info]
    defaults = {0: [False, 'off', False, True], 
                1: [True, 'off', True, True], 
                2: [True, 'safe', True, True], 
                3: [True, 'aggressive', True, True],
                4: [True, 'aggressive', True, False]}[args.opt_level]

    args.module_tracing = defaults[0] if args.module_tracing is None else args.module_tracing
    args.function_tracing = args.function_tracing or defaults[1]
    args.compression = defaults[2] if args.compression is None else args.compression
    args.debug_info = defaults[3] if args.debug_info is None else args.debug_info

    return args
    
def main():
    parser = argparse.ArgumentParser(description=__doc__.strip(), formatter_class=argparse.RawDescriptionHelpFormatter)
    
    parser.add_argument('build_dir', nargs='?', default='build', help='Build directory (default: build)')
    parser.add_argument('-i', '--input-file', default=LIB_PATH / 'python.wasm', help='Input WASM file name (default: embedded python.wasm)')
    parser.add_argument('-o', '--output-file', default='python-optimized.wasm', help='Output WASM file name (default: python-optimized.wasm)')
    parser.add_argument('-l', '--user-lib-dir', default='lib', help='User Python library directory (default: lib)')
    parser.add_argument('--python-stdlib-zip', default=LIB_PATH / 'python-stdlib.zip', help='Python standard library zip (default: embedded python-stdlib.zip)')
    parser.add_argument('-O', '--opt-level', type=int, default=3, choices=[0,1,2,3,4], help='Optimization level 0-4 (default: 3)')
    
    def bool_arg(v):
        if isinstance(v, str):
            return v.lower() in ['1', 'true', 'yes', 'on']
        return bool(v)
    
    parser.add_argument('--module-tracing', type=bool_arg, help='Enable Python module tracing (1/0)')
    parser.add_argument('--function-tracing', choices=['off','safe','aggressive'], help='Function tracing mode')
    parser.add_argument('--compression', type=bool_arg, help='Enable WASM data initializer compression (1/0)')
    parser.add_argument('--debug-info', type=bool_arg, help='Include WASM debug information (1/0)')
    parser.add_argument('--verify-optimized-wasm', type=bool_arg, default=True, help='Run/verify optimized WASM after building (1/0)')    
    parser.add_argument('-p', '--pinned-functions', help='Comma-separated list of function names to pin (case-sensitive)')
    parser.add_argument('-e', '--exports', help='Comma-separated list of function names to be exported from the WASM (will be auto-detected via @near.export search if omitted)')
        
    args = resolve_defaults(parser.parse_args())
    args.pinned_functions = [f.strip() for f in (args.pinned_functions or '').split(',') if f.strip()]
    args.exports = [f.strip() for f in (args.exports or '').split(',') if f.strip()]
    
    optimize_wasm_file(args.build_dir, args.input_file, args.output_file, module_opt=args.module_tracing, 
                       function_opt=args.function_tracing, compression=args.compression, debug_info=args.debug_info,
                       pinned_functions=args.pinned_functions, user_lib_dir=args.user_lib_dir, stdlib_zip=args.python_stdlib_zip,
                       contract_exports=args.exports, verify_optimized_wasm=args.verify_optimized_wasm)

if __name__ == "__main__":
    main()

import ast
import json
import platform
import shutil
import struct
import subprocess
import sys
import zipfile
from collections import defaultdict
from copy import deepcopy
from pathlib import Path

import lz4.frame
import wasmtime

from .defaults import (
    BUILTIN_MODULE_FUNCTION_NAME_PREFIXES,
    DEFAULT_PINNED_FUNCTIONS,
    SAFE_PINNED_FUNCTIONS,
    SAFELY_REMOVABLE_FUNCTION_NAME_PREFIXES,
    SAFELY_REMOVABLE_FUNCTION_NAME_SUFFIXES,
)

BINARY_PATH = Path(__file__).parent / "bin"
LIB_PATH = Path(__file__).parent / "lib"
CONTRACT_MODULE_PREFIX = "__near_contract__"


_LPAREN = object()
_RPAREN = object()


def tokenize_sexp(s):
    tokens = []
    current_atom = []
    in_atom = False
    in_string = False
    in_comment = False
    i = 0
    n = len(s)

    while i < n:
        char = s[i]
        if in_string:
            if char == "\\":
                # Handle escape sequences, preserving them as-is except for \" and \\
                if i + 1 >= n:
                    raise ValueError("Unclosed escape sequence at end of string")
                next_char = s[i + 1]
                if next_char in ('"', "\\"):
                    # Preserve the escape sequence as-is (e.g., \" becomes \", \\ becomes \\)
                    current_atom.append(char + next_char)
                    i += 2
                else:
                    # Preserve the backslash and next character (e.g., \n becomes \n)
                    current_atom.append(char)
                    current_atom.append(next_char)
                    i += 2
            elif char == '"':
                # End of string, add the collected content as a single token
                tokens.append('"' + ("".join(current_atom)) + '"')
                current_atom = []
                in_string = False
                i += 1
            else:
                current_atom.append(char)
                i += 1
        elif in_comment:
            if char == "\n":
                in_comment = False
            i += 1
        else:
            if char == '"':
                # Start of string
                in_string = True
                current_atom = []
                i += 1
            elif char.isspace():
                if in_atom:
                    tokens.append("".join(current_atom))
                    current_atom = []
                    in_atom = False
                i += 1
            elif char in "()":
                if in_atom:
                    tokens.append("".join(current_atom))
                    current_atom = []
                    in_atom = False
                tokens.append(_LPAREN if char == "(" else _RPAREN)
                i += 1
            elif char == ";":
                in_comment = True
                i += 1
            else:
                in_atom = True
                current_atom.append(char)
                i += 1
    if in_string:
        raise ValueError("Unclosed string")
    if current_atom:
        tokens.append("".join(current_atom))
    return tokens


def parse_sexp(tokens) -> list:
    stack = []
    root = []
    for token in tokens:
        if token is _LPAREN:
            new_list = []
            if stack:
                stack[-1].append(new_list)
            else:
                root = new_list
            stack.append(new_list)
        elif token is _RPAREN:
            if not stack:
                raise ValueError("Unexpected ')'")
            stack.pop()
        else:
            if not stack:
                raise ValueError("Atom outside of list")
            stack[-1].append(token)
    if stack:
        raise ValueError("Unclosed '('")
    return root


def read_sexp(filename) -> list:
    with open(filename, "r", encoding="ascii") as f:
        data = f.read()
    tokens = tokenize_sexp(data)
    return parse_sexp(tokens)


def write_sexp_to_string(expr):
    def helper(e):
        if isinstance(e, list):
            return "(" + " ".join(helper(child) for child in e) + ")"
        else:
            return str(e)

    return helper(expr)


def write_sexp(expr, filename):
    with open(filename, "w", encoding="ascii") as f:
        sexp_str = write_sexp_to_string(expr)
        f.write(sexp_str)


def fnv1a_32(data):
    hash_val = 0x811C9DC5  # FNV offset basis
    for byte in data.encode("ascii"):
        hash_val ^= byte
        hash_val = (hash_val * 0x01000193) & 0xFFFFFFFF  # FNV prime
    return hash_val & 0xFFFFFFFF


class WasmRunner:
    def __init__(self, wasm_bytes: bytes):
        self.wasm_bytes = wasm_bytes
        self.input_bytes = b""
        self.called_functions = set[int]()
        self.loaded_frozen_modules = set[str]()
        self.loaded_builtin_modules = set[str]()
        self.engine = wasmtime.Engine()
        self.store = wasmtime.Store(self.engine)
        self.module = wasmtime.Module(self.engine, self.wasm_bytes)
        self.memory = None
        imports = self.create_host_imports()
        self.linker = wasmtime.Linker(self.engine)
        for name, func in imports.items():
            self.linker.define(self.store, "env", name, func)
        self.reset()

    def reset(self):
        self.instance = self.linker.instantiate(self.store, self.module)
        self.memory = self.instance.exports(self.store)["memory"]

    def set_input_bytes(self, input_bytes: bytes):
        self.input_bytes = input_bytes

    def export(self, name):
        exported_func = self.instance.exports(self.store)[name]

        def exported_func_wrapper(*args):
            return exported_func(self.store, *args)

        return exported_func_wrapper

    def data_ptr(self):
        return self.memory.data_ptr(self.store)

    def create_host_imports(self) -> dict:
        # Auxilary functions which are not part of the NEAR API
        def c_str_from_ptr(ptr: int) -> str:
            chars = []
            data = self.memory.data_ptr(self.store)
            for i in range(ptr, ptr + 4096):
                if data[i] == 0:
                    break
                chars.append(data[i])
            return bytes(chars).decode()

        def bytes_from_ptr(ptr: int, length: int) -> bytes:
            data = self.memory.data_ptr(self.store)
            return bytes(data[ptr : ptr + length])

        def str_from_ptr(ptr: int, length: int) -> str:
            return bytes_from_ptr(ptr, length).decode()

        def trace_function_call(function_name_hash: int) -> None:
            self.called_functions.add(function_name_hash & 0xFFFFFFFF)

        def trace_frozen_module_load(module_path_ptr: int) -> None:
            module_path = c_str_from_ptr(module_path_ptr)
            self.loaded_frozen_modules.add(module_path)

        def trace_builtin_module_load(module_name_ptr: int) -> None:
            module_name = c_str_from_ptr(module_name_ptr)
            self.loaded_builtin_modules.add(module_name)

        # NEAR API impl
        registers = defaultdict(bytes)
        storage = defaultdict(bytes)

        # Registers
        def read_register(register_id: int, ptr: int) -> None:
            data_bytes = registers[register_id]
            data = self.memory.data_ptr(self.store)
            for i, byte in enumerate(data_bytes):
                data[ptr + i] = byte

        def register_len(register_id: int) -> int:
            return len(registers[register_id])

        def write_register(register_id: int, length: int, ptr: int) -> None:
            registers[register_id] = bytes_from_ptr(ptr, length)

        # Context API
        def current_account_id(register_id: int) -> None:
            registers[register_id] = b"wasm.optimizer"

        def signer_account_pk(register_id: int) -> None:
            registers[register_id] = b"wasm.optimizer_pk=="

        def signer_account_id(register_id: int) -> None:
            registers[register_id] = b"wasm.optimizer_signer"

        def predecessor_account_id(register_id: int) -> None:
            registers[register_id] = b"wasm.optimizer_predecessor"

        def input(register_id: int) -> None:
            registers[register_id] = self.input_bytes

        def block_index() -> int:
            return 200000000

        def block_timestamp() -> int:
            return 1700000000000000000

        def epoch_height() -> int:
            return 200000000

        def storage_usage() -> int:
            return 100000

        # Economics API
        def account_balance(register_id: int) -> None:
            registers[register_id] = (99800000000000000000000000).to_bytes(16, "little")

        def account_locked_balance(register_id: int) -> None:
            registers[register_id] = (100000000000000).to_bytes(16, "little")

        def attached_deposit(register_id: int) -> None:
            registers[register_id] = (100000000000000).to_bytes(16, "little")

        def prepaid_gas() -> int:
            return 300000000000000

        def used_gas() -> int:
            return 10000000000000

        # Math API
        def random_seed(register_id: int) -> None:
            registers[register_id] = (100000000000000000000000000).to_bytes(
                32, "little"
            )

        def sha256(length: int, ptr: int, register_id: int) -> None:
            pass

        def keccak256(value_len: int, value_ptr: int, register_id: int) -> None:
            pass

        def keccak512(value_len: int, value_ptr: int, register_id: int) -> None:
            pass

        def ripemd160(value_len: int, value_ptr: int, register_id: int) -> None:
            pass

        def ecrecover(
            hash_len: int,
            hash_ptr: int,
            sig_len: int,
            sig_ptr: int,
            v: int,
            malleability_flag: int,
            register_id: int,
        ) -> int:
            pass

        def ed25519_verify(
            sig_len: int,
            sig_ptr: int,
            msg_len: int,
            msg_ptr: int,
            pub_key_len: int,
            pub_key_ptr: int,
        ) -> int:
            pass

        # Miscellaneous API
        def value_return(value_len: int, value_ptr: int) -> None:
            print(
                f"value_return: {value_len} bytes: {bytes_from_ptr(value_ptr, value_len)}"
            )

        def panic() -> None:
            print(">>panic")

        def panic_utf8(length: int, ptr: int) -> None:
            print(f">>panic: {str_from_ptr(ptr, length)}")

        def log_utf8(length: int, ptr: int) -> None:
            msg = str_from_ptr(ptr, length).replace("\n", "\n>>")
            print(f">>{msg}")

        def log_utf16(length: int, ptr: int) -> None:
            print("log_utf16: not implemented")

        def abort(msg_ptr: int, filename_ptr: int, line: int, col: int) -> None:
            print(
                f"abort: {c_str_from_ptr(msg_ptr)} at {c_str_from_ptr(filename_ptr)}@{line}:{col}"
            )

        # Promises API
        def promise_create(
            account_id_len: int,
            account_id_ptr: int,
            function_name_len: int,
            function_name_ptr: int,
            arguments_len: int,
            arguments_ptr: int,
            amount_ptr: int,
            gas: int,
        ) -> int:
            return 0

        def promise_then(
            promise_index: int,
            account_id_len: int,
            account_id_ptr: int,
            function_name_len: int,
            function_name_ptr: int,
            arguments_len: int,
            arguments_ptr: int,
            amount_ptr: int,
            gas: int,
        ) -> int:
            return 0

        def promise_and(promise_idx_ptr: int, promise_idx_count: int) -> int:
            return 0

        def promise_batch_create(account_id_len: int, account_id_ptr: int) -> int:
            return 0

        def promise_batch_then(
            promise_index: int, account_id_len: int, account_id_ptr: int
        ) -> int:
            return 0

        # Promise API actions
        def promise_batch_action_create_account(promise_index: int) -> None:
            pass

        def promise_batch_action_deploy_contract(
            promise_index: int, code_len: int, code_ptr: int
        ) -> None:
            pass

        def promise_batch_action_function_call(
            promise_index: int,
            function_name_len: int,
            function_name_ptr: int,
            arguments_len: int,
            arguments_ptr: int,
            amount_ptr: int,
            gas: int,
        ) -> None:
            pass

        def promise_batch_action_function_call_weight(
            promise_index: int,
            function_name_len: int,
            function_name_ptr: int,
            arguments_len: int,
            arguments_ptr: int,
            amount_ptr: int,
            gas: int,
            weight: int,
        ) -> None:
            pass

        def promise_batch_action_transfer(promise_index: int, amount_ptr: int) -> None:
            pass

        def promise_batch_action_stake(
            promise_index: int,
            amount_ptr: int,
            public_key_len: int,
            public_key_ptr: int,
        ) -> None:
            pass

        def promise_batch_action_add_key_with_full_access(
            promise_index: int, public_key_len: int, public_key_ptr: int, nonce: int
        ) -> None:
            pass

        def promise_batch_action_add_key_with_function_call(
            promise_index: int,
            public_key_len: int,
            public_key_ptr: int,
            nonce: int,
            allowance_ptr: int,
            receiver_id_len: int,
            receiver_id_ptr: int,
            function_names_len: int,
            function_names_ptr: int,
        ) -> None:
            pass

        def promise_batch_action_delete_key(
            promise_index: int, public_key_len: int, public_key_ptr: int
        ) -> None:
            pass

        def promise_batch_action_delete_account(
            promise_index: int, beneficiary_id_len: int, beneficiary_id_ptr: int
        ) -> None:
            pass

        def promise_yield_create(
            function_name_len: int,
            function_name_ptr: int,
            arguments_len: int,
            arguments_ptr: int,
            gas: int,
            gas_weight: int,
            register_id: int,
        ) -> int:
            return 0

        def promise_yield_resume(
            data_id_len: int, data_id_ptr: int, payload_len: int, payload_ptr: int
        ) -> int:
            return 0

        # Promise API results
        def promise_results_count() -> int:
            return 0

        def promise_result(result_idx: int, register_id: int) -> int:
            return 0

        def promise_return(promise_id: int) -> None:
            pass

        # Storage API
        def storage_write(
            key_len: int, key_ptr: int, value_len: int, value_ptr: int, register_id: int
        ) -> int:
            storage[bytes_from_ptr(key_ptr, key_len)] = bytes_from_ptr(
                value_ptr, value_len
            )
            return 1

        def storage_read(key_len: int, key_ptr: int, register_id: int) -> int:
            key = bytes_from_ptr(key_ptr, key_len)
            if key in storage:
                registers[register_id] = storage[key]
                return 1
            return 0

        def storage_remove(key_len: int, key_ptr: int, register_id: int) -> int:
            key = bytes_from_ptr(key_ptr, key_len)
            if key in storage:
                del storage[key]
            return 1

        def storage_has_key(key_len: int, key_ptr: int) -> int:
            key = bytes_from_ptr(key_ptr, key_len)
            return 1 if key in storage else 0

        # Validator API
        def validator_stake(
            account_id_len: int, account_id_ptr: int, stake_ptr: int
        ) -> None:
            pass

        def validator_total_stake(stake_ptr: int) -> None:
            pass

        # Alt BN128
        def alt_bn128_g1_multiexp(
            value_len: int, value_ptr: int, register_id: int
        ) -> None:
            pass

        def alt_bn128_g1_sum(value_len: int, value_ptr: int, register_id: int) -> None:
            pass

        def alt_bn128_pairing_check(value_len: int, value_ptr: int) -> int:
            return 0

        func = wasmtime.Func
        ft = wasmtime.FuncType
        vt = wasmtime.ValType

        env_imports = {
            # Auxilary functions which are not part of the NEAR API
            "trace_function_call": func(
                self.store, ft([vt.i32()], []), trace_function_call
            ),
            "trace_frozen_module_load": func(
                self.store, ft([vt.i32()], []), trace_frozen_module_load
            ),
            "trace_builtin_module_load": func(
                self.store, ft([vt.i32()], []), trace_builtin_module_load
            ),
            # Registers
            "read_register": func(
                self.store, ft([vt.i64(), vt.i64()], []), read_register
            ),
            "register_len": func(self.store, ft([vt.i64()], [vt.i64()]), register_len),
            "write_register": func(
                self.store, ft([vt.i64(), vt.i64(), vt.i64()], []), write_register
            ),
            # Context API
            "current_account_id": func(
                self.store, ft([vt.i64()], []), current_account_id
            ),
            "signer_account_pk": func(
                self.store, ft([vt.i64()], []), signer_account_pk
            ),
            "signer_account_id": func(
                self.store, ft([vt.i64()], []), signer_account_id
            ),
            "predecessor_account_id": func(
                self.store, ft([vt.i64()], []), predecessor_account_id
            ),
            "input": func(self.store, ft([vt.i64()], []), input),
            "block_index": func(self.store, ft([], [vt.i64()]), block_index),
            "block_timestamp": func(self.store, ft([], [vt.i64()]), block_timestamp),
            "epoch_height": func(self.store, ft([], [vt.i64()]), epoch_height),
            "storage_usage": func(self.store, ft([], [vt.i64()]), storage_usage),
            # Economics API
            "account_balance": func(self.store, ft([vt.i64()], []), account_balance),
            "account_locked_balance": func(
                self.store, ft([vt.i64()], []), account_locked_balance
            ),
            "attached_deposit": func(self.store, ft([vt.i64()], []), attached_deposit),
            "prepaid_gas": func(self.store, ft([], [vt.i64()]), prepaid_gas),
            "used_gas": func(self.store, ft([], [vt.i64()]), used_gas),
            # Math API
            "random_seed": func(self.store, ft([vt.i64()], []), random_seed),
            "sha256": func(self.store, ft([vt.i64(), vt.i64(), vt.i64()], []), sha256),
            "keccak256": func(
                self.store, ft([vt.i64(), vt.i64(), vt.i64()], []), keccak256
            ),
            "keccak512": func(
                self.store, ft([vt.i64(), vt.i64(), vt.i64()], []), keccak512
            ),
            "ripemd160": func(
                self.store, ft([vt.i64(), vt.i64(), vt.i64()], []), ripemd160
            ),
            "ecrecover": func(
                self.store,
                ft(
                    [
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                    ],
                    [vt.i64()],
                ),
                ecrecover,
            ),
            "ed25519_verify": func(
                self.store,
                ft(
                    [vt.i64(), vt.i64(), vt.i64(), vt.i64(), vt.i64(), vt.i64()],
                    [vt.i64()],
                ),
                ed25519_verify,
            ),
            # Miscellaneous API
            "value_return": func(
                self.store, ft([vt.i64(), vt.i64()], []), value_return
            ),
            "panic": func(self.store, ft([], []), panic),
            "panic_utf8": func(self.store, ft([vt.i64(), vt.i64()], []), panic_utf8),
            "log_utf8": func(self.store, ft([vt.i64(), vt.i64()], []), log_utf8),
            "log_utf16": func(self.store, ft([vt.i64(), vt.i64()], []), log_utf16),
            "abort": func(
                self.store, ft([vt.i32(), vt.i32(), vt.i32(), vt.i32()], []), abort
            ),
            # Promises API
            "promise_create": func(
                self.store,
                ft(
                    [
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                    ],
                    [vt.i64()],
                ),
                promise_create,
            ),
            "promise_then": func(
                self.store,
                ft(
                    [
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                    ],
                    [vt.i64()],
                ),
                promise_then,
            ),
            "promise_and": func(
                self.store, ft([vt.i64(), vt.i64()], [vt.i64()]), promise_and
            ),
            "promise_batch_create": func(
                self.store, ft([vt.i64(), vt.i64()], [vt.i64()]), promise_batch_create
            ),
            "promise_batch_then": func(
                self.store,
                ft([vt.i64(), vt.i64(), vt.i64()], [vt.i64()]),
                promise_batch_then,
            ),
            # Promise API actions
            "promise_batch_action_create_account": func(
                self.store, ft([vt.i64()], []), promise_batch_action_create_account
            ),
            "promise_batch_action_deploy_contract": func(
                self.store,
                ft([vt.i64(), vt.i64(), vt.i64()], []),
                promise_batch_action_deploy_contract,
            ),
            "promise_batch_action_function_call": func(
                self.store,
                ft(
                    [
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                    ],
                    [],
                ),
                promise_batch_action_function_call,
            ),
            "promise_batch_action_function_call_weight": func(
                self.store,
                ft(
                    [
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                    ],
                    [],
                ),
                promise_batch_action_function_call_weight,
            ),
            "promise_batch_action_transfer": func(
                self.store, ft([vt.i64(), vt.i64()], []), promise_batch_action_transfer
            ),
            "promise_batch_action_stake": func(
                self.store,
                ft([vt.i64(), vt.i64(), vt.i64(), vt.i64()], []),
                promise_batch_action_stake,
            ),
            "promise_batch_action_add_key_with_full_access": func(
                self.store,
                ft([vt.i64(), vt.i64(), vt.i64(), vt.i64()], []),
                promise_batch_action_add_key_with_full_access,
            ),
            "promise_batch_action_add_key_with_function_call": func(
                self.store,
                ft(
                    [
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                    ],
                    [],
                ),
                promise_batch_action_add_key_with_function_call,
            ),
            "promise_batch_action_delete_key": func(
                self.store,
                ft([vt.i64(), vt.i64(), vt.i64()], []),
                promise_batch_action_delete_key,
            ),
            "promise_batch_action_delete_account": func(
                self.store,
                ft([vt.i64(), vt.i64(), vt.i64()], []),
                promise_batch_action_delete_account,
            ),
            "promise_yield_create": func(
                self.store,
                ft(
                    [
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                        vt.i64(),
                    ],
                    [vt.i64()],
                ),
                promise_yield_create,
            ),
            "promise_yield_resume": func(
                self.store,
                ft([vt.i64(), vt.i64(), vt.i64(), vt.i64()], [vt.i32()]),
                promise_yield_resume,
            ),
            # Promise API results
            "promise_results_count": func(
                self.store, ft([], [vt.i64()]), promise_results_count
            ),
            "promise_result": func(
                self.store, ft([vt.i64(), vt.i64()], [vt.i64()]), promise_result
            ),
            "promise_return": func(self.store, ft([vt.i64()], []), promise_return),
            # Storage API
            "storage_write": func(
                self.store,
                ft([vt.i64(), vt.i64(), vt.i64(), vt.i64(), vt.i64()], [vt.i64()]),
                storage_write,
            ),
            "storage_read": func(
                self.store, ft([vt.i64(), vt.i64(), vt.i64()], [vt.i64()]), storage_read
            ),
            "storage_remove": func(
                self.store,
                ft([vt.i64(), vt.i64(), vt.i64()], [vt.i64()]),
                storage_remove,
            ),
            "storage_has_key": func(
                self.store, ft([vt.i64(), vt.i64()], [vt.i64()]), storage_has_key
            ),
            # Validator API
            "validator_stake": func(
                self.store, ft([vt.i64(), vt.i64(), vt.i64()], []), validator_stake
            ),
            "validator_total_stake": func(
                self.store, ft([vt.i64()], []), validator_total_stake
            ),
            # Alt BN128
            "alt_bn128_g1_multiexp": func(
                self.store,
                ft([vt.i64(), vt.i64(), vt.i64()], []),
                alt_bn128_g1_multiexp,
            ),
            "alt_bn128_g1_sum": func(
                self.store, ft([vt.i64(), vt.i64(), vt.i64()], []), alt_bn128_g1_sum
            ),
            "alt_bn128_pairing_check": func(
                self.store,
                ft([vt.i64(), vt.i64()], [vt.i64()]),
                alt_bn128_pairing_check,
            ),
        }
        return env_imports


def trace_wasm(
    wasm_runner: WasmRunner, entry_points: list, entry_point_test_inputs: dict
) -> tuple[set[int], set[str]]:
    for entry_point in entry_points:
        test_inputs = entry_point_test_inputs.get(entry_point, [])
        if len(test_inputs) == 0:
            test_inputs.append(b"")
        for input_bytes in test_inputs:
            print(f"running method {entry_point}({input_bytes})")
            wasm_runner.set_input_bytes(input_bytes)
            entry_point_export = wasm_runner.export(entry_point)
            try:
                entry_point_export()
            except Exception as e:
                print(f"trace_wasm(): exception {e}")
            wasm_runner.reset()
    return (
        wasm_runner.called_functions,
        wasm_runner.loaded_frozen_modules,
        wasm_runner.loaded_builtin_modules,
    )


def get_function_names(wat: list) -> set[str]:
    names = set()
    for item in wat:
        if item[0] == "func":
            names.add(str(item[1]).lstrip("$"))
    return names


def instrument_wat(wat):
    instrumented_wat = []
    imports_added = False
    for item in wat:
        if item[0] == "func":
            func = deepcopy(item)
            func_name = str(func[1]).lstrip("$")
            func_name_hash = fnv1a_32(func_name)
            pos = 2
            for func_item in func[2:]:
                if func_item[0] not in ("param", "result", "local"):
                    break
                pos += 1
            func.insert(
                pos, ["call", "$trace_function_call", ["i32.const", func_name_hash]]
            )
            if func_name == "load_frozen_module":
                func.insert(
                    pos, ["call", "$trace_frozen_module_load", ["local.get", "$0"]]
                )
            if func_name == "notify_builtin_module_load":
                func.insert(
                    pos, ["call", "$trace_builtin_module_load", ["local.get", "$0"]]
                )
            instrumented_wat.append(func)
        elif item[0] == "import" and not imports_added:
            instrumented_wat.append(
                [
                    "import",
                    '"env"',
                    '"trace_function_call"',
                    ["func", "$trace_function_call", ["param", "i32"]],
                ]
            )
            instrumented_wat.append(
                [
                    "import",
                    '"env"',
                    '"trace_frozen_module_load"',
                    ["func", "$trace_frozen_module_load", ["param", "i32"]],
                ]
            )
            instrumented_wat.append(
                [
                    "import",
                    '"env"',
                    '"trace_builtin_module_load"',
                    ["func", "$trace_builtin_module_load", ["param", "i32"]],
                ]
            )
            instrumented_wat.append(item)
            imports_added = True
        else:
            instrumented_wat.append(item)
    return instrumented_wat


def unescape_data_str(s):
    if not (s.startswith('"') and s.endswith('"')):
        raise ValueError("String must be doubly-quoted")
    content, result, i = s[1:-1], [], 0
    while i < len(content):
        if content[i] == "\\" and i + 1 < len(content):
            next_char = content[i + 1]
            if next_char == "t":
                result.append(ord("\t"))
                i += 2
            elif next_char == "n":
                result.append(ord("\n"))
                i += 2
            elif next_char == "r":
                result.append(ord("\r"))
                i += 2
            elif next_char == '"':
                result.append(ord('"'))
                i += 2
            elif next_char == "'":
                result.append(ord("'"))
                i += 2
            elif next_char == "\\":
                result.append(ord("\\"))
                i += 2
            elif i + 2 < len(content) and all(
                c in "0123456789abcdefABCDEF" for c in content[i + 1 : i + 3]
            ):
                result.append(int(content[i + 1 : i + 3], 16))
                i += 3
            else:
                result.append(ord("\\"))
                i += 1
        else:
            result.append(ord(content[i]))
            i += 1
    return bytes(result)


def escape_data_str(data: bytes):
    result = []
    for b in data:
        # if b == ord('\t'): result.append('\\t')
        # elif b == ord('\n'): result.append('\\n')
        # elif b == ord('\r'): result.append('\\r')
        if b == ord('"'):
            result.append('\\"')
        elif b == ord("'"):
            result.append("\\'")
        elif b == ord("\\"):
            result.append("\\\\")
        elif 32 <= b <= 126:
            result.append(chr(b))
        else:
            result.append(f"\\{b:02x}")
    # assert(unescape_data_str('"' + ''.join(result) + '"') == data)
    return '"' + "".join(result) + '"'


def get_wasm_data_initializer(wat):
    initialized_memory_length = 0
    initializer = bytearray(20000000)
    for item in wat:
        if item[0] == "data":
            data = unescape_data_str(item[-1])
            offset = int(item[-2][1])
            length = len(data)
            initialized_memory_length = max(initialized_memory_length, offset + length)
            initializer[offset : offset + length] = data
    return bytes(initializer[0:initialized_memory_length])


def compress_wasm_data_initializer(wat):
    FROZEN_MODULE_BASE_ADDR = 1048576
    WASM_DATA_BASE_ADDR = 8388608
    COMPRESSION_TYPE_LZ4 = 0x00347A6C
    COMPRESSED_BLOCK_HEADER_ADDR = 1024
    wasm_data = get_wasm_data_initializer(wat)
    frozen_module_data_last_addr = 0
    for i in range(FROZEN_MODULE_BASE_ADDR, min(WASM_DATA_BASE_ADDR, len(wasm_data))):
        if wasm_data[i] != 0:
            frozen_module_data_last_addr = i + 1
    wasm_data0 = wasm_data[FROZEN_MODULE_BASE_ADDR:frozen_module_data_last_addr]
    wasm_data1 = wasm_data[WASM_DATA_BASE_ADDR:]
    compressed_data0 = lz4.frame.compress(
        wasm_data0,
        compression_level=lz4.frame.COMPRESSIONLEVEL_MAX,
        block_size=lz4.frame.BLOCKSIZE_MAX4MB,
    )
    compressed_data1 = lz4.frame.compress(
        wasm_data1,
        compression_level=lz4.frame.COMPRESSIONLEVEL_MAX,
        block_size=lz4.frame.BLOCKSIZE_MAX4MB,
    )
    compressed_data_addr0 = COMPRESSED_BLOCK_HEADER_ADDR + 1024
    compressed_data_addr1 = (
        compressed_data_addr0 + len(compressed_data0) + 1023
    ) & ~1023
    print("applying lz4 compression to wasm data initializers:")
    print(
        f" data0: {len(wasm_data0)} bytes @{FROZEN_MODULE_BASE_ADDR} -> {len(compressed_data0)} bytes @{compressed_data_addr0}"
    )
    print(
        f" data1: {len(wasm_data1)} bytes @{WASM_DATA_BASE_ADDR} -> {len(compressed_data1)} bytes @{compressed_data_addr1}"
    )
    modified_wat = []
    for item in wat:
        if item[0] != "data":
            modified_wat.append(item)
    modified_wat.append(
        [
            "data",
            "$.compressed_data.header",
            ["i32.const", COMPRESSED_BLOCK_HEADER_ADDR],
            escape_data_str(
                struct.pack("<L", COMPRESSION_TYPE_LZ4)
                + struct.pack("<L", compressed_data_addr0)
                + struct.pack("<L", len(compressed_data0))
                + struct.pack("<L", FROZEN_MODULE_BASE_ADDR)
                + struct.pack("<L", COMPRESSION_TYPE_LZ4)
                + struct.pack("<L", compressed_data_addr1)
                + struct.pack("<L", len(compressed_data1))
                + struct.pack("<L", WASM_DATA_BASE_ADDR)
            ),
        ]
    )
    modified_wat.append(
        [
            "data",
            "$.compressed_data.0",
            ["i32.const", compressed_data_addr0],
            escape_data_str(compressed_data0),
        ]
    )
    modified_wat.append(
        [
            "data",
            "$.compressed_data.1",
            ["i32.const", compressed_data_addr1],
            escape_data_str(compressed_data1),
        ]
    )
    return modified_wat


class WasmDataStore:
    BASE_ADDR = 1048576
    MAX_ADDR = 8388608
    FROZEN_MODULE_HEADER_LENGTH = 256
    FROZEN_MODULE_MAX_PATH_LENGTH = 248
    MAX_FROZEN_MODULES = 512
    STRINGS_OFFSET = FROZEN_MODULE_HEADER_LENGTH * MAX_FROZEN_MODULES

    # memory layout:
    #   BASE_ADDR: <frozen module header:256 bytes> * MAX_FROZEN_MODULES
    #              <allocated null-terminated strings>
    #              <frozen module data chunks linked from the header>
    #              ...
    #   MAX_ADDR: start of the regular WASM data area (-sGLOBAL_BASE=<MAX_ADDR> Emscripten option)

    # frozen module header (64 bytes):
    #   data addr:4 bytes (le)
    #   data length:4 bytes (le)
    #   path: 248 bytes (null-terminated)
    #   both data addr and size fields is a empty header/end of valid headers marker

    def __init__(self):
        self.frozen_modules = []
        self.packed_strings = bytearray()
        self.packed_strings_cache = dict()

    def add_frozen_module(self, path: str, bytecode: bytes):
        # print(f"add_frozen_module(): including {path}")
        self.frozen_modules.append((path, bytecode))

    def allocate_string(self, value: str):
        if value in self.packed_strings_cache:
            return self.packed_strings_cache[value]
        addr = self.BASE_ADDR + self.STRINGS_OFFSET + len(self.packed_strings)
        self.packed_strings += value.encode("utf-8") + b"\0"
        self.packed_strings_cache[value] = addr
        return addr

    def to_bytes(self):
        "Produces the raw bytes to be put into WASM data section starting from BASE_ADDR, excluding any of the trailing zeroes"
        data = bytearray(self.MAX_ADDR - self.BASE_ADDR)
        data[self.STRINGS_OFFSET : self.STRINGS_OFFSET + len(self.packed_strings)] = (
            self.packed_strings
        )
        alloc_offset = self.STRINGS_OFFSET + len(self.packed_strings)
        frozen_module_index = 0
        for path, bytecode in self.frozen_modules:
            data[
                frozen_module_index * self.FROZEN_MODULE_HEADER_LENGTH : (
                    frozen_module_index + 1
                )
                * self.FROZEN_MODULE_HEADER_LENGTH
            ] = (
                struct.pack("<L", self.BASE_ADDR + alloc_offset)
                + struct.pack("<L", len(bytecode))
                + path.encode("utf-8").ljust(self.FROZEN_MODULE_MAX_PATH_LENGTH, b"\0")
            )
            assert len(path.encode("utf-8")) < self.FROZEN_MODULE_MAX_PATH_LENGTH
            data[alloc_offset : alloc_offset + len(bytecode)] = bytecode
            alloc_offset += len(bytecode)
            frozen_module_index += 1
        assert alloc_offset < self.MAX_ADDR
        del data[alloc_offset:]
        if len(self.frozen_modules) < 100:
            print(
                f"included frozen modules: {', '.join([path for (path, _) in self.frozen_modules])}"
            )
        return bytes(data)

    def add_to_wasm_runner(self, wasm_runner: WasmRunner):
        data = self.to_bytes()
        data_ptr = wasm_runner.data_ptr()
        for i in range(0, len(data)):
            data_ptr[self.BASE_ADDR + i] = data[i]

    def add_to_wat(self, wat):
        modified_wat = wat.copy()
        modified_wat.append(
            [
                "data",
                "$.data.frozen",
                ["i32.const", self.BASE_ADDR],
                escape_data_str(self.to_bytes()),
            ]
        )
        return modified_wat


def add_contract_entry_points_to_wat(
    wat, wasm_data: WasmDataStore, contract_module_name, entry_points
):
    modified_wat = wat.copy()
    for func_name in entry_points:
        module_name_address = wasm_data.allocate_string(contract_module_name)
        func_name_address = wasm_data.allocate_string(func_name)
        modified_wat.append(
            [
                "export",
                f'"{func_name}"',
                ["func", f"${contract_module_name}_{func_name}"],
            ]
        )
        modified_wat.append(
            [
                "func",
                f"${contract_module_name}_{func_name}",
                [
                    "call",
                    "$contract_entry_point",
                    ["i32.const", module_name_address],
                    ["i32.const", func_name_address],
                ],
            ]
        )
    return modified_wat


def compile_to_bytecode(
    wasm_runner: WasmRunner, wasm_data: WasmDataStore, source_code, filename
):
    alloc_buffer = wasm_runner.export("_alloc_buffer")
    compile_contract_source = wasm_runner.export("_compile_contract_source")
    wasm_data.add_to_wasm_runner(wasm_runner)
    data_ptr = wasm_runner.data_ptr()

    def alloc_null_terminated_string(string, encoding="utf-8"):
        string_bytes = string.encode(encoding)
        buffer_ptr = alloc_buffer(len(string_bytes) + 1)
        for i in range(0, len(string_bytes)):
            data_ptr[buffer_ptr + i] = string_bytes[i]
        data_ptr[buffer_ptr + len(string_bytes)] = 0
        return buffer_ptr

    bytecode_len_ptr = alloc_buffer(4)
    bytecode_ptr = compile_contract_source(
        alloc_null_terminated_string(source_code),
        alloc_null_terminated_string(filename),
        bytecode_len_ptr,
    )
    bytecode_len = struct.unpack(
        "<L", bytes(data_ptr[bytecode_len_ptr : bytecode_len_ptr + 4])
    )[0]
    return bytes(data_ptr[bytecode_ptr : bytecode_ptr + bytecode_len])


def should_include_lib_path(pinned_module_paths, path: str):
    return "__pycache__" not in path and (
        pinned_module_paths is None or path in pinned_module_paths
    )


def add_frozen_modules(
    wasm_data: WasmDataStore,
    pinned_module_paths,
    contract_pyc_path,
    stdlib_zip_path,
    user_lib_path,
):
    with zipfile.ZipFile(stdlib_zip_path, "r") as zip_file:
        for info in zip_file.infolist():
            frozen_path = info.filename.lstrip("/")
            if (
                not info.is_dir()
                and frozen_path.endswith(".pyc")
                and should_include_lib_path(pinned_module_paths, frozen_path)
            ):
                wasm_data.add_frozen_module(frozen_path, zip_file.read(info.filename))
    if user_lib_path:
        for path in Path(user_lib_path).glob("**/*.pyc"):
            frozen_path = str(path.relative_to(user_lib_path)).replace("\\", "/")
            if should_include_lib_path(pinned_module_paths, frozen_path):
                with open(path, "rb") as f:
                    wasm_data.add_frozen_module(frozen_path, f.read())
    if contract_pyc_path:
        with open(contract_pyc_path, "rb") as f:
            wasm_data.add_frozen_module(
                CONTRACT_MODULE_PREFIX + contract_pyc_path.name, f.read()
            )


def get_near_exports_from_file(file_path: str) -> set[str]:
    with open(file_path, "r") as file:
        content = file.read()
        tree = ast.parse(content, filename=file_path)

    # Track custom decorators that eventually use near.export
    custom_exporters = set(["export", "view", "call", "init", "callback"])
    # Track functions that are exported
    near_exports = []
    near_optimizer_inputs = defaultdict(list)

    # First pass: identify custom decorators that use near.export
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            # Check if this is a potential custom decorator function
            if node.name in custom_exporters:
                for body_node in ast.walk(node):
                    # Check function bodies for return statements that use near.export
                    if (
                        isinstance(body_node, ast.Return)
                        and body_node.value is not None
                    ):
                        # Look for near.export in the return expression
                        for return_node in ast.walk(body_node.value):
                            if (
                                isinstance(return_node, ast.Attribute)
                                and isinstance(return_node.value, ast.Name)
                                and return_node.value.id == "near"
                                and return_node.attr == "export"
                            ):
                                custom_exporters.add(node.name)
                                break

    # Second pass: find functions with near.export or custom exporters as decorators
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                # Case 1: Direct @near.export
                if (
                    isinstance(decorator, ast.Attribute)
                    and isinstance(decorator.value, ast.Name)
                    and decorator.value.id == "near"
                    and decorator.attr == "export"
                ) or (
                    isinstance(decorator, ast.Name) and decorator.id == "near.export"
                ):
                    near_exports.append(node.name)

                # Case 2: Using a custom exporter decorator like @init, @view, etc.
                if isinstance(decorator, ast.Name) and decorator.id in custom_exporters:
                    near_exports.append(node.name)

                # Case 3: @near.optimizer_inputs()
                if isinstance(decorator, ast.Call) and decorator.args:
                    if (
                        isinstance(decorator.func, ast.Attribute)
                        and isinstance(decorator.func.value, ast.Name)
                        and decorator.func.value.id == "near"
                        and decorator.func.attr == "optimizer_inputs"
                    ) or (
                        isinstance(decorator.func, ast.Name)
                        and decorator.func.id == "near.optimizer_inputs"
                    ):
                        for elt in decorator.args[0].elts:
                            if isinstance(elt, ast.Constant):
                                value = None
                                if isinstance(elt.value, str):
                                    value = elt.value.encode("utf-8")
                                elif isinstance(elt.value, bytes):
                                    value = elt.value
                                elif isinstance(elt.value, (dict, list)):
                                    value = json.dumps(elt.value).encode("utf-8")
                                else:
                                    value = str(elt.value).encode("utf-8")
                                near_optimizer_inputs[node.name].append(value)

    return near_exports, near_optimizer_inputs


def get_binary_path(tool_name):
    if platform.system() == "Windows":
        binary_path = BINARY_PATH / f"{tool_name}.exe"
    else:
        binary_path = BINARY_PATH / tool_name
    if not binary_path.exists():
        raise FileNotFoundError(f"Binary {tool_name} not found at {binary_path}")
    return str(binary_path)


def run_tool(tool_name, args):
    cmd = [get_binary_path(tool_name)] + args
    print(f"running {' '.join([str(c) for c in cmd])}")
    return subprocess.run(cmd, text=True, check=True)


def optimize_wasm_file(
    build_dir="build",
    input_file=LIB_PATH / "python.wasm",
    output_file="python-optimized.wasm",
    module_opt=True,
    function_opt="aggressive",  # valid values: "aggressive", "safe", "safest", "off"
    compression=True,
    debug_info=True,
    pinned_functions=[],
    user_lib_dir="lib",
    stdlib_zip=LIB_PATH / "python-stdlib.zip",
    contract_file="contract.py",
    contract_exports=[],
    verify_optimized_wasm=True,
    abi=None,
):
    build_path = Path(build_dir)
    wasm_path = Path(input_file)
    wat_path = build_path / "python.wat"
    instrumented_wasm_path = build_path / "python-instrumented.wasm"
    instrumented_wat_path = build_path / "python-instrumented.wat"

    build_path.mkdir(parents=True, exist_ok=True)

    sys.setrecursionlimit(10000)

    run_tool("wasm-dis", [wasm_path, "-o", wat_path])
    print(f"reading {wat_path}..")
    wat = read_sexp(wat_path)

    function_names = get_function_names(wat)
    function_name_hashes = {fnv1a_32(s) for s in function_names}

    with open(wasm_path, "rb") as f:
        wasm_bytes = f.read()

    wasm_data = WasmDataStore()
    add_frozen_modules(wasm_data, None, None, stdlib_zip, None)

    contract_path = Path(contract_file)
    contract_pyc_path = contract_path.with_suffix(".pyc")

    entry_points = contract_exports
    entry_point_test_inputs = defaultdict(list)

    if len(contract_exports) == 0:
        entry_points, entry_point_test_inputs = get_near_exports_from_file(
            contract_path
        )
    elif abi is not None:
        arg_test_values = {
            "string": ["", "An ascii string value", "此地无银三百两"],
            "integer": [0, -3, 10000000000000000],
            "boolean": [True, False],
            "object": [{}, None],
        }
        for f in abi.get("body", {}).get("functions", {}):
            name = f.get("name")
            args = {}
            for arg in f.get("params", {}).get("args", {}):
                args[arg.get("name")] = arg.get("type_schema", {}).get("type", "string")
            test_args_sets = []
            if len(args.keys()) > 0:
                max_values = max(len(values) for values in arg_test_values.values())
                test_args = [
                    dict(
                        zip(
                            args.keys(),
                            [
                                arg_test_values[t][i % len(arg_test_values[t])]
                                for t in args.values()
                            ],
                        )
                    )
                    for i in range(max_values)
                ]
                test_args_sets.extend(test_args)
            entry_point_test_inputs[name] = [
                json.dumps(args_set).encode("utf-8") for args_set in test_args_sets
            ]

    print(f"contract {contract_file} entry points: {entry_points}")
    print(
        f"contract {contract_file} entry point test inputs: {entry_point_test_inputs}"
    )

    compiler = WasmRunner(wasm_bytes)
    for path in Path(user_lib_dir).glob("**/*.py"):
        pyc_path = path.with_suffix(".pyc")
        # print(f"compiling {path} to {pyc_path}..")
        with open(path, "r") as source_file:
            with open(pyc_path, "wb") as pyc_file:
                pyc_file.write(
                    compile_to_bytecode(
                        compiler, wasm_data, source_file.read(), path.name
                    )
                )
                compiler.reset()

    # print(f"compiling {contract_path} to {contract_pyc_path}..")
    with open(contract_path, "r") as source_file:
        with open(contract_pyc_path, "wb") as pyc_file:
            pyc_file.write(
                compile_to_bytecode(
                    compiler, wasm_data, source_file.read(), contract_path.name
                )
            )

    wasm_data = WasmDataStore()
    add_frozen_modules(wasm_data, None, contract_pyc_path, stdlib_zip, user_lib_dir)

    instrumented_wat = wasm_data.add_to_wat(
        instrument_wat(
            add_contract_entry_points_to_wat(
                wat,
                wasm_data,
                CONTRACT_MODULE_PREFIX + contract_pyc_path.stem,
                entry_points,
            )
        )
    )
    print(f"writing {instrumented_wat_path}..")
    write_sexp(instrumented_wat, instrumented_wat_path)

    run_tool(
        "wasm-as",
        [
            "-g",
            instrumented_wat_path,
            "-o",
            instrumented_wasm_path,
            "--enable-nontrapping-float-to-int",
            "--enable-sign-ext",
        ],
    )

    print(f"tracing called functions and loaded modules in {instrumented_wasm_path}..")
    with open(instrumented_wasm_path, "rb") as f:
        instrumented_wasm_bytes = f.read()

    called_function_name_hashes, loaded_frozen_modules, loaded_builtin_modules = (
        trace_wasm(
            WasmRunner(instrumented_wasm_bytes), entry_points, entry_point_test_inputs
        )
    )
    print(f"loaded builtin modules: {loaded_builtin_modules}")
    print(f"loaded frozen modules: {loaded_frozen_modules}")

    pinned_function_names = set(DEFAULT_PINNED_FUNCTIONS + pinned_functions)

    if function_opt in ("safe", "safest"):
        pinned_function_names.update(SAFE_PINNED_FUNCTIONS)

    pinned_function_name_hashes = set()
    pinned_function_name_hashes = pinned_function_name_hashes.union(
        {fnv1a_32(s.strip()) for s in pinned_function_names}
    )
    unreferenced_function_name_hashes = function_name_hashes.difference(
        called_function_name_hashes
    ).difference(pinned_function_name_hashes)
    non_loaded_builtin_modules_removable_function_name_prefixes = [
        v
        for module, prefixes in BUILTIN_MODULE_FUNCTION_NAME_PREFIXES.items()
        for v in prefixes
        if module not in loaded_builtin_modules
    ]

    def removing_function_allowed(func_name):
        if function_opt in ("aggressive", "safe"):
            return True
        elif function_opt == "safest":
            for prefix in (
                SAFELY_REMOVABLE_FUNCTION_NAME_PREFIXES
                + non_loaded_builtin_modules_removable_function_name_prefixes
            ):
                if func_name.startswith(prefix):
                    return True
            for suffix in SAFELY_REMOVABLE_FUNCTION_NAME_SUFFIXES:
                if func_name.endswith(suffix):
                    return True
        return False

    wasm_data = WasmDataStore()

    def replace_removed_function_calls(items):
        for item in items:
            if isinstance(item, list):
                if len(item) > 1 and item[0] == "call":
                    func_name = str(item[1]).lstrip("$")
                    if (
                        fnv1a_32(func_name) in unreferenced_function_name_hashes
                        and removing_function_allowed(func_name)
                    ):
                        # print(f"optimizing out {func_name}")
                        del item[0:]
                        item += [
                            "block",
                            [
                                "call",
                                "$optimized_out_function_panic_handler",
                                ["i32.const", wasm_data.allocate_string(func_name)],
                            ],
                            ["unreachable"],
                        ]
                else:
                    replace_removed_function_calls(item)

    if function_opt != "off":
        removed_function_names = set()
        for item in wat:
            if item[0] == "func":
                replace_removed_function_calls(item)
                func_name = str(item[1]).lstrip("$")
                if fnv1a_32(
                    func_name
                ) in unreferenced_function_name_hashes and removing_function_allowed(
                    func_name
                ):
                    removed_function_names.add(func_name)
                    pos = 2
                    for func_item in item[2:]:
                        if func_item[0] not in ("param", "result", "local"):
                            break
                        pos += 1
                    item.insert(pos, ["unreachable"])
                    del item[pos + 1 :]

        with open(build_path / "removed_functions.txt", "w") as f:
            for fn in sorted(removed_function_names):
                f.write(f"{fn}\n")

        with open(build_path / "retained_functions.txt", "w") as f:
            for fn in sorted(function_names):
                if fn not in removed_function_names:
                    f.write(f"{fn}\n")

    add_frozen_modules(
        wasm_data,
        loaded_frozen_modules if module_opt else None,
        contract_pyc_path,
        stdlib_zip,
        user_lib_dir,
    )
    modified_wat = wasm_data.add_to_wat(
        add_contract_entry_points_to_wat(
            wat,
            wasm_data,
            CONTRACT_MODULE_PREFIX + contract_pyc_path.stem,
            entry_points,
        )
    )

    modified_wat_path = build_path / "python-modified.wat"
    optimized_wasm_path = build_path / "python-optimized.wasm"
    optimized_wat_path = build_path / "python-optimized.wat"
    compressed_optimized_wasm_path = build_path / "python-compressed.wasm"
    compressed_optimized_wat_path = build_path / "python-compressed.wat"

    print(f"writing {modified_wat_path}..")
    write_sexp(modified_wat, modified_wat_path)

    run_tool(
        "wasm-opt",
        [
            "-Oz",
            modified_wat_path,
            "-o",
            optimized_wasm_path,
            "--enable-nontrapping-float-to-int",
            "--enable-sign-ext",
        ]
        + (["-g"] if debug_info else []),
    )

    run_tool("wasm-dis", [optimized_wasm_path, "-o", optimized_wat_path])
    print(f"reading {optimized_wat_path}..")
    optimized_wat = read_sexp(optimized_wat_path)

    if compression:
        compressed_optimized_wat = compress_wasm_data_initializer(optimized_wat)
        print(f"writing {compressed_optimized_wat_path}..")
        write_sexp(compressed_optimized_wat, compressed_optimized_wat_path)
        run_tool(
            "wasm-as",
            [
                compressed_optimized_wat_path,
                "-o",
                compressed_optimized_wasm_path,
                "--enable-nontrapping-float-to-int",
                "--enable-sign-ext",
            ]
            + (["-g"] if debug_info else []),
        )

    final_wasm_path = (
        compressed_optimized_wasm_path if compression else optimized_wasm_path
    )

    if verify_optimized_wasm:
        with open(final_wasm_path, "rb") as f:
            wasm_bytes = f.read()
        print(
            f"verifying optimized WASM at {final_wasm_path} ({len(wasm_bytes)} bytes).."
        )
        trace_wasm(WasmRunner(wasm_bytes), entry_points, entry_point_test_inputs)

    print(f"copying optimized WASM to {Path(output_file).absolute()}")
    shutil.copy(final_wasm_path, Path(output_file).absolute())

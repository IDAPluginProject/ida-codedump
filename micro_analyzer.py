# -*- coding: utf-8 -*-
from __future__ import annotations

import ida_hexrays
import ida_funcs
import idaapi
import ida_kernwin
import ida_nalt
import idautils
import idc
import ida_name
import ida_typeinf

from typing import Dict, List, Optional, Tuple, Set, Callable
from ptn_utils import FunctionSummary, ArgUse, GlobalAccess, Alias

# Intraprocedural provenance extraction based primarily on ctree with defensive fallbacks.
# This module must run in the IDA main thread.

def _get_func_name(ea: int) -> str:
    try:
        n = ida_funcs.get_func_name(ea)
        if n:
            return n
    except Exception:
        pass
    return f"sub_{ea:X}"

def _type_size_bytes(t) -> Optional[int]:
    try:
        if t and t.get_size() > 0:
            return int(t.get_size())
    except Exception:
        pass
    return None

def _ptr_pointee_size_bytes(t) -> Optional[int]:
    try:
        if t and t.is_ptr():
            pt = t.get_pointed_object()
            if pt:
                return _type_size_bytes(pt)
    except Exception:
        pass
    return None

def _num_value(e) -> Optional[int]:
    try:
        if e.op == ida_hexrays.cot_num:
            return int(e.numval())
    except Exception:
        pass
    return None

def _unwrap_casts(e):
    while e and e.op == ida_hexrays.cot_cast:
        e = e.x
    return e

def _resolve_struct_member(t, offset: int) -> Optional[str]:
    """
    Given a type 't' and a byte offset, try to find the struct member name.
    """
    try:
        if not t:
            return None
        if t.is_ptr():
            t = t.get_pointed_object()

        if not t.is_udt():
            return None

        udt = ida_typeinf.udt_type_data_t()
        if t.get_udt_details(udt):
            for m in udt:
                m_off_bytes = m.offset // 8
                m_size_bytes = m.size // 8
                if m_off_bytes <= offset < m_off_bytes + m_size_bytes:
                    return m.name
    except Exception:
        pass
    return None

def _normalize_expr_origin(cfunc, e) -> Tuple[str, int, str, Optional[int], Optional[int], Optional[str], str, Optional[str]]:
    mode = ""
    off = 0
    length = None
    cast_txt = None
    base_kind = "U"
    base_id = -1
    base_name = ""
    member_name = None
    base_type = None

    def peel(expr):
        nonlocal mode, off, cast_txt, base_type
        cur = expr
        while True:
            if cur is None:
                return None
            if cur.op == ida_hexrays.cot_cast:
                try:
                    cast_txt = str(cur.type)
                except Exception:
                    cast_txt = None
                cur = cur.x
                continue
            if cur.op == ida_hexrays.cot_ref:
                mode = "&"
                cur = cur.x
                continue
            if cur.op == ida_hexrays.cot_memref:
                mode = "*"
                cur = cur.x
                continue
            if cur.op == ida_hexrays.cot_memptr:
                mode = "*"
                try:
                    off += int(cur.m)
                except Exception:
                    pass
                cur = cur.x
                continue
            if cur.op == ida_hexrays.cot_idx:
                idxv = _num_value(cur.y)
                stride = _ptr_pointee_size_bytes(cur.x.type) or _type_size_bytes(cur.type)
                if idxv is not None and stride:
                    off += idxv * stride
                cur = cur.x
                continue
            if cur.op == ida_hexrays.cot_add:
                c1 = _num_value(cur.y)
                c0 = _num_value(cur.x)
                if c1 is not None:
                    off += c1
                    cur = cur.x
                    continue
                if c0 is not None:
                    off += c0
                    cur = cur.y
                    continue
            break
        return cur

    base = peel(_unwrap_casts(e))
    if base is None:
        return ("U", -1, "", None, None, cast_txt, mode, None)

    try:
        base_type = base.type

        if base.op == ida_hexrays.cot_var:
            lv = base.v
            pidx = -1
            lidx = -1
            try:
                if getattr(lv, "is_arg_var", False):
                    pidx = getattr(lv, "argidx", -1)
                    base_kind = "P"
                    base_id = int(pidx) if isinstance(pidx, int) else -1
                else:
                    base_kind = "L"
                    lidx = getattr(lv, "idx", -1)
                    base_id = int(lidx) if isinstance(lidx, int) else -1
            except Exception:
                base_kind = "L"
                base_id = -1
            base_name = getattr(lv, "name", "")
            if mode == "&":
                length = _ptr_pointee_size_bytes(e.type) or _ptr_pointee_size_bytes(base.type)
            else:
                length = _type_size_bytes(e.type)

        elif base.op == ida_hexrays.cot_obj:
            base_kind = "G"
            base_id = int(base.obj_ea)
            base_name = ida_name.get_name(base_id) or ""
            length = _type_size_bytes(e.type)

        elif base.op == ida_hexrays.cot_num:
            base_kind = "C"
            base_id = int(base.numval())
            base_name = f"0x{base_id:X}"
            length = _type_size_bytes(e.type)

        else:
            base_kind = "U"
            base_id = -1

        if off > 0 and base_type:
            member_name = _resolve_struct_member(base_type, off)

        off_val = off if off != 0 else None
        return (base_kind, base_id, base_name, off_val, length, cast_txt, mode, member_name)
    except Exception:
        return ("U", -1, "", None, None, cast_txt, mode, None)

class _ProvCollector(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc):
        super().__init__(ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.fs = FunctionSummary(func_ea=cfunc.entry_ea,
                                  func_name=_get_func_name(cfunc.entry_ea))
        self._seen_globals: Set[Tuple[int, str]] = set()

        try:
            lvars = list(cfunc.get_lvars())
            for lv in lvars:
                nm = getattr(lv, "name", "")
                if getattr(lv, "is_arg_var", False):
                    pidx = getattr(lv, "argidx", -1)
                    self.fs.params[int(pidx) if isinstance(pidx, int) else -1] = nm
                else:
                    lidx = getattr(lv, "idx", -1)
                    self.fs.locals[int(lidx) if isinstance(lidx, int) else -1] = nm
        except Exception:
            pass

        if not self.fs.params:
            try:
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, cfunc.entry_ea):
                    func_data = ida_typeinf.func_type_data_t()
                    if tif.get_func_details(func_data):
                        for i, arg in enumerate(func_data):
                            if arg.name:
                                self.fs.params[i] = arg.name
            except Exception:
                pass

    def _record_arguse(self, call_ea: int, callee_ea: Optional[int], arg_index: int, e):
        bk, bid, bname, off, length, cast, mode, member = _normalize_expr_origin(self.cfunc, e)
        conf = "high" if bk in ("L", "P", "G", "C") else "low"
        callee_name = _get_func_name(callee_ea) if callee_ea else None
        self.fs.arguses.append(ArgUse(
            cs_ea=call_ea or 0,
            callee_ea=callee_ea,
            callee_name=callee_name,
            arg_index=arg_index,
            base_kind=bk,
            base_id=bid if isinstance(bid, int) else -1,
            base_name=bname or "",
            off=off, length=length, mode=mode, cast=cast, conf=conf,
            member_name=member
        ))

    def _record_alias(self, lhs, rhs):
        dst_kind, dst_id, dst_name = "U", -1, ""
        try:
            if lhs.op == ida_hexrays.cot_var:
                lv = lhs.v
                dst_name = getattr(lv, "name", "")
                if getattr(lv, "is_arg_var", False):
                    dst_kind = "P"
                    dst_id = getattr(lv, "argidx", -1)
                else:
                    dst_kind = "L"
                    dst_id = getattr(lv, "idx", -1)
        except Exception:
            return

        if rhs.op == ida_hexrays.cot_call:
            callee_ea = self._extract_callee_ea(rhs.x)
            if callee_ea:
                self.fs.aliases.append(Alias(
                    dst_kind=dst_kind, dst_id=dst_id, dst_name=dst_name,
                    src_kind="R", src_id=callee_ea, src_name=_get_func_name(callee_ea),
                    conf="high"
                ))
            return

        bk, bid, bname, off, length, cast, mode, member = _normalize_expr_origin(self.cfunc, rhs)
        if bk in ("L", "P", "G", "C") and mode in ("&", "*", ""):
            self.fs.aliases.append(Alias(
                dst_kind=dst_kind, dst_id=dst_id if isinstance(dst_id, int) else -1, dst_name=dst_name or "",
                src_kind=bk, src_id=bid if isinstance(bid, int) else -1, src_name=bname or "",
                off=off, length=length, mode=mode or "&", cast=cast, conf="med",
                member_name=member
            ))

    def _record_global_access(self, ea: int, off: Optional[int], kind: str, cs_ea: int):
        key = (ea, kind)
        if key in self._seen_globals:
            return
        self._seen_globals.add(key)
        name = ida_name.get_name(ea) or ""
        self.fs.globals.append(GlobalAccess(ea=ea, off=off, length=None, kind=kind, cs_ea=cs_ea, name=name))

    def _record_global_write_from_lvalue(self, lhs, cs_ea: int):
        cur = lhs
        off = 0
        try:
            while cur:
                if cur.op == ida_hexrays.cot_obj:
                    gea = int(cur.obj_ea)
                    self._record_global_access(gea, (off if off else None), "W", cs_ea or 0)
                    return
                if cur.op == ida_hexrays.cot_memptr:
                    off += int(cur.m)
                    cur = cur.x
                    continue
                if cur.op == ida_hexrays.cot_memref:
                    cur = cur.x
                    continue
                if cur.op == ida_hexrays.cot_cast:
                    cur = cur.x
                    continue
                break
        except Exception:
            return

    def _record_global_read_from_expr(self, e, cs_ea: int):
        stack = [e]
        seen = set()
        try:
            while stack:
                cur = stack.pop()
                if not cur or id(cur) in seen:
                    continue
                seen.add(id(cur))

                if cur.op == ida_hexrays.cot_obj:
                    gea = int(cur.obj_ea)
                    self._record_global_access(gea, None, "R", cs_ea or 0)

                pass
        except Exception:
            return

    def visit_expr(self, e):
        try:
            if e.op == ida_hexrays.cot_call:
                call_ea = int(e.ea) if e.ea else 0
                callee_ea = self._extract_callee_ea(e.x)
                argc = e.a.size()
                for k in range(argc):
                    arg = e.a[k]
                    self._record_arguse(call_ea, callee_ea, k, arg)
                    self.apply_to(arg, None)

                if e.x.op != ida_hexrays.cot_obj:
                    self.apply_to(e.x, None)

                return 1

            if e.op == ida_hexrays.cot_asg:
                a_ea = int(e.ea) if e.ea else 0
                self._record_global_write_from_lvalue(e.x, a_ea)
                self._record_alias(e.x, e.y)
                return 0

            if e.op == ida_hexrays.cot_obj:
                gea = int(e.obj_ea)
                self._record_global_access(gea, None, "R", int(e.ea) if e.ea else 0)
                return 0

        except Exception:
            pass
        return 0

    def _extract_callee_ea(self, x) -> Optional[int]:
        try:
            y = x
            while y and y.op == ida_hexrays.cot_cast:
                y = y.x
            if not y:
                return None
            if y.op == ida_hexrays.cot_obj:
                return int(y.obj_ea)
            if y.op == ida_hexrays.cot_helper:
                h = getattr(y, "helper", None)
                if h:
                    ea = ida_name.get_name_ea(idaapi.BADADDR, h)
                    if ea != idaapi.BADADDR:
                        return int(ea)
                return None
            return None
        except Exception:
            return None

def analyze_functions_ctree(func_eas, progress_cb: Optional[Callable[[str], None]] = None) -> Dict[int, FunctionSummary]:
    out: Dict[int, FunctionSummary] = {}
    total = len(func_eas)
    for i, ea in enumerate(func_eas):
        if progress_cb and i % 10 == 0:
            progress_cb(f"Analyzing provenance... {i}/{total}")

        cfunc = None
        try:
            cfunc = ida_hexrays.decompile(ea)
        except ida_hexrays.DecompilationFailure:
            cfunc = None
        except Exception:
            cfunc = None
        if not cfunc:
            out[ea] = FunctionSummary(func_ea=ea, func_name=_get_func_name(ea))
            continue
        v = _ProvCollector(cfunc)
        try:
            v.apply_to(cfunc.body, None)
        except Exception:
            try:
                cfunc.body.visit_exprs(v)
            except Exception:
                pass
        out[ea] = v.fs
    return out

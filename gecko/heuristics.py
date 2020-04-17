from numbers import Number as _Number
from collections import Iterable as _Iterable

import itertools as _itertools
import angr as _angr
import claripy as _claripy

import gecko as _gecko

from ipdb import set_trace


######################################################################
# Annotation related
######################################################################
class AnnotationWithData(_claripy.annotation.Annotation):
    def __init__(self, data):
        super(AnnotationWithData, self).__init__()

        self.data = data

    def __repr__(self):
        self_type = type(self)
        self_data = self.data
        return "{self_type}({self_data})".format(**locals())


class AddressAnnotation(AnnotationWithData):
    pass


class RegisterAnnotation(AnnotationWithData):
    pass


class ArgumentAnnotation(AnnotationWithData):
    pass


@_gecko.project_util
def get_constant_from_bv(state, bv, ignore_stack=True, any_constant=False):
    # TODO: Implement ignore_stack

    symbolic_args = []
    constant_args = []
    for arg in bv.args:
        # if not isinstance(arg, _claripy.ast.bv.BV):
        #     return None  # TODO: Raise exception?

        if arg.symbolic:
            symbolic_args.append(arg)
        elif arg.concrete:

            if any_constant:
                return state.solver.eval(arg)

            constant_args.append(arg)

    if len(symbolic_args) <= 1 and len(constant_args) == 1:
        return state.solver.eval(constant_args[0])

@_gecko.project_util
def is_leaf(sym):
    # TODO: Find better way to do this (at least loop on sym.arg?)
    # If son is BV, this isn't a leaf
    return not isinstance(sym.args[0], _claripy.ast.bv.BV)

@_gecko.project_util
def get_annotations_from_symbol(sym, annotation_types=None, filter_callback=None):
    if annotation_types is None:
        annotation_types = [_claripy.Annotation]

    elif not isinstance(annotation_types, _Iterable):
        annotation_types = [annotation_types]

    if filter_callback is None:
        filter_callback = lambda ann: True

    for ann in sym.annotations:
        for ann_type in annotation_types:
            if isinstance(ann, ann_type) and filter_callback(ann):
                yield ann

@_gecko.project_util
def get_single_annotation_from_symbol(sym, annotation_types=None, filter_callback=None):
    generator = get_annotations_from_symbol(sym, annotation_types=annotation_types, filter_callback=filter_callback)

    try:
        ann = next(generator)
    except StopIteration:
        return None

    try:
        next(generator)
    except StopIteration:
        return ann
    else:
        raise Exception("Called get_single_annotation_from_symbol on symbol with multiple annotations")

@_gecko.project_util
def get_annotations_from_ast(ast, max_depth=None, annotation_types=None, filter_callback=None):
    if max_depth is None or max_depth > 0:
        for ann in get_annotations_from_symbol(ast,
                                               annotation_types=annotation_types,
                                               filter_callback=filter_callback):
            yield ann

        if not is_leaf(ast):
            if isinstance(max_depth, _Number):
                max_depth -= 1

            for arg in ast.args:
                for ann in get_annotations_from_ast(arg, max_depth=max_depth,
                                                    annotation_types=annotation_types,
                                                    filter_callback=filter_callback):
                    yield ann

@_gecko.project_util
def get_single_annotation_from_ast(ast, max_depth=None, annotation_types=None, filter_callback=None):
    generator = get_annotations_from_ast(ast, max_depth=max_depth,
                                         annotation_types=annotation_types,
                                         filter_callback=filter_callback)

    try:
        ann = next(generator)
    except StopIteration:
        return None

    try:
        next(generator)
    except StopIteration:
        return ann
    else:
        raise Exception("Called get_single_annotation_from_ast on ast with multiple annotations")


######################################################################
# Calling convention hacks
######################################################################
class SimFakeArgument(_angr.calling_conventions.SimFunctionArgument):

    def __init__(self, data=None, label=None):
        super(SimFakeArgument, self).__init__(0)
        self.data = data
        self.label = label

    def __repr__(self):
        return "FakeArg(%s)" % str(self.data)

    def __eq__(self, other):
        return type(other) is SimFakeArgument and self.data == other.data

    def __hash__(self):
        return hash(self.data)

    def set_value(self, state, value, endness=None):
        self.data = value

    def get_value(self, state, endness=None, size=None):
        return self.data

class SimAddressArgument(_angr.calling_conventions.SimFunctionArgument):

    @_gecko.default_kwarg_project
    def __init__(self, address, size=None, project=None):
        if size is None:
            size = project.angr.arch.bytes

        super(SimAddressArgument, self).__init__(size)
        self.address = address

    def __repr__(self):
        return "(0x%X)" % (self.address)

    def __eq__(self, other):
        return type(other) is SimAddressArgument and self.address == other.address

    def __hash__(self):
        return hash(self.address)

    def get_value(self, state, endness=None, offset=None, size=None):
        if offset is None:
            offset = 0

        return self.address + offset

class SimDerefArgument(_angr.calling_conventions.SimFunctionArgument):

    @_gecko.default_kwarg_project
    def __init__(self, arg, offset=0, reg_size=None, cc=None, project=None):
        if cc is None:
            cc = project.angr.factory.cc()

        self.size = project.angr.arch.bytes
        self.offset = offset
        self.deref = guess_sim_function_argument(arg, reg_size=reg_size, cc=cc, project=project)

    def __repr__(self):
        return '[%s]' % str(self.deref)

    def __eq__(self, other):
        return type(other) is SimDerefArgument and self.deref == other.deref

    def __hash__(self):
        return hash((self.size, self.deref))

    def set_value(self, state, value, endness=None, deref=None):
        self.check_value(value)

        if endness is None:
            endness = state.project.arch.memory_endness

        if deref is None:
            deref = state.solver.eval(self.deref)

        # TODO: Improve checks to assert BVV
        if isinstance(value, int):
            value = _claripy.BVV(value, self.size * 8)

        state.memory.store(deref + self.offset, value, endness=endness, size=value.length // 8)

    def get_value(self, state, endness=None, deref=None, size=None, offset=None):
        if endness is None:
            endness = state.project.arch.memory_endness

        if deref is None:
            deref = self.deref

        if isinstance(deref, _angr.calling_conventions.SimFunctionArgument):
            # TODO: Make sure all subclasses have same kwargs?
            """
                TODO: IMPORTANT! Figure out this error

                    heuristics.py in get_value(self, state, endness, deref, size, offset)
                --> 229             deref = deref.get_value(self, state, endness=endness, size=size)

                TypeError: get_value() got multiple values for argument 'endness'
            """
            deref = deref.get_value(state)

        if offset is None:
            offset = self.offset

        return state.memory.load(state.solver.eval(deref) + offset, endness=endness, size=size or self.size)

class CustomCC(_angr.calling_conventions.SimCC):
    pass


@_gecko.project_util_bind
@_gecko.default_kwarg_project
def yield_arguments_from_cc(use_stack=True, cc=None, project=None):
    if cc is None:
        cc = project.angr.factory.cc()

    if cc.args:
        generator = iter(cc.args)
    else:
        generator = cc.int_args

    if use_stack:
        generator = _itertools.chain(generator, cc.both_args)

    for arg in generator:
        yield arg

@_gecko.project_util_bind
@_gecko.default_kwarg_project
def get_argument_from_cc(index, use_stack=True, cc=None, project=None):
    assert isinstance(index, _Number), "For function 'get_argument_from_cc' argument 'index' must be a number"

    if cc is None:
        cc = project.angr.factory.cc()

    index = int(index)

    try:
        for arg in yield_arguments_from_cc(use_stack=use_stack, cc=cc, project=project):
            if index == 0:
                return arg

            index -= 1
    except StopIteration:
        return None

@_gecko.project_util_bind
@_gecko.default_kwarg_project
def guess_sim_function_argument(arg, reg_size=None, cc=None, project=None):
    if cc is None:
        cc = project.angr.factory.cc()

    if reg_size is None:
        reg_size = project.angr.arch.bytes

    # Already a SimFunctionArgument type, return as-is
    if isinstance(arg, _angr.calling_conventions.SimFunctionArgument):
        return arg

    # String representing the register name
    elif isinstance(arg, str):
        reg_offset, reg_size = project.angr.arch.registers[arg]
        return _angr.calling_conventions.SimRegArg(arg, reg_size)

    # Number representing the positional argument at index 'arg'
    elif isinstance(arg, _Number):
        sim_arg = get_argument_from_cc(arg, cc=cc)

        if sim_arg is None:
            raise Exception("Couldn't get argument number {arg} from cc!".format(**locals()))

        return sim_arg

    # Tuple representing the (offset,size) of a stack argument
    elif isinstance(arg, _Iterable):
        offset, size = arg

        if not size or size < 0:
            size = reg_size

        return _angr.calling_conventions.SimStackArg(offset, size)

    else:
        raise Exception("Couldn't guess argument type from {arg}..".format(**locals()))


@_gecko.project_util_bind
@_gecko.default_kwarg_project
def custom_cc(arg_list, reg_size=None, cc=None, project=None):
    if cc is None:
        cc = project.angr.factory.cc()

    sim_arg_list = []

    for arg in arg_list:
        sim_arg = guess_sim_function_argument(arg, reg_size=reg_size, cc=cc, project=project)
        sim_arg_list.append(sim_arg)

    return CustomCC(project.angr.arch, args=sim_arg_list)

######################################################################
# Angr emulation related
######################################################################
@_gecko.project_util_bind
@_gecko.default_kwarg_project
def get_next_callsite(ea, project=None):
    # TODO: Implement emulation

    block = project.angr.factory.block(addr=ea)
    if block.vex.jumpkind == 'Ijk_Call':
        return block.instruction_addrs[-1]


@_gecko.project_util
def create_add_argument_annotations_callback(num_args=20):

    def callback(state, cc):
        i = 0  # If yield_arguments_from_cc... doesn't yield anything i is undefined

        # For each argument add an annotation representing the argument's positional value
        for i, arg in enumerate(yield_arguments_from_cc(cc)):
            value = arg.get_value(state)
            value = value.annotate(ArgumentAnnotation(i))
            arg.set_value(state, value)

            if i == num_args:
                break

        if i != num_args:
            raise Exception(
                "Calling Convention doesn't support {num_args} args. Stopped at {i} args.".format(**locals()))

    return callback

def _create_annotate_memory_access_callback(address_member_name):
    """
    # TODO: Make this enums
    address_member_name should be "mem_read_address" or "mem_write_address"
    TODO: Implement annotations correctly so i wont need these breakpoints
    """

    def callback(state):
        state.globals.tainted_addresses = getattr(state.globals, 'tainted_addresses', dict())

        address = getattr(state.inspect, address_member_name)
        endness = state.project.arch.memory_endness
        if address not in state.globals.tainted_addresses:
            # TODO: State dependant way to find endness?
            sym = state.memory.load(address, disable_actions=True, inspect=False,
                                    size=state.inspect.mem_read_length,
                                    endness=endness
                                    )

            # TODO: Hack way to assert only one address annotation exists
            ann = get_single_annotation_from_ast(sym, annotation_types=AddressAnnotation)

            if ann is not None and ann.address != address:
                sym = sym.annotate(AddressAnnotation(address))

            state.globals.tainted_addresses[address] = sym
            state.memory.store(address, sym, disable_actions=True, inspect=False, endness=endness)

    return callback


annotate_memory_read_callback = _create_annotate_memory_access_callback('mem_read_address')
annotate_memory_write_callback = _create_annotate_memory_access_callback('mem_write_address')


@_gecko.project_util_bind
@_gecko.default_kwarg_project
def _annotate_register_names(state, project=None):
    # TODO: Should we do it for registers contained in other registers too? (eax, ax, al)
    for reg_offset, reg_name in project.angr.arch.register_names.items():
        sym = state.registers.load(reg_name)
        sym = sym.annotate(RegisterAnnotation(reg_offset))
        state.registers.store(reg_name, sym)
    return state


@_gecko.project_util_bind
@_gecko.default_kwarg_project
def create_state(start, ignore_calls=True, breakpoints=None, project=None):
    # TODO: Add cc as kwarg

    angr_options = set()
    if ignore_calls:
        angr_options.add(_angr.options.CALLLESS)

    # TODO: Decide out which state factory to use
    state = project.angr.factory.blank_state(add_options=angr_options)
    state.ip = start

    for bp_type, when, callback in (breakpoints or []):
        if isinstance(when, str):
            when = {
                "before": _angr.BP_BEFORE,
                "after": _angr.BP_AFTER
            }.get(when.lower())

        state.inspect.b(bp_type, when=when, action=callback)

    return state


@_gecko.project_util_bind
@_gecko.default_kwarg_project
def simulate_and_find_origins(dest, follow, start=None, avoid=None, breakpoints=None,
                              annotate_memory_reads=True, annotate_memory_writes=True,
                              init_state_callback=None,
                              cc=None, project=None):
    # TODO: IMPORTANT!!Implement until call
    if cc is None:
        cc = project.angr.factory.cc()

    if start is None:
        start = project.ida.get_func(dest).startEA

    if not isinstance(follow, CustomCC):
        follow = custom_cc(follow, cc=cc, project=project)

    set_trace()

    init_state = create_state(start, project=project)

    if init_state_callback is not None:
        init_state_callback(init_state, cc)

    if annotate_memory_reads:
        init_state.inspect.b('mem_read', when=_angr.BP_BEFORE, action=annotate_memory_read_callback)

    if annotate_memory_writes:
        init_state.inspect.b('mem_write', when=_angr.BP_BEFORE, action=annotate_memory_write_callback)

    simgr = project.angr.factory.simulation_manager(init_state)

    found_all_offsets = False
    while not found_all_offsets:
        simgr.explore(find=dest, avoid=avoid)

        if not simgr.found:
            raise Exception("Couldn't find state {dest}".format(**locals()))

        # TODO: Should we pop or leave each found state in the list? Loops may initialize after a certain iteration?
        found_state = simgr.found.pop()

        found_offsets = {}
        for arg_num, sim_arg in enumerate(follow.args):
            value = sim_arg.get_value(found_state)

            # TODO: Sanity checks on the value
            # make sure there's a number (offset) in the source tree

            # TODO: Find a way to control which search to do (concrete, reg+offset, address)
            if value.concrete:
                found_offsets[arg_num] = found_state.solver.eval(value)

            elif get_constant_from_bv(found_state, value) is not None:
                found_offsets[arg_num] = get_constant_from_bv(found_state, value, any_constant=True)

            else:

                ann = get_single_annotation_from_ast(value, annotation_types=AddressAnnotation)
                if ann is not None:
                    offset = get_constant_from_bv(found_state, ann.address)
                    found_offsets[arg_num] = offset

        found_all_offsets = all(off is not None for off in found_offsets.values())

        if found_all_offsets:
            yield found_state, found_offsets

@_gecko.project_util_bind
@_gecko.default_kwarg_project
def simulate_and_find_origins_simple(dest, follow, start=None, project=None, **kwargs):
    if isinstance(dest, str):
        dest = project.ida.LocByName(dest)

    if isinstance(start, str):
        start = project.ida.LocByName(start)

    return next(simulate_and_find_origins(dest, follow, start=start, project=project, **kwargs))

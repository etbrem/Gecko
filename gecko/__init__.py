import sys as _sys
import functools as _functools
import collections as _collections
import angr as _angr


######################################################################
# Globals
######################################################################
CURRENT_PROJECT = None


######################################################################
# General
######################################################################
bit_field = lambda n: 1 << n


def default_kwarg_value(name, factory):
    def decorator(func):

        @_functools.wraps(func)
        def func_wrapper(*args, **kwargs):
            if name not in kwargs:
                kwargs[name] = factory(*args, **kwargs)
            return func(*args, **kwargs)

        return func_wrapper
    return decorator


class AliasedObject(object):
    __aliases__ = {}

    def __setattr__(self, name, value):
        if name == '__aliases__':
            raise Exception("AliasedObject uses the __aliases__ member privately!")

        name = self.__aliases__.get(name, name)
        object.__setattr__(self, name, value)

    def __getattr__(self, name):
        name = self.__aliases__.get(name, name)
        return object.__getattribute__(self, name)


######################################################################
# Project related
######################################################################
REGISTERED_PROJECT_UTILS = {}

def isbound(method):
    try:
        return method.im_self is not None
    except:
        return hasattr(method, '__self__')

def project_util(func, bind_project_word=False):
    if not callable(func):
        name = func

        def decorator(func2):
            assert name not in REGISTERED_PROJECT_UTILS, 'Already registered a project util with name {}'.format(name)
            REGISTERED_PROJECT_UTILS[name] = (func2, bind_project_word)
            return func2
        return decorator

    name = func.__name__

    assert name not in REGISTERED_PROJECT_UTILS, 'Already registered a project util with name {}'.format(name)
    REGISTERED_PROJECT_UTILS[name] = (func, bind_project_word)
    return func


project_util_bind = _functools.partial(project_util, bind_project_word=True)


class ProjectUtils(object):
    def __init__(self, gecko_project):
        self._gecko_project = gecko_project
        self._loaded_utils = {}

    def __getattr__(self, name):
        _utils_dict = REGISTERED_PROJECT_UTILS
        if name not in _utils_dict:
            return object.__getattribute__(self, name)

        _loaded_utils = object.__getattribute__(self, '_loaded_utils')
        if name not in _loaded_utils:
            util, bind_project_word = _utils_dict[name]

            if bind_project_word:
                binded_util = _functools.partial(util, project=object.__getattribute__(self, '_gecko_project'))
                _loaded_utils[name] = _functools.wraps(util)(binded_util)
            else:
                _loaded_utils[name] = util

        return _loaded_utils[name]


class GeckoProject(AliasedObject):
    __aliases__ = {
        'idaapi': 'ida',
        'ida_api': 'ida',
        'angr_project': 'angr',
    }

    def __init__(self, angr_project, ida_api):
        # TODO: IMPORTANT! Bind 'self' to all 'project' kwargs
        self.angr = angr_project
        self.ida = ida_api
        self.utils = ProjectUtils(self)

        # # Sorry.. Context->Namespace->Struct->Member
        # self._structs = _collections.defaultdict(lambda: _collections.defaultdict(lambda: _collections.defaultdict(lambda: _collections.defaultdict(list))))

def set_global_project(project):
    global CURRENT_PROJECT

    assert isinstance(project, GeckoProject)
    prev = CURRENT_PROJECT
    CURRENT_PROJECT = project
    return prev

def get_global_project():
    global CURRENT_PROJECT

    assert isinstance(CURRENT_PROJECT, GeckoProject)
    return CURRENT_PROJECT

def load_project(db_path, bin_path, as_global_project=True):
    # TODO: Load with db instead of using angr's loader?
    import gecko.idaapi  # TODO: This is not the way

    ida_api = gecko.idaapi.IDAApi(db_path, bin_path)
    angr_project = _angr.Project(bin_path)

    gecko_project = GeckoProject(angr_project, ida_api)
    set_global_project(gecko_project)
    return gecko_project


default_kwarg_project = default_kwarg_value('project', lambda *args, **kwargs: get_global_project())


######################################################################
# Function cache
######################################################################
FUNCTION_CACHE = {}

def cache(func):

    @_functools.wraps(func)
    def wrapper(*args, **kwargs):
        if func not in FUNCTION_CACHE:
            FUNCTION_CACHE[func] = func(*args, **kwargs)
        return FUNCTION_CACHE[func]
    return wrapper


######################################################################
# Offset/member cache related
######################################################################
MEMBER_CACHE = _collections.defaultdict(lambda: _collections.defaultdict(lambda: None))

def _version_is_supported(version, min_version=None, max_version=None, cache_entry=None):
    if version is None:
        return True

    if cache_entry is None:
        cache_entry = _collections.defaultdict(lambda: None)

    min_version = min_version or cache_entry['min_version']
    max_version = max_version or cache_entry['max_version']

    if min_version is not None and version < min_version:
        return False
    if max_version is not None and version >= max_version:
        return False

    return True

@project_util_bind
def enumerate_registered_members(version=None, context=None, namespaces=None, structs=None, members=None, filter_callback=None, project=None):
    # TODO: Get version from project

    for cache_entry in MEMBER_CACHE.values():
        if context is not None and cache_entry['context'] != context:
            continue

        if namespaces is not None and cache_entry['namespace'] not in namespaces:
            continue

        if structs is not None and cache_entry['struct'] not in structs:
            continue

        if members is not None and cache_entry['member'] not in members:
            continue

        if version is not None and not _version_is_supported(version, cache_entry=cache_entry):
            continue

        if filter_callback is not None and not filter_callback(cache_entry):
            continue

        yield cache_entry


def _update_member_cache(unique, overwrite=True, **kwargs):
    updated = 0
    for key, value in kwargs.items():

        if not overwrite:
            if key in MEMBER_CACHE[unique] and MEMBER_CACHE[unique][key] is not None:
                print("Not overwriting", key)
                continue

        print("Overwriting", key)
        MEMBER_CACHE[unique][key] = value
        updated += 1
    return updated


def member(member, context=None, namespace=None, struct=None, min_version=None, max_version=None, dont_cache=False, **kwargs1):

    def decorator(func):
        struct_ = struct

        struct_was_guessed = False
        if struct_ is None:
            struct_ = func.__module__
            struct_was_guessed = True

        # ex: (kernel, process, task_struct, pid, ...)
        unique = (context, namespace, struct_, member, min_version, max_version)

        _update_member_cache(unique, overwrite=False,
                             function=func,
                             dont_cache=dont_cache,

                             context=context,
                             namespace=namespace,
                             struct=struct_,
                             struct_was_guessed=struct_was_guessed,
                             member=member,

                             min_version=min_version,
                             max_version=max_version,

                             **kwargs1)

        @_functools.wraps(func)
        @default_kwarg_value('project', lambda *args, **kwargs: get_global_project())
        def wrapper(*args, **kwargs):
            if MEMBER_CACHE[unique]['value_was_set'] and not MEMBER_CACHE[unique]['dont_cache']:  # negative*2==positive
                return MEMBER_CACHE[unique]['value']

            off = func(*args, **kwargs)

            _update_member_cache(unique, value=off, value_was_set=True)
            return off

        return _functools.wraps(func)(wrapper)

    return decorator


######################################################################
# Import submodules
######################################################################
import os as _os

_ignore = ["__init__.py", '__pycache__']
__all__ = [_os.path.basename(f)[:-len(".py") if f.endswith('.py') else None] for f in
           _os.listdir(_os.path.dirname(__file__) or '.') if f not in _ignore and not f.startswith("_")]

from . import *
import gecko.idaapi

_sys.modules['__main__'].SegmentTuple = gecko.idaapi.SegmentTuple
_sys.modules['__main__'].FunctionTuple = gecko.idaapi.FunctionTuple
_sys.modules['__main__'].ReferenceTuple = gecko.idaapi.ReferenceTuple
_sys.modules['__main__'].BasicBlockTuple = gecko.idaapi.BasicBlockTuple

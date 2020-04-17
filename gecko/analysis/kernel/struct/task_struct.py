import gecko as _gecko

@_gecko.member('comm', class_name='tast_struct', namespace='process', context='LinuxKernel', min_version=None, max_version=None, random_extra_info=3)
def comm(project=None):

    # Find the indicative warning string
    searchstr = b'"\x013Killed process %d (%s) total-vm:%'
    string_ea = project.ida.FindBinary(project.ida.MinEA(), project.ida.SEARCH_DOWN, searchstr)

    xrefs = list(project.ida.DataRefsTo(string_ea))
    assert len(xrefs) == 1
    xref = xrefs[0]

    log_call_site = project.utils.get_next_callsite(xref)

    wanted_regs = [2]

    found_state, found_offsets = project.utils.simulate_and_find_origins_simple(log_call_site, wanted_regs)

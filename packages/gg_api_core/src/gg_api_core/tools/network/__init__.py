"""Network primitive tools (DNS, RDAP, SSL, reachability).

These tools have no GitGuardian auth requirement (``required_scopes=[]``) and
hit only public infrastructure (DNS resolvers, rdap.org, the target host).
They are the eyes used by HIL-style triage / qualification prompts.
"""

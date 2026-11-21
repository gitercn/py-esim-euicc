"""Stand-in for the `smpp` package that pySim imports for SMS PDU translation.

pySim's import chain pulls it in through pySim.global_platform -> pySim.ota ->
pySim.sms.  Nothing on the profile-building / profile-reading path ever calls
into it -- it is only used by to_smpp()/from_smpp(), which turn SMS-DELIVER
and SMS-SUBMIT PDUs into SMPP operations.

Upstream smpplib no longer ships a `smpp` top-level package, so the import
fails on a clean install.  These stubs satisfy the module-level type
annotations and raise if anything actually tries to use them.
"""
